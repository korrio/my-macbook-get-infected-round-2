#!/bin/zsh
# Security watchdog v2 (2026-09-11). Runs every 5 min via com.korrio.security-watchdog.
#
# Checks:
#  1. Persistence baseline diff  - LaunchAgents/Daemons plists, crontab, login items,
#                                  shell rc files, /etc/hosts, ~/.ssh/authorized_keys, /etc/sudoers.d
#  2. Plist content rules        - any launchd plist matching pattern: rules in iocs.txt (ignores baseline)
#  3. IOC files                  - file: rules in iocs.txt
#  4. Loaded launchd labels      - label: rules in iocs.txt
#  5. Suspicious processes       - osascript/sh/bash/curl parented by launchd, "base64 -d" in cmdline,
#                                  or any binary executing from /tmp, /var/tmp
#  6. Network                    - established connections to net: rules in iocs.txt
#  7. TCC reset                  - "tccutil reset" seen in the unified log in the last 6 minutes
#  8. High CPU not allowlisted   - carried over from v1
#
# Usage:  watchdog.sh                    normal run (exit 0 clean, 2 findings)
#         watchdog.sh --accept-baseline  after you knowingly installed something persistent
#         watchdog.sh --self-test        fire a fake alert to prove notifications work
#         watchdog.sh --status           print last state

set -uo pipefail
setopt NULL_GLOB

DIR="$HOME/.security-watchdog"
IOCS="$DIR/iocs.txt"
BASELINE="$DIR/baseline.txt"
STATE="$DIR/state.txt"
LOG="$DIR/watchdog.log"
LAST_ALERT_SIG="$DIR/last_alert_sig.txt"
NOW=$(date "+%Y-%m-%d %H:%M:%S")
NL=$'\n'

CPU_ALLOWLIST_REGEX='WindowServer|Xcode|node |webpack|docker|com\.docker|com\.apple\.|Chrome Helper|Google Chrome$|Electron|swiftc|clang|ld$|Zoom|OrbStack|colima|qemu|limactl|postgres|redis|ollama|ccusage'
CPU_THRESHOLD=200

mkdir -p "$DIR"; touch "$LOG"

# ---------- helpers ----------
notify() {
  local title="$1" msg="$2"
  msg=${msg//\"/\\\"}; title=${title//\"/\\\"}
  osascript -e "display notification \"$msg\" with title \"$title\" sound name \"Basso\"" >/dev/null 2>&1 || true
}
ioc() { # ioc <kind> -> values of that kind from iocs.txt, ~ expanded
  [[ -f "$IOCS" ]] || return 0
  grep -E "^${1}:" "$IOCS" | sed -E "s/^${1}://" | sed "s#^~#$HOME#"
}
sha() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

plist_files() {
  local f
  for f in "$HOME"/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
    [[ -e "$f" ]] && echo "$f"
  done
}

snapshot_persistence() {
  {
    plist_files | while read -r f; do echo "plist:$f:$(sha "$f")"; done
    echo "crontab:$(crontab -l 2>/dev/null | shasum -a 256 | awk '{print $1}')"
    # classic login items via System Events (fast). sfltool dumpbtm takes >60 s, so it is not used.
    echo "loginitems:$(osascript -e 'tell application "System Events" to get the path of every login item' 2>/dev/null | shasum -a 256 | awk '{print $1}')"
    local f
    for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.zlogin" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile" \
             /etc/hosts "$HOME/.ssh/authorized_keys" "$HOME/.ssh/config" /etc/zshrc /etc/zprofile /etc/bashrc; do
      [[ -f "$f" ]] && echo "file:$f:$(sha "$f")"
    done
    echo "sudoers.d:$( (ls -1 /etc/sudoers.d 2>/dev/null; find /etc/sudoers.d -type f -exec shasum -a 256 {} + 2>/dev/null) | shasum -a 256 | awk '{print $1}')"
  } | sort
}

# ---------- modes ----------
case "${1:-}" in
  --accept-baseline)
    snapshot_persistence > "$BASELINE"
    echo "$NOW  baseline re-accepted by user" >> "$LOG"
    echo "OK|Baseline accepted at $NOW" > "$STATE"
    notify "Security Watchdog" "Baseline accepted - current persistence set is now trusted."
    exit 0 ;;
  --status) cat "$STATE" 2>/dev/null; exit 0 ;;
esac

FINDINGS=()

if [[ "${1:-}" == "--self-test" ]]; then
  FINDINGS+=("SELF-TEST: simulated finding - if you can read this in a notification, alerts work")
else
  # 1) persistence baseline
  if [[ ! -f "$BASELINE" ]]; then
    snapshot_persistence > "$BASELINE"
    echo "$NOW  initial baseline established" >> "$LOG"
  else
    CURRENT=$(snapshot_persistence)
    DIFF=$(diff <(cat "$BASELINE") <(echo "$CURRENT") | grep -E '^[<>]' || true)
    [[ -n "$DIFF" ]] && FINDINGS+=("Persistence changed (plists/crontab/login items/rc files/hosts/ssh/sudoers):${NL}${DIFF}")
  fi

  # 2) plist content rules (baseline-independent)
  PATTERNS=$(ioc pattern | paste -sd'|' -)
  if [[ -n "$PATTERNS" ]]; then
    HITS=$(plist_files | while read -r f; do
      body=$(plutil -convert xml1 -o - "$f" 2>/dev/null || cat "$f")
      hit=$(echo "$body" | grep -oiE "$PATTERNS" | sort -u | paste -sd',' -)
      [[ -n "$hit" ]] && echo "$f => $hit"
    done)
    [[ -n "$HITS" ]] && FINDINGS+=("Launchd plist contains suspicious content:${NL}${HITS}")
  fi

  # 3) IOC files
  PRESENT=$(ioc file | while read -r p; do [[ -e "$p" ]] && echo "$p"; done | paste -sd' ' -)
  [[ -n "$PRESENT" ]] && FINDINGS+=("IOC file present: $PRESENT")

  # 4) loaded labels
  LABELS=$(ioc label | paste -sd'|' -)
  if [[ -n "$LABELS" ]]; then
    BAD=$(launchctl list 2>/dev/null | awk '{print $3}' | grep -E "$LABELS" | paste -sd' ' - || true)
    [[ -n "$BAD" ]] && FINDINGS+=("Known-bad launchd label loaded: $BAD")
  fi

  # 5) suspicious processes
  PROCS=$(ps -axo pid=,ppid=,command= | while read -r pid ppid cmd; do
    [[ "$pid" == "$$" ]] && continue
    case "$cmd" in
      *"base64 -d"*|*"base64 --decode"*|*"base64 -D"*)
        echo "pid=$pid ppid=$ppid decodes base64: ${cmd:0:160}" ;;
    esac
    if [[ "$ppid" == "1" ]]; then
      case "$cmd" in
        /usr/bin/osascript*|osascript*|/bin/sh*|/bin/bash*|"/bin/zsh -c"*|/usr/bin/curl*|curl*)
          echo "pid=$pid launchd-parented shell/script: ${cmd:0:160}" ;;
      esac
    fi
    case "$cmd" in
      /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*)
        echo "pid=$pid executing from temp dir: ${cmd:0:160}" ;;
    esac
  done)
  [[ -n "$PROCS" ]] && FINDINGS+=("Suspicious process:${NL}${PROCS}")

  # 6) network to IOC hosts (domains resolved each run; attacker rotates C2 via the contract)
  NET_IPS=$(ioc net | while read -r h; do
    if [[ "$h" =~ ^[0-9.]+$ ]]; then echo "$h"; else dig +short +time=2 +tries=1 "$h" A 2>/dev/null | grep -E '^[0-9.]+$'; fi
  done | sort -u | paste -sd'|' -)
  if [[ -n "$NET_IPS" ]]; then
    CONNS=$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | grep -E "(${NET_IPS//./\\.}):" | awk '{print $1, $2, $9}' || true)
    [[ -n "$CONNS" ]] && FINDINGS+=("Connection to known C2:${NL}${CONNS}")
  fi

  # 7) TCC reset in the last 6 minutes
  TCC=$(log show --last 6m --style compact --predicate '(process == "tccd" OR process == "tccutil") AND eventMessage CONTAINS[c] "reset"' 2>/dev/null | grep -v '^Timestamp' | head -3 || true)
  [[ -n "$TCC" ]] && FINDINGS+=("TCC reset observed (tccutil reset):${NL}${TCC}")

  # 8) high CPU
  CPU=$(ps -Ao pcpu=,comm= -r | while read -r pcpu comm; do
    pcpu_int=${pcpu%.*}
    [[ "$pcpu_int" -lt "$CPU_THRESHOLD" ]] && break
    echo "$comm" | grep -qE "$CPU_ALLOWLIST_REGEX" || echo "${pcpu}% $comm"
  done | paste -sd';' -)
  [[ -n "$CPU" ]] && FINDINGS+=("High CPU, not allowlisted: $CPU")
fi

# ---------- report ----------
if (( ${#FINDINGS[@]} > 0 )); then
  SIG=$(printf '%s\n' "${FINDINGS[@]}" | shasum -a 256 | awk '{print $1}')
  PREV_SIG=""; [[ -f "$LAST_ALERT_SIG" ]] && PREV_SIG=$(cat "$LAST_ALERT_SIG")
  {
    echo "$NOW  ALERT (${#FINDINGS[@]} finding(s))"
    for f in "${FINDINGS[@]}"; do printf '%s\n' "$f" | sed '1s/^/  - /; 2,$s/^/      /'; done
  } >> "$LOG"
  echo "ALERT|${#FINDINGS[@]} finding(s) at $NOW - see ~/.security-watchdog/watchdog.log" > "$STATE"
  if [[ "$SIG" != "$PREV_SIG" || "${1:-}" == "--self-test" ]]; then
    first="${FINDINGS[1]%%$NL*}"
    notify "Security Watchdog: ALERT" "${#FINDINGS[@]} finding(s): ${first:0:120}"
    echo "$SIG" > "$LAST_ALERT_SIG"
  fi
  exit 2
else
  echo "OK|Last check $NOW - clean" > "$STATE"
  rm -f "$LAST_ALERT_SIG"
  exit 0
fi
