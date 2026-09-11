# CLEANUP — status as of 2026-09-11

## Done (user level, by Claude Code)

| # | Action | Result |
|---|---|---|
| 1 | `launchctl bootout gui/501/com.qxgpjsivitldyooj` | service was already not loaded; plist not in `~/Library/LaunchAgents` (moved to quarantine on 2026-08-19) |
| 2 | Kill any `osascript`/`curl` talking to `jse8x92s.me` | none running |
| 3 | Delete `~/.passphrase` (cleartext login password) and `~/.txid` (bot id) | removed; `.txid` preserved in `evidence/system/`, password intentionally NOT preserved |
| 4 | Check known AMOS-family paths (`~/.helper`, `~/.agent`, `/tmp/.helper`, `com.finder.helper.plist`) | none present |
| 5 | Verify LaunchAgents/Daemons, cron, login items, shell rc, sudoers, hosts, ssh authorized_keys, unpacked browser extensions | clean (see `evidence/system/live_state_2026-09-11.txt`) |

Original plist still exists (inert) at `~/Desktop/_quarantine-2026-08-19/com.qxgpjsivitldyooj.plist`; a copy is in `evidence/samples/`.

## Needs sudo (run manually)

```sh
# block the C2 domain locally (attacker can rotate it via the contract, so this is defence-in-depth only)
echo '0.0.0.0 jse8x92s.me' | sudo tee -a /etc/hosts
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder

# make sure nothing is loaded in the system domain either
sudo launchctl list | grep -vE '^\S+\s+\S+\s+com\.apple\.'
```

## MUST DO — credential rotation (attacker had the login password + remote shell for ~9 days)

Do these from a device you trust, in this order:

1. **macOS login password** (System Settings → Users & Groups). Then also change the **login Keychain** password if it was separate.
2. **Crypto wallets**: MetaMask (Chrome Profile 1, Profile 3, Brave), Phantom (Chrome Profile 1), anything in `~/.nansen/wallets` → move funds to a *new* seed phrase created on a clean device. Assume the old seeds are stolen.
3. **Browser**: sign out of all sessions and change passwords for Google, Facebook, Cloudflare, GitHub, Apple ID, banks/exchanges. Revoke "remembered devices". Clear saved passwords in Chrome/Brave/Firefox/Edge/Arc after moving them to a password manager with a *new* master password.
4. **SSH keys** (all 8 in `~/.ssh`): generate new keys, replace on GitHub, Bitbucket, GCE, OCI, deploy targets, then delete the old ones.
5. **Cloud/API**: AWS SSO (`~/.aws/sso`), Kubernetes (`~/.kube/config`), `~/.boto` (GCS), Cloudflare API tokens, Render/Postgres passwords (one was visible in a running MCP process), Supabase, Vercel, and **every secret in the 93 `.env` files** under `~`.
6. **AI tools**: revoke/re-login Claude Code, Codex/OpenAI, Gemini, Kimi, OpenCode, Cline, Continue (tokens live in dotfiles).
7. **Messaging**: Discord (token stored locally), LINE, Telegram → log out all sessions and re-login.
8. **2FA**: if any TOTP secrets/backup codes were stored in Notes, files, or browser, regenerate them.

## Recommended

- Because an `openshell` remote shell was available to the attacker, a **clean reinstall of macOS** (erase-all-content-and-settings, then restore only documents, not apps/settings) is the only way to be certain nothing else was left behind.
- Keep `com.korrio.security-watchdog` running; consider adding a rule that alerts on any LaunchAgent containing `base64`/`osascript`, and on the existence of `~/.passphrase` / `~/.txid`.
- Enable "Full Disk Access" only for tools that need it; do not grant Terminal/iTerm blanket FDA.

## Watchdog v2 (deployed 2026-09-11)

`~/.security-watchdog/watchdog.sh` was rewritten (copy in `tools/`). Every 5 minutes it now checks, in ~1-2 s:
persistence baseline diff (plists, crontab, login items, shell rc, /etc/hosts, ssh authorized_keys, sudoers.d),
launchd plists containing `base64`/`osascript`/`curl`/`/tmp/`/`nohup`/`eval` regardless of baseline,
IOC files (`~/.passphrase`, `~/.txid`, AMOS paths), known-bad labels, launchd-parented shells or
`base64 -d` in any command line, processes running from temp dirs, established connections to the C2
(`jse8x92s.me` re-resolved each run), `tccutil reset` in the unified log, and high CPU.
Indicators live in `~/.security-watchdog/iocs.txt`. `--self-test` fires a notification; `--accept-baseline`
after a deliberate install. Verified by planting an inert plist + `~/.txid`: both rules fired.
