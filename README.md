# Terry's Toolkit

A scope-guarded web front-end for **nmap** — a "wargames"-styled console you can drive from
any device on your network (laptop, phone). Type a target or subnet, flip the options you want,
watch the scan run live, and read clean per-host results. It also has a **Vuln** tab that runs
nmap's `--script vuln` NSE checks.

> [!warning] Authorized use only
> This runs real active scans. It will **only** scan the ranges in `config.json → authorized_scopes`
> and refuses everything else. Do **not** expose it to the public internet as an open scanner —
> keep it on a trusted network (or behind a VPN) and set an access token. Scan only networks you
> are authorized to test.

## Run it
No dependencies — pure Python standard library, uses the `nmap` already on the box.

```bash
cd terrys-toolkit
python3 server.py
```

Open **http://localhost:8777** on the same box, or from your phone/laptop on the same network:
**http://<this-box-ip>:8777** (e.g. `http://192.168.55.130:8777`).

- SYN scan (`-sS`) and OS detection (`-O`) need raw sockets — run with `sudo python3 server.py`
  if you want those. TCP connect scan (the default) works without root.

## Configure — `config.json`
| key | meaning |
|---|---|
| `authorized_scopes` | CIDRs/IPs the tool is allowed to scan. Anything outside is refused. **Set this to your lab/authorized ranges.** |
| `excluded` | CIDRs/IPs to always refuse, even if inside an authorized scope (your exclusion list). |
| `access_token` | If set, the UI asks for it and the API requires it. **Set this whenever the box is reachable by others.** Empty = open on the LAN. |
| `bind_host` | `0.0.0.0` = reachable from other devices (default). `127.0.0.1` = this box only. |
| `bind_port` | default `8777`. |
| `scan_timeout_sec`, `max_concurrent_scans` | safety limits. |

## Reaching it from your phone off-network
On the same Wi-Fi, the LAN IP just works. For true remote access (phone on cellular) you'd put it
behind a tunnel like `cloudflared` **with `access_token` set** — but understand you're then exposing
a scanner, so only do that behind real auth/VPN and never point it at networks you don't own.

## How it's built
- `server.py` — stdlib HTTP server: serves the UI, exposes `/api/scan` (start) and `/api/scan/<id>` (poll).
- `scanner.py` — scope guard (`ipaddress`), nmap command builder (fixed flag allow-list, no shell),
  background job runner, nmap XML → structured results.
- `web/` — the UI (vanilla HTML/CSS/JS, mobile-responsive).

Safety notes: the client never sends raw nmap flags — the server only emits flags from a fixed map,
targets are validated against the scope before anything runs, and nmap is executed as an argument
list (no shell), so there's no command injection surface.

## Roadmap ideas
- Scan history / saved results, export to JSON/CSV
- Diff two scans (new/closed ports) — ties to CPT change detection
- Presets ("quick triage", "full audit")
- Per-user tokens + an audit log of who scanned what
