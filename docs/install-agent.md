# Installing the ClamAV console agent

The agent runs on each client endpoint, asks the local clamd for its status (`PING` and `VERSION` only) and reports it to the console over outbound HTTPS. It never listens on a network port.

| | Linux | Windows |
|---|---|---|
| Runs as | systemd unit `clamav-agent`, user `clamav-agent` | service `ClamAVAgent`, virtual account `NT SERVICE\ClamAVAgent` |
| Binary | `/usr/local/bin/clamav-agent` | `%ProgramFiles%\ClamAVAgent\clamav-agent.exe` |
| Config | `/etc/clamav-agent/agent.yaml` (root, 0644, no secrets) | `%ProgramData%\ClamAVAgent\agent.yaml` (service: read only) |
| Credential | `/var/lib/clamav-agent/credential` (clamav-agent, 0600; dir 0700) | `%ProgramData%\ClamAVAgent\credential` (service + Administrators only) |
| Logs | journal: `journalctl -u clamav-agent` | `%ProgramData%\ClamAVAgent\logs\agent.log` (5 MB x 3), plus stderr |
| clamd | Unix socket (auto-detected) | `tcp://127.0.0.1:3310` (read from `clamd.conf`) |

## Quick install: paste one command

In the console, open the client's tenant, go to *Enrollment tokens* and create a token. The page shows the token once, with a ready-made command for each OS:

- **Linux:** paste it into a terminal on the endpoint. It uses `sudo` (drop `sudo` if you are already root).
- **Windows:** paste it into PowerShell opened with *Run as administrator*.

That is all: the command downloads the installer, which verifies the agent's release signature, installs it as a service, enrolls the machine and starts it. On Debian/Ubuntu it also installs and sets up ClamAV if needed (see [ClamAV setup](#clamav-setup-linux)). It ends with **ALL SET** or with an **ACTION NEEDED** line saying exactly what is left. Within about a minute the endpoint shows as online. The token is passed to the installer on stdin (Linux) or in the PowerShell session's environment (Windows), never as a command-line argument. The Linux command starts with a space so that bash's `ignorespace` (Ubuntu's default) keeps it out of the shell history.

If the console uses a private CA (for example a test VM reached by IP address, see [Console with a private CA](#console-with-a-private-ca)), the commands also carry the CA's fingerprint and need nothing installed beforehand.

The sections below describe the installers' options, for running them from an RMM tool or by hand.

## What you need

- The console URL, e.g. `https://console.example.com` (must be https).
- An enrollment token for the client's tenant (`cav_enr_...`), created in the console under *Tenant → Enrollment tokens*. It is shown once.
- ClamAV with clamd. On Debian/Ubuntu the Linux installer sets it up for you; elsewhere, install and start clamd first. (The agent still installs without it and reports `not_installed` / `not_responding`.)

## Linux

Supported: systemd distributions on amd64 and arm64. Run as root:

```sh
curl -fsSL https://console.example.com/downloads/install.sh -o install.sh
printf '%s\n' 'cav_enr_...' | sh install.sh --server https://console.example.com --token-stdin
```

Options (each can also be given as an environment variable, which suits RMM tools that run scripts as root with variables):

| Option | Variable | Required | Meaning |
|---|---|---|---|
| `--server URL` | `CAV_SERVER_URL` | yes | Console URL, `https://` only |
| `--token-stdin` | `CAV_ENROLL_TOKEN` | to enroll | Enrollment token, read from stdin with `--token-stdin`. Passed to the agent via the environment, never on a command line |
| `--ca-sha256 HEX` | `CAV_CA_SHA256` | private CA only | SHA-256 fingerprint of the console's CA certificate (see below) |
| `--clamd ADDR` | `CAV_CLAMD_ADDR` | no | `unix:///path/to/clamd.sock` or `tcp://127.0.0.1:3310`. Default: first existing of `/run/clamav/clamd.ctl` (Debian/Ubuntu), `/run/clamd.scan/clamd.sock` (RHEL), `/var/run/clamav/clamd.ctl` |
| `--no-clamav-setup` | `CAV_CLAMAV_SETUP=0` | no | Leave ClamAV alone (see [ClamAV setup](#clamav-setup-linux)). Implied by `--clamd` |
| `--scan-roots LIST` | `CAV_SCAN_ROOTS` | no | Folders the console may scan, comma-separated, e.g. `/srv,/var/www`. An empty list turns scans off. Default: keep the current list (none on a new install). See [Actions from the console](#actions-from-the-console) |
| `--reinstall` | | no | Enroll again with a new token |

What `install.sh` does:

1. With `--ca-sha256`: downloads the console's CA certificate and continues only if its fingerprint matches. Otherwise reuses a CA installed by an earlier run, if any.
2. Downloads `clamav-agent_linux_<arch>`, `clamav-agent.service` and their `.minisig` files from `$CAV_SERVER_URL/downloads/`.
3. **Verifies the minisign signatures** with the release public key embedded in the script (see below). Nothing is installed if verification fails.
4. Creates the system user `clamav-agent` (no login shell), sets up ClamAV (below), and adds the agent user to the group that owns the clamd socket.
5. Installs the binary (and the CA at `/etc/clamav-agent/console-ca.pem`), runs `clamav-agent enroll`, sets ownership/permissions, installs and starts the hardened systemd unit.

6. Waits (a few minutes at most) until the agent gets an answer from clamd, then prints **ALL SET**, or **ACTION NEEDED** with the exact fix.

It is idempotent: running it again upgrades the binary and unit and keeps the existing enrollment (no token needed). `sh install.sh --reinstall` enrolls again with a new token and asks the console to replace this machine's previous agent.

### ClamAV setup (Linux)

Unless you pass `--no-clamav-setup` (or `--clamd`, which means you manage clamd yourself), the installer makes sure ClamAV works on Debian/Ubuntu:

1. Installs `clamav-daemon` and `clamav-freshclam` with `apt-get` if clamd is missing (waiting up to 5 minutes for another apt run, such as unattended upgrades, to finish).
2. Enables `clamav-freshclam` and waits for it to download the virus databases. Ubuntu's `clamav-daemon` does not start without them.
3. Turns on clamd's `VERSION`, `RELOAD` and `STATS` commands where `/etc/clamav/clamd.conf` lists them as off (ClamAV 1.5 packages ship them off; the agent needs `VERSION` to report signature versions, freshclam and the console's "Reload signatures" action use `RELOAD`, and the "clamd stats" action uses `STATS`). The original file is kept as `clamd.conf.cav-orig`. Options the file does not list are left alone, because older clamd refuses unknown options.
4. Enables and starts `clamav-daemon`.

On other distributions it installs nothing and prints what to do (RHEL/Rocky/Alma: `dnf install clamd clamav-update` from EPEL); install and start clamd, then run the installer again (no token needed).

Uninstall: `sh uninstall.sh` (or `--keep-data` to keep config and credential). Then revoke the endpoint in the console.

## Windows

Windows Server 2016+ / Windows 10+, amd64, Windows PowerShell 5.1 or PowerShell 7. In an elevated PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing https://console.example.com/downloads/install.ps1 -OutFile install.ps1
$env:CAV_ENROLL_TOKEN = 'cav_enr_...'
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -ServerUrl https://console.example.com
Remove-Item Env:\CAV_ENROLL_TOKEN
```

(The first line matters on older Windows PowerShell, which may otherwise try TLS 1.0.)

Parameters: `-ServerUrl` (required, https), `-EnrollToken` (or `$env:CAV_ENROLL_TOKEN`; the environment variable keeps the token out of the process list), `-CaSha256` (or `$env:CAV_CA_SHA256`; private CA only, see below), `-ClamdAddress` (default: `TCPAddr`/`TCPSocket` from `%ProgramFiles%\ClamAV\clamd.conf`, else `tcp://127.0.0.1:3310`), `-Reinstall`. From an RMM tool that runs scripts as SYSTEM, run `install.ps1` with these parameters and the token in `CAV_ENROLL_TOKEN`.

What `install.ps1` does:

1. With `-CaSha256`: downloads the console's CA certificate and continues only if its fingerprint matches; all further downloads must then chain to that CA. Otherwise reuses a CA installed by an earlier run, if any.
2. Downloads `clamav-agent_windows_amd64.exe` and its `.minisig`.
3. **Verifies the minisign signature** with the embedded release public key. Windows has no built-in Ed25519 or BLAKE2b, so the script compiles a small C# verifier (`Add-Type`).
4. Installs the binary to `%ProgramFiles%\ClamAVAgent`, creates the `ClamAVAgent` service (automatic start) running as `NT SERVICE\ClamAVAgent`, recovery = restart on crash.
5. Sets ACLs on `%ProgramData%\ClamAVAgent` (inheritance disabled; Administrators full, SYSTEM on the folder only, service Modify so it can replace its credential atomically), installs the CA (if any) as `console-ca.pem`, enrolls, then locks the credential to the service account + Administrators and makes the config and CA read-only for the service.
6. Starts the service and prints `clamav-agent status`.

> **Interim Windows verifier.** The inline C# minisign verifier in `install.ps1` is a stopgap until we have a Windows code-signing certificate. It is tested against the Project Wycheproof Ed25519 vectors and the BLAKE2b reference vectors on Windows PowerShell 5.1 and PowerShell 7 (`packaging/windows/tests/Test-Verifier.ps1`, run in CI). Once a certificate is in place, the Windows binary will be Authenticode-signed and `install.ps1` will verify it with `Get-AuthenticodeSignature` (status `Valid` and the expected signer certificate thumbprint) instead, and the inline verifier will be removed.

It is idempotent; `-Reinstall` enrolls again. Uninstall: `.\uninstall.ps1` (or `-KeepData`), then revoke the endpoint in the console.

clamd on Windows must listen on loopback. The agent refuses any clamd address other than `127.0.0.0/8`, `::1` or `localhost`.

## Console with a private CA

A console reached by IP address or by a local name (for example a test VM at `https://192.168.1.50` or `https://buoy.internal`) gets its TLS certificate from Caddy's internal CA, which endpoints do not trust. `deploy/setup.sh` publishes that CA as `/downloads/console-ca.pem`, and the console then adds the CA's SHA-256 fingerprint to every install command. Nothing needs to be installed on endpoints beforehand:

- The CA certificate is fetched without TLS verification (it is what TLS will be verified with) and used only if its fingerprint matches the one in the command, which you copied from the console together with the token.
- **Linux:** the command then fetches `install.sh` over TLS checked against that CA only (`curl --cacert`), and `install.sh` checks the CA again.
- **Windows:** PowerShell has no per-request CA option, so the command pins `install.ps1` itself by its SHA-256 (computed by the console from the published file). `install.ps1` then checks the CA again and requires every further download to chain to it. If you publish a new agent release, generate a new command, because the old one pins the old `install.ps1`.
- The agent stores the CA (`/etc/clamav-agent/console-ca.pem`, `%ProgramData%\ClamAVAgent\console-ca.pem`) and its config points to it with `ca_cert_file`. The agent then trusts **only** that CA for the console, not the system trust store. Upgrade runs of the installers reuse the installed CA; `--reinstall` / `-Reinstall` uses only what its command gives it.

If the console later moves to a publicly trusted certificate, re-enroll endpoints with a fresh command from the console plus `--reinstall` / `-Reinstall`; the old CA is removed. (Or remove the `ca_cert_file` line from `agent.yaml` and restart the agent.)

The fingerprint is shown on the token page and printed by `setup.sh`; you can compare it with `openssl x509 -in console-ca.pem -noout -fingerprint -sha256`.

## What the scripts verify, and the trust chain

Agent binaries are signed offline with a minisign (Ed25519) key that never touches the console server (see [release-signing.md](release-signing.md)). The public key is compiled into the agent and baked into both install scripts at build time; it is **never** fetched from the server. The scripts check the key id, the file signature (prehashed `ED` or legacy `Ed`) and the trusted-comment signature, and abort on any mismatch. On Linux they use the `minisign` CLI when installed, otherwise `openssl` 3.x + `b2sum`; if neither is available they abort.

The commands from the console fetch the install script itself from the console, so a compromised console could serve a modified script (with a private CA, the CA fingerprint and the Windows script hash also come from the console). For the strictest trust, deploy the install script from the signed release bundle (via your RMM or a file share) and check its own signature first with any minisign verifier, e.g. `minisign -Vm install.sh -P <release public key>`, or `clamav-agent verify install.sh install.sh.minisig` with an agent you already trust.

You can also check any downloaded file by hand:

```sh
sh install.sh --verify-only clamav-agent_linux_amd64 clamav-agent_linux_amd64.minisig
```
```powershell
.\install.ps1 -VerifyOnly -VerifyFile .\clamav-agent_windows_amd64.exe -VerifySignatureFile .\clamav-agent_windows_amd64.exe.minisig
```

## Actions from the console

The console can ask an endpoint to run one of a fixed list of ClamAV actions, on one endpoint (the endpoint's page) or on many at once (a tenant's **Run action…** button). Nothing else can be run: the agent has no way to execute commands, scripts or programs sent by the console (CLAUDE.md rule 1).

| Action | What the endpoint does | Needs in `clamd.conf` |
|---|---|---|
| Check clamd | Asks clamd for its version and signature database version | `EnableVersionCommand yes` |
| Reload signatures | Tells clamd to reload its signature databases (`RELOAD`) | `EnableReloadCommand yes` |
| clamd stats | Returns clamd's thread pool and queue statistics (`STATS`) | `EnableStatsCommand yes` |
| Scan a folder | clamd scans the folder (`CONTSCAN`) and reports infected files and files it could not read. Nothing is quarantined or deleted | a scan folder set on the endpoint (below) |

The Linux installer turns these clamd commands on. On Windows, set them in `clamd.conf` yourself if your build ships them off.

Endpoints pick actions up on their next heartbeat (within about a minute) and check in every 15 seconds while they have actions open. An action not picked up within 24 hours expires; a running action must report within 10 minutes (4 hours 15 minutes for scans). One scan runs at a time per endpoint. Results are kept for 90 days.

**Scan folders.** The console can only scan folders that were allowed **on the endpoint itself**; the list lives in the agent's local config (`scan_roots` in `agent.yaml`) and the console cannot change it. Until one is set, scan requests are refused. A requested folder must be inside an allowed folder after symlinks are resolved. To set the list (it replaces the old one; no arguments turns scans off):

- Linux: rerun the installer with `--scan-roots /srv,/var/www` (no token needed), or `sudo clamav-agent set-scan-roots /srv /var/www && sudo systemctl restart clamav-agent`
- Windows: `& "$env:ProgramFiles\ClamAVAgent\clamav-agent.exe" set-scan-roots D:\Shares E:\Web; Restart-Service ClamAVAgent`

clamd runs as its own user (`clamav` on Debian/Ubuntu), so it can only scan files that user can read; others are listed as "not scanned" with the reason. Scanning a large tree loads the machine like any clamd scan.

**Output and export.** Each run opens a page that updates as endpoints report, with a link to each endpoint's full output. Export a run as CSV or JSON, or just the infected files of a scan as CSV; an endpoint's page exports its action history. Cells that a spreadsheet would treat as a formula are prefixed with `'`, since file names on an endpoint can be chosen by an attacker. Every queue and cancel, and every refused request, is recorded in the audit log.

## Checking status

- Linux: `sudo clamav-agent status`, `systemctl status clamav-agent`, `journalctl -u clamav-agent -f`
- Windows: `& "$env:ProgramFiles\ClamAVAgent\clamav-agent.exe" status`, `Get-Service ClamAVAgent`, `Get-Content $env:ProgramData\ClamAVAgent\logs\agent.log -Tail 50`

`status` shows the config, whether a credential is present (never its value) and a live clamd query. The console marks an endpoint offline after 3 minutes without a heartbeat.

## Troubleshooting

**clamd `not_responding` with "permission denied" (Linux).** The agent user must be in the group that owns the clamd socket. Check `ls -l /run/clamav/clamd.ctl` and `id clamav-agent`. If the socket's group is `root`, set `LocalSocketGroup` (e.g. `clamav`) and `LocalSocketMode 660` in `clamd.conf`, restart clamd, then rerun `install.sh` (or `usermod -aG <group> clamav-agent && systemctl restart clamav-agent`).

**clamd running, error "the VERSION command is disabled".** clamd answers PING but not VERSION, so the console shows no signature version. Set `EnableVersionCommand yes` in `clamd.conf` and run `systemctl restart clamav-daemon` (the Linux installer does this for you unless `--no-clamav-setup` was used). A ClamAV package upgrade may rewrite `clamd.conf`; if the error comes back, rerun the installer.

**clamd `not_responding` with "i/o timeout" right after clamd starts.** clamd is still loading its databases (30 to 60 seconds, about 1.5 GB of RAM). The agent retries; check `systemctl status clamav-daemon` if it lasts.

**clamd `not_installed`.** No clamd binary was found (`/usr/sbin/clamd`, `/usr/bin/clamd`, `/usr/local/sbin/clamd`, or `%ProgramFiles%\ClamAV\clamd.exe`) and clamd did not answer.

**Agent stopped with exit code 78.** Exit code 78 means the console revoked this agent (HTTP 401 with code `agent_revoked`), or the agent is not enrolled / its config is invalid. systemd (`RestartPreventExitStatus=78`) and the Windows service (stops with service-specific code 78, not treated as a crash) do **not** restart it. Check the log, then re-enroll with a new token: `install.sh --reinstall` / `install.ps1 -Reinstall`.

**Repeated "HEARTBEAT REJECTED WITH 401 (not a revocation)" in the log.** Any 401 other than `agent_revoked` (a proxy, a server bug, a credential the server does not recognise) is logged at error level and retried every 30 to 60 minutes; the agent keeps running so a server-side mistake cannot take down a fleet. Fix the server or proxy, or re-enroll if the credential is genuinely bad.

**Network errors / 5xx / 429.** Retried with exponential backoff from 60 s up to 5 minutes, then the normal interval resumes.

**Self-hosted or private CA.** By default the agent uses the system trust store. For a console with a private CA, the installers set `ca_cert_file` (see [Console with a private CA](#console-with-a-private-ca)); the agent then trusts only that CA. "console CA fingerprint mismatch" means the CA served by the console is not the one in your command: do not work around it; check the fingerprint in the console and `setup.sh` output. Separately, you can pin the console's certificate chain with `ca_cert_pin` (base64 SHA-256 of a SubjectPublicKeyInfo in the chain) in `agent.yaml`, or pass `--ca-cert-pin` to `clamav-agent enroll`. Compute it with:
`openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`

**Proxy.** The agent honours `HTTPS_PROXY`/`NO_PROXY` (set them in a systemd drop-in, or in the service's environment on Windows).

**Signature verification failed.** Do not work around it. Either the download was corrupted or tampered with, or the server hosts a bundle signed with a different key than the one in your install script. Get a fresh install script from the signed release bundle.
