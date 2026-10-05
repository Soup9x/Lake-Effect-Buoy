# Release signing

Agent binaries and install scripts are signed with a minisign (Ed25519) key. The **secret key never lives on the console server or in this repository**; signing happens on an offline release workstation. The public key is committed at `internal/release/minisign.pub`, compiled into the agent (`clamav-agent verify`, `clamav-agent version`) and rendered into both install scripts by `scripts/build-dist.sh`.

Until a real key is committed, `minisign.pub` is a clearly marked placeholder and `make dist` / `make sign` refuse to run.

## Generate the key (once, offline)

On an offline machine with a Go toolchain (or a prebuilt `release-sign` binary):

```sh
go build -o release-sign ./cmd/release-sign
./release-sign keygen -s /media/usb/minisign.key -p minisign.pub
```

You are prompted for a password (or set `MINISIGN_PASSWORD`). The secret key file is encrypted with a key derived from it by scrypt (the standard minisign format) and is compatible with the `minisign` CLI; `minisign -G` works too.

Then commit only the public key:

```sh
cp minisign.pub internal/release/minisign.pub
git add internal/release/minisign.pub
```

## Back up the secret key

- Keep at least two copies of `minisign.key` on encrypted offline media (e.g. two USB drives in different safes). Store the password separately (password manager / sealed envelope).
- Never copy the key to the console server, CI, a shared drive or this repo (`.gitignore` excludes `*.key`).
- Losing the key means you cannot ship updates that existing install scripts trust; you would have to rotate (below).

## Sign a release

```sh
# Any build machine:
make dist VERSION=1.2.0          # = scripts/build-dist.sh; writes dist/downloads/ + SHA256SUMS
# Copy dist/downloads to the offline workstation, then there:
MINISIGN_SECRET_KEY=/media/usb/minisign.key make sign   # = scripts/sign-dist.sh
```

`sign-dist.sh` signs every file (binaries, install/uninstall scripts, systemd unit, `SHA256SUMS`) as `FILE.minisig` with prehashed signatures, checks the secret key matches the committed public key, and verifies every signature afterwards. Copy the whole `dist/downloads/` directory (files and `.minisig`s) to the console's downloads directory; it is served flat at `/downloads/<file>`.

Anyone can check a file with the standard CLI: `minisign -Vm FILE -p internal/release/minisign.pub`.

## Rotate the public key

Rotation is needed if the secret key is lost or may be compromised.

1. Generate a new key pair offline (above) and commit the new `internal/release/minisign.pub`.
2. Rebuild and sign a full release with the new key. This produces agents and install scripts that trust only the new key.
3. Existing install scripts that admins saved elsewhere embed the old key and will refuse the new binaries; replace them with the new signed scripts.
4. Already installed agents are not affected at runtime (they do not self-update in Phase 1); upgrade them by rerunning the new install script.
5. If the old key was compromised, also remove all old-key-signed files from the downloads directory.

## Testing with a throwaway key

For development only, `RELEASE_PUBKEY_FILE` points the build at a test public key instead of the committed one. It is injected into the agent with `-ldflags -X` (and shown as a TEST key by `clamav-agent version`) and rendered into the scripts. The scripts print loud warnings; never publish such a bundle.

```sh
./release-sign keygen -s /tmp/test.key -p /tmp/test.pub
RELEASE_PUBKEY_FILE=/tmp/test.pub scripts/build-dist.sh
RELEASE_PUBKEY_FILE=/tmp/test.pub MINISIGN_SECRET_KEY=/tmp/test.key scripts/sign-dist.sh
```

`scripts/release.sh --test` does all of this in one step for a test VM: it keeps the throwaway key outside the checkout, builds, signs and publishes to the local console (docs/operations.md).

## Windows: interim verifier, Authenticode later

Windows has no built-in Ed25519 or BLAKE2b, so `install.ps1` currently verifies minisign signatures with an inline C# implementation (tested against Wycheproof and BLAKE2b reference vectors in CI, see `packaging/windows/tests/`). This is interim. Once we have a code-signing certificate, the release process will Authenticode-sign `clamav-agent_windows_amd64.exe` (and the PowerShell scripts), `install.ps1` will check `Get-AuthenticodeSignature` for a `Valid` status and the expected signer thumbprint, and the inline verifier will be removed. Linux keeps minisign.
