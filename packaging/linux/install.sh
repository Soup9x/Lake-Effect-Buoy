#!/bin/sh
# Installs the ClamAV console agent as the systemd service clamav-agent.
#
# Usage (as root):
#   printf '%s\n' cav_enr_... | sh install.sh --server https://console.example.com --token-stdin
#   CAV_SERVER_URL=https://console.example.com CAV_ENROLL_TOKEN=cav_enr_... sh install.sh
#   sh install.sh --reinstall ...      # enroll again, replacing this machine's agent
#   sh install.sh --verify-only FILE SIGFILE   # only check a minisign signature
#
# Options (each can also be set in the environment):
#   --server URL        CAV_SERVER_URL    required, https:// console URL
#   --token-stdin       CAV_ENROLL_TOKEN  enrollment token, required when enrolling
#                                         (first install or --reinstall); with
#                                         --token-stdin it is read from stdin
#   --ca-sha256 HEX     CAV_CA_SHA256     only for a console with a private CA:
#                                         SHA-256 fingerprint of its CA certificate
#   --clamd ADDR        CAV_CLAMD_ADDR    clamd address (unix:///path or
#                                         tcp://127.0.0.1:3310); default: auto-detect.
#                                         Implies --no-clamav-setup.
#   --no-clamav-setup   CAV_CLAMAV_SETUP=0  leave ClamAV alone (see below)
#   --scan-roots LIST   CAV_SCAN_ROOTS    folders the console may scan, comma-
#                                         separated (e.g. /srv,/var/www); an empty
#                                         LIST turns scans off. Default: keep the
#                                         current list (none on a new install, so
#                                         scans from the console are refused).
#   --reinstall                           enroll again with a new token
#
# The agent binary and the systemd unit are downloaded from
# $CAV_SERVER_URL/downloads/ and their minisign signatures are VERIFIED against
# the public key embedded below before anything is installed. The key is
# never fetched from the server.
#
# ClamAV setup (Debian/Ubuntu, unless --no-clamav-setup): installs
# clamav-daemon if clamd is missing, enables freshclam and waits for the
# virus databases, turns on clamd's VERSION, RELOAD and STATS commands where
# clamd.conf lists them as off (the original is kept as clamd.conf.cav-orig),
# and starts clamd. Other distributions get instructions instead.
#
# With --ca-sha256, the console's CA certificate is downloaded and used only
# if its fingerprint matches; it is installed for the agent, which then trusts
# only that CA for the console. Later upgrade runs reuse the installed CA;
# --reinstall uses only what it is given.
set -eu

# Substituted by scripts/build-dist.sh. Release signing public key (minisign).
MINISIGN_PUBKEY='__MINISIGN_PUBKEY__'

BIN_DST=/usr/local/bin/clamav-agent
UNIT_DST=/etc/systemd/system/clamav-agent.service
CONF_DIR=/etc/clamav-agent
CONF_FILE=$CONF_DIR/agent.yaml
STATE_DIR=/var/lib/clamav-agent
CRED_FILE=$STATE_DIR/credential
CA_FILE=$CONF_DIR/console-ca.pem
AGENT_USER=clamav-agent
SOCKET_CANDIDATES="/run/clamav/clamd.ctl /run/clamd.scan/clamd.sock /var/run/clamav/clamd.ctl"
CLAMD_CONF=/etc/clamav/clamd.conf
CLAMAV_DB=/var/lib/clamav

WORK=''
# CA bundle for downloads from the console (private CA), or empty for the
# system trust store.
CA=''
cleanup() { if [ -n "$WORK" ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT INT TERM

die() { echo "install.sh: ERROR: $*" >&2; exit 1; }
say() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# minisign verification
# ---------------------------------------------------------------------------

check_pubkey() {
    # Must be a rendered key ("RW" + 54 base64 chars), not the template token.
    case "$MINISIGN_PUBKEY" in
        RW*) ;;
        *) die "this install script has no release public key embedded; use the install.sh produced by scripts/build-dist.sh" ;;
    esac
    [ "${#MINISIGN_PUBKEY}" -eq 56 ] || die "embedded public key has the wrong length"
    printf '%s' "$MINISIGN_PUBKEY" | grep -Eq '^RW[A-Za-z0-9+/]{54}$' || die "embedded public key is malformed"
}

# hex_to_bin HEX: write the bytes encoded by HEX to stdout (POSIX sh + awk).
hex_to_bin() {
    # shellcheck disable=SC2059 # the format is a generated \ooo escape list
    printf "$(printf '%s' "$1" | awk '{
        h = "0123456789abcdef"; s = tolower($0); out = ""
        for (i = 1; i < length(s); i += 2) {
            v = (index(h, substr(s, i, 1)) - 1) * 16 + index(h, substr(s, i + 1, 1)) - 1
            out = out sprintf("\\%03o", v)
        }
        printf "%s", out
    }')"
}

b64dec() { printf '%s' "$1" | openssl base64 -d -A; }
hexof() { od -An -tx1 -v | tr -d ' \n'; }

# ed25519_verify PUBKEY_PEM MESSAGE_FILE SIG_FILE (raw 64-byte signature)
ed25519_verify() {
    openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$2" -sigfile "$3" >/dev/null 2>&1
}

# verify_with_openssl FILE SIGFILE: full minisign verification (both
# signatures and the key id) with openssl 3 + b2sum.
verify_with_openssl() {
    _t=$(mktemp -d) || return 1
    if _verify_openssl_inner "$1" "$2"; then _rc=0; else _rc=1; fi
    rm -rf "$_t"
    return $_rc
}

_verify_openssl_inner() {
    _file=$1; _sig=$2

    _l1=$(sed -n '1p' "$_sig" | tr -d '\r')
    _l2=$(sed -n '2p' "$_sig" | tr -d '\r')
    _l3=$(sed -n '3p' "$_sig" | tr -d '\r')
    _l4=$(sed -n '4p' "$_sig" | tr -d '\r')
    case "$_l1" in "untrusted comment: "*) ;; *) echo "bad untrusted comment line" >&2; return 1 ;; esac
    case "$_l3" in "trusted comment: "*) ;; *) echo "bad trusted comment line" >&2; return 1 ;; esac
    printf '%s' "$_l2" | grep -Eq '^[A-Za-z0-9+/]{99}=$' || { echo "malformed signature line" >&2; return 1; }
    printf '%s' "$_l4" | grep -Eq '^[A-Za-z0-9+/]{86}==$' || { echo "malformed global signature line" >&2; return 1; }

    b64dec "$MINISIGN_PUBKEY" > "$_t/pk" || return 1
    b64dec "$_l2" > "$_t/sigblob" || return 1
    b64dec "$_l4" > "$_t/gsig" || return 1
    [ "$(wc -c < "$_t/pk" | tr -d ' ')" -eq 42 ] || { echo "bad public key length" >&2; return 1; }
    [ "$(wc -c < "$_t/sigblob" | tr -d ' ')" -eq 74 ] || { echo "bad signature length" >&2; return 1; }
    [ "$(wc -c < "$_t/gsig" | tr -d ' ')" -eq 64 ] || { echo "bad global signature length" >&2; return 1; }

    [ "$(dd if="$_t/pk" bs=1 count=2 2>/dev/null | hexof)" = "4564" ] || { echo "unsupported public key algorithm" >&2; return 1; }
    _keyid_pk=$(dd if="$_t/pk" bs=1 skip=2 count=8 2>/dev/null | hexof)
    _keyid_sig=$(dd if="$_t/sigblob" bs=1 skip=2 count=8 2>/dev/null | hexof)
    [ "$_keyid_pk" = "$_keyid_sig" ] || { echo "signature was made with a different key (key id mismatch)" >&2; return 1; }

    # SubjectPublicKeyInfo DER prefix for an Ed25519 key, then the 32 raw bytes.
    { hex_to_bin 302a300506032b6570032100; dd if="$_t/pk" bs=1 skip=10 count=32 2>/dev/null; } > "$_t/pk.der"
    openssl pkey -pubin -inform DER -in "$_t/pk.der" -out "$_t/pk.pem" 2>/dev/null || { echo "cannot load public key" >&2; return 1; }
    dd if="$_t/sigblob" bs=1 skip=10 count=64 2>/dev/null > "$_t/sig"

    case "$(dd if="$_t/sigblob" bs=1 count=2 2>/dev/null | hexof)" in
        4544) # "ED": signature over BLAKE2b-512(file)
            command -v b2sum >/dev/null 2>&1 || { echo "b2sum is required for prehashed signatures" >&2; return 1; }
            _h=$(b2sum -l 512 < "$_file" | cut -d' ' -f1)
            printf '%s' "$_h" | grep -Eq '^[0-9a-f]{128}$' || { echo "b2sum failed" >&2; return 1; }
            hex_to_bin "$_h" > "$_t/msg"
            ed25519_verify "$_t/pk.pem" "$_t/msg" "$_t/sig" || { echo "signature verification FAILED" >&2; return 1; }
            ;;
        4564) # "Ed": legacy signature over the file itself
            ed25519_verify "$_t/pk.pem" "$_file" "$_t/sig" || { echo "signature verification FAILED" >&2; return 1; }
            ;;
        *) echo "unsupported signature algorithm" >&2; return 1 ;;
    esac

    # Global signature: Ed25519 over (signature || trusted comment text).
    { cat "$_t/sig"; printf '%s' "${_l3#trusted comment: }"; } > "$_t/global"
    ed25519_verify "$_t/pk.pem" "$_t/global" "$_t/gsig" || { echo "trusted comment signature verification FAILED" >&2; return 1; }

    echo "trusted comment: ${_l3#trusted comment: }"
    return 0
}

openssl_usable() {
    command -v openssl >/dev/null 2>&1 || return 1
    _v=$(openssl version 2>/dev/null | awk '{print $2}')
    case "$_v" in [3-9].*) ;; *) return 1 ;; esac
    command -v b2sum >/dev/null 2>&1
}

# minisign_verify FILE SIGFILE: verify with the minisign CLI when installed,
# else openssl 3 + b2sum. CAV_VERIFIER=openssl|minisign forces one (testing).
minisign_verify() {
    check_pubkey
    _mode=${CAV_VERIFIER:-auto}
    if [ "$_mode" = minisign ] || { [ "$_mode" = auto ] && command -v minisign >/dev/null 2>&1; }; then
        command -v minisign >/dev/null 2>&1 || die "minisign CLI not found"
        # -V verifies both the file signature and the trusted comment signature.
        minisign -V -q -P "$MINISIGN_PUBKEY" -m "$1" -x "$2"
        return $?
    fi
    if [ "$_mode" = openssl ] || [ "$_mode" = auto ]; then
        openssl_usable || die "cannot verify signatures: install minisign, or openssl >= 3 and b2sum (coreutils)"
        verify_with_openssl "$1" "$2"
        return $?
    fi
    die "unknown CAV_VERIFIER '$_mode'"
}

# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------

download() { # URL DEST
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$CA" ]; then
            curl --proto '=https' --tlsv1.2 -fsSL --cacert "$CA" -o "$2" "$1"
        else
            curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$CA" ]; then
            wget --https-only --ca-certificate="$CA" -q -O "$2" "$1"
        else
            wget --https-only -q -O "$2" "$1"
        fi
    else
        die "curl or wget is required"
    fi
}

# cert_fingerprint PEM_FILE: lowercase hex SHA-256 of the DER certificate.
cert_fingerprint() {
    openssl x509 -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1
}

# fetch_console_ca BASE FINGERPRINT DEST: download the console's CA
# certificate and accept it only if its fingerprint matches. It is fetched
# without TLS verification because it is what TLS will be verified with;
# the fingerprint, from the console admin, is what makes it trusted.
fetch_console_ca() {
    command -v openssl >/dev/null 2>&1 || die "openssl is required to check the console CA"
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to check the console CA"
    _url="$1/downloads/console-ca.pem"
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSk -o "$3" "$_url" || die "cannot download $_url"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --no-check-certificate -q -O "$3" "$_url" || die "cannot download $_url"
    else
        die "curl or wget is required"
    fi
    [ "$(grep -c -- '-----BEGIN CERTIFICATE-----' "$3")" -eq 1 ] || die "$_url must hold exactly one certificate"
    _got=$(cert_fingerprint "$3")
    [ "$_got" = "$2" ] || die "console CA fingerprint mismatch (got ${_got:-nothing}, expected $2); NOT installing"
    # Keep only the verified certificate, in canonical PEM.
    openssl x509 -in "$3" -out "$3.pem" 2>/dev/null || die "cannot read the console CA certificate"
    mv -f "$3.pem" "$3"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac
}

# Prints the clamd socket path, or nothing.
detect_socket() {
    for s in $SOCKET_CANDIDATES; do
        if [ -S "$s" ]; then echo "$s"; return 0; fi
    done
    return 0
}

ensure_user() {
    if id "$AGENT_USER" >/dev/null 2>&1; then return 0; fi
    _nologin=/usr/sbin/nologin
    [ -x "$_nologin" ] || _nologin=/sbin/nologin
    [ -x "$_nologin" ] || _nologin=/bin/false
    command -v useradd >/dev/null 2>&1 || die "useradd not found"
    useradd --system --no-create-home --home-dir "$STATE_DIR" --shell "$_nologin" "$AGENT_USER"
    say "created system user $AGENT_USER"
}

join_socket_group() { # SOCKET_PATH
    _grp=$(stat -c %G "$1" 2>/dev/null || true)
    case "$_grp" in
        ''|UNKNOWN) echo "WARNING: cannot determine the group of $1" >&2 ;;
        root) echo "WARNING: $1 is owned by group root; not adding $AGENT_USER to root. Adjust clamd's LocalSocketGroup." >&2 ;;
        *)
            if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$_grp"; then
                say "$AGENT_USER is already in group $_grp"
            else
                usermod -a -G "$_grp" "$AGENT_USER"
                say "added $AGENT_USER to group $_grp (owner of $1)"
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------------
# ClamAV setup
# ---------------------------------------------------------------------------

clamd_installed() { command -v clamd >/dev/null 2>&1 || [ -x /usr/sbin/clamd ]; }

db_ready() { # the main and daily signature databases are both present
    { [ -f "$CLAMAV_DB/main.cvd" ] || [ -f "$CLAMAV_DB/main.cld" ]; } &&
        { [ -f "$CLAMAV_DB/daily.cvd" ] || [ -f "$CLAMAV_DB/daily.cld" ]; }
}

# enable_clamd_command NAME: switch on a clamd command that clamd.conf lists
# as off. Returns 0 if the file changed. An option clamd.conf does not list is
# left alone: older clamd refuses to start on an option it does not know.
enable_clamd_command() {
    grep -Eqi "^[[:space:]]*$1[[:space:]]+(no|false)[[:space:]]*$" "$CLAMD_CONF" || return 1
    [ -f "$CLAMD_CONF.cav-orig" ] || cp -p "$CLAMD_CONF" "$CLAMD_CONF.cav-orig"
    sed -i -E "s/^[[:space:]]*$1[[:space:]]+[A-Za-z]+[[:space:]]*$/$1 yes/" "$CLAMD_CONF"
    say "set $1 yes in $CLAMD_CONF (original kept as $CLAMD_CONF.cav-orig)"
    return 0
}

# setup_clamav: make sure clamd is installed, has its databases, answers
# VERSION, and is running. Never fatal: the agent installs either way and
# the final check says what is left to do.
setup_clamav() {
    if ! clamd_installed; then
        if ! command -v apt-get >/dev/null 2>&1; then
            echo "WARNING: ClamAV (clamd) is not installed, and this installer only installs it on Debian/Ubuntu." >&2
            echo "         Install and start clamd yourself (RHEL/Rocky/Alma: dnf install clamd clamav-update from EPEL)," >&2
            echo "         then run this installer again; no token is needed." >&2
            return 0
        fi
        say "installing ClamAV (clamav-daemon, clamav-freshclam); this can take a minute"
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null ||
            echo "WARNING: apt-get update failed; trying the install anyway" >&2
        if ! DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq clamav-daemon clamav-freshclam >/dev/null; then
            echo "WARNING: could not install ClamAV with apt-get; install clamav-daemon yourself, then run this installer again." >&2
            return 0
        fi
    fi
    if ! systemctl cat clamav-daemon.service >/dev/null 2>&1 || ! systemctl cat clamav-freshclam.service >/dev/null 2>&1; then
        say "clamd is not set up as Debian/Ubuntu's clamav-daemon service here; leaving it as it is"
        return 0
    fi

    systemctl enable --now clamav-freshclam.service >/dev/null 2>&1 ||
        echo "WARNING: could not start clamav-freshclam; see: journalctl -u clamav-freshclam" >&2
    if ! db_ready; then
        say "waiting for freshclam to download the virus databases (usually under a minute)"
        _i=0
        while ! db_ready && [ "$_i" -lt 60 ]; do sleep 5; _i=$((_i + 1)); done
        db_ready || echo "WARNING: no virus databases in $CLAMAV_DB yet, and clamd cannot start without them; see: journalctl -u clamav-freshclam" >&2
    fi

    _changed=0
    if [ -f "$CLAMD_CONF" ]; then
        if enable_clamd_command EnableVersionCommand; then _changed=1; fi
        if enable_clamd_command EnableReloadCommand; then _changed=1; fi
        if enable_clamd_command EnableStatsCommand; then _changed=1; fi
    fi
    systemctl enable clamav-daemon.service >/dev/null 2>&1 || true
    if [ "$_changed" = 1 ] || ! systemctl is-active --quiet clamav-daemon.service; then
        say "starting clamav-daemon"
        systemctl restart clamav-daemon.service ||
            echo "WARNING: clamav-daemon did not start; see: journalctl -u clamav-daemon" >&2
    fi
    # The socket appears as soon as clamd (or its systemd socket) is up.
    _i=0
    while [ -z "$(detect_socket)" ] && [ "$_i" -lt 12 ]; do sleep 5; _i=$((_i + 1)); done
}

# final_check: wait (a few minutes at most) for the agent to reach clamd,
# then say plainly whether anything is left to do.
# apply_scan_roots LIST: set the folders the console may scan, from a comma-
# separated list (empty: none). The agent validates each folder; this is the
# only way to allow scans, and it needs root on this machine.
apply_scan_roots() {
    _list=$1
    set -f
    set --
    _old_ifs=$IFS
    IFS=,
    for _d in $_list; do
        _d=$(printf '%s' "$_d" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        if [ -n "$_d" ]; then set -- "$@" "$_d"; fi
    done
    IFS=$_old_ifs
    set +f
    "$BIN_DST" set-scan-roots --config "$CONF_FILE" "$@" >/dev/null || die "--scan-roots: folders must be absolute paths"
    if [ $# -eq 0 ]; then
        say "scans from the console are off on this machine"
    else
        say "the console may scan under: $*"
    fi
}

final_check() {
    _i=0
    while :; do
        _out=$("$BIN_DST" status --config "$CONF_FILE" --credential "$CRED_FILE" 2>&1 || true)
        case "$_out" in
            *"permission denied"*) break ;;      # waiting will not fix this
            *"clamd status: not_responding"*) ;; # clamd may still be loading its databases
            *) break ;;
        esac
        [ "$_i" -lt 36 ] || break
        if [ "$_i" = 0 ]; then say "waiting for clamd to answer (it loads its databases first; this can take a minute or two)"; fi
        _i=$((_i + 1))
        sleep 5
    done
    printf '%s\n' "$_out"
    echo
    case "$_out" in
        *"clamd status: running"*"error:"*)
            echo "ACTION NEEDED: clamd answers, but reported the error above." >&2
            echo "  If it says the VERSION command is disabled: set \"EnableVersionCommand yes\" in $CLAMD_CONF," >&2
            echo "  then run: systemctl restart clamav-daemon" >&2
            ;;
        *"clamd status: running"*)
            say "ALL SET: the agent reports this machine's ClamAV status to $base"
            ;;
        *"clamd status: not_installed"*)
            echo "ACTION NEEDED: ClamAV (clamd) is not installed. Install and start it, then run this installer again (no token needed)." >&2
            ;;
        *"permission denied"*|*"group"*)
            echo "ACTION NEEDED: the agent cannot open clamd's socket. Run this installer again once clamd is running (no token needed)," >&2
            echo "  or add the clamav-agent user to the socket's group and run: systemctl restart clamav-agent" >&2
            ;;
        *)
            echo "ACTION NEEDED: clamd is not answering. Check: systemctl status clamav-daemon; journalctl -u clamav-daemon -n 30" >&2
            echo "  (On a small VM clamd may need more memory: about 1.5 GB.) The agent keeps retrying; once clamd is up, nothing else is needed." >&2
            ;;
    esac
    case "$_out" in
        *"scan_roots: none"*)
            echo "Note: folder scans from the console are off on this machine. To allow them, run this installer again with"
            echo "  --scan-roots /srv,/var/www (no token needed), or: clamav-agent set-scan-roots /srv /var/www && systemctl restart clamav-agent"
            ;;
    esac
}

install_agent() {
    reinstall=$1
    token_stdin=$2
    clamav_setup=$3
    if [ "$token_stdin" = 1 ]; then
        # Read before anything else consumes stdin. The token never appears
        # on a command line.
        CAV_ENROLL_TOKEN=''
        IFS= read -r CAV_ENROLL_TOKEN || true
        CAV_ENROLL_TOKEN=$(printf '%s' "$CAV_ENROLL_TOKEN" | tr -d '\r')
        [ -n "$CAV_ENROLL_TOKEN" ] || die "--token-stdin: no enrollment token on stdin"
    fi
    if [ -n "${CAV_ENROLL_TOKEN:-}" ]; then
        case "$CAV_ENROLL_TOKEN" in
            cav_enr_*) ;;
            *) die "the enrollment token must start with cav_enr_" ;;
        esac
    fi
    [ "$(id -u)" -eq 0 ] || die "must be run as root"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    check_pubkey

    : "${CAV_SERVER_URL:?CAV_SERVER_URL is required}"
    case "$CAV_SERVER_URL" in
        https://*) ;;
        *) die "CAV_SERVER_URL must start with https://" ;;
    esac
    printf '%s' "$CAV_SERVER_URL" | grep -Eq '^https://[][A-Za-z0-9.:-]+(/[A-Za-z0-9._~/-]*)?$' || die "CAV_SERVER_URL looks malformed"
    base=${CAV_SERVER_URL%/}

    need_enroll=0
    if [ "$reinstall" = 1 ] || [ ! -f "$CRED_FILE" ]; then need_enroll=1; fi
    if [ "$need_enroll" = 1 ] && [ -z "${CAV_ENROLL_TOKEN:-}" ]; then
        die "CAV_ENROLL_TOKEN is required to enroll"
    fi

    arch=$(detect_arch)
    WORK=$(mktemp -d)

    ca_fp=$(printf '%s' "${CAV_CA_SHA256:-}" | tr -d ':' | tr 'A-F' 'a-f')
    if [ -n "$ca_fp" ]; then
        printf '%s' "$ca_fp" | grep -Eq '^[0-9a-f]{64}$' || die "--ca-sha256 must be a SHA-256 fingerprint (64 hex characters)"
        say "downloading the console CA and checking its fingerprint"
        fetch_console_ca "$base" "$ca_fp" "$WORK/console-ca.pem"
        CA=$WORK/console-ca.pem
    elif [ "$reinstall" != 1 ] && [ -f "$CA_FILE" ]; then
        # An upgrade keeps the trust set up at enrollment. A re-enrollment
        # follows the command it was given (a console may have moved to a
        # public certificate).
        CA=$CA_FILE
        say "using the console CA installed at $CA_FILE"
    fi

    bin="clamav-agent_linux_${arch}"
    say "downloading $bin from $base/downloads/"
    download "$base/downloads/$bin" "$WORK/$bin"
    download "$base/downloads/$bin.minisig" "$WORK/$bin.minisig"
    download "$base/downloads/clamav-agent.service" "$WORK/clamav-agent.service"
    download "$base/downloads/clamav-agent.service.minisig" "$WORK/clamav-agent.service.minisig"

    say "verifying minisign signatures"
    minisign_verify "$WORK/$bin" "$WORK/$bin.minisig" || die "signature verification failed for $bin; NOT installing"
    minisign_verify "$WORK/clamav-agent.service" "$WORK/clamav-agent.service.minisig" || die "signature verification failed for clamav-agent.service; NOT installing"

    ensure_user

    if [ "$clamav_setup" = 1 ] && [ -z "${CAV_CLAMD_ADDR:-}" ]; then
        setup_clamav
    fi

    if [ -n "${CAV_CLAMD_ADDR:-}" ]; then
        clamd_addr=$CAV_CLAMD_ADDR
        case "$clamd_addr" in unix://*) sock=${clamd_addr#unix://} ;; *) sock='' ;; esac
    else
        sock=$(detect_socket)
        if [ -n "$sock" ]; then
            clamd_addr="unix://$sock"
        else
            clamd_addr="unix:///run/clamav/clamd.ctl"
            echo "WARNING: no clamd socket found ($SOCKET_CANDIDATES); using $clamd_addr. Set CAV_CLAMD_ADDR if clamd lives elsewhere." >&2
        fi
    fi
    if [ -n "$sock" ] && [ -S "$sock" ]; then join_socket_group "$sock"; fi

    say "installing $BIN_DST"
    install -d -m 0755 -o root -g root /usr/local/bin
    install -m 0755 -o root -g root "$WORK/$bin" "$BIN_DST.new"
    mv -f "$BIN_DST.new" "$BIN_DST"

    install -d -m 0755 -o root -g root "$CONF_DIR"
    install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$STATE_DIR"

    ca_arg=''
    if [ -n "$CA" ]; then
        if [ "$CA" != "$CA_FILE" ]; then
            install -m 0644 -o root -g root "$CA" "$CA_FILE"
            say "installed the console CA at $CA_FILE"
        fi
        ca_arg="--ca-cert-file $CA_FILE"
    fi

    if [ "$need_enroll" = 1 ]; then
        say "enrolling with $base (clamd $clamd_addr)"
        replace=''
        if [ -f "$CRED_FILE" ]; then replace='--replace'; fi
        # The token is passed in the environment, never on the command line.
        # shellcheck disable=SC2086
        CAV_ENROLL_TOKEN="$CAV_ENROLL_TOKEN" "$BIN_DST" enroll --server "$base" --clamd "$clamd_addr" \
            --config "$CONF_FILE" --credential "$CRED_FILE" $replace $ca_arg || die "enrollment failed"
        if [ -z "$CA" ] && [ -f "$CA_FILE" ]; then
            rm -f "$CA_FILE"
            say "removed the console CA from an earlier enrollment (no longer used)"
        fi
    else
        say "already enrolled; keeping the existing credential (use --reinstall to re-enroll)"
        if [ -n "$CA" ] && ! grep -q '^ca_cert_file:' "$CONF_FILE" 2>/dev/null; then
            echo "WARNING: the existing enrollment does not use the console CA; run again with --reinstall and a new token." >&2
        fi
    fi
    unset CAV_ENROLL_TOKEN
    if [ "$scan_roots_set" = 1 ]; then apply_scan_roots "$CAV_SCAN_ROOTS"; fi

    chown root:root "$CONF_FILE"; chmod 0644 "$CONF_FILE"
    chown "$AGENT_USER:$AGENT_USER" "$STATE_DIR" "$CRED_FILE"
    chmod 0700 "$STATE_DIR"; chmod 0600 "$CRED_FILE"

    say "installing systemd unit"
    install -m 0644 -o root -g root "$WORK/clamav-agent.service" "$UNIT_DST"
    systemctl daemon-reload
    systemctl enable clamav-agent.service >/dev/null
    systemctl restart clamav-agent.service
    sleep 2
    if systemctl is-active --quiet clamav-agent.service; then
        say "the clamav-agent service is running"
    else
        echo "WARNING: the clamav-agent service is not running; see: journalctl -u clamav-agent" >&2
    fi
    final_check
}

usage() {
    # The header comment, without the leading "# ".
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

main() {
    if [ "${1:-}" = --verify-only ]; then
        [ $# -eq 3 ] || die "usage: install.sh --verify-only FILE SIGFILE"
        if minisign_verify "$2" "$3"; then echo "Signature OK"; exit 0; fi
        echo "Signature verification FAILED" >&2
        exit 1
    fi
    reinstall=0
    token_stdin=0
    clamav_setup=1
    if [ "${CAV_CLAMAV_SETUP:-1}" = 0 ]; then clamav_setup=0; fi
    scan_roots_set=0
    if [ -n "${CAV_SCAN_ROOTS+x}" ]; then scan_roots_set=1; fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --reinstall) reinstall=1 ;;
            --token-stdin) token_stdin=1 ;;
            --no-clamav-setup) clamav_setup=0 ;;
            --server|--ca-sha256|--clamd|--scan-roots)
                [ $# -ge 2 ] || die "$1 needs a value"
                case "$1" in
                    --server) CAV_SERVER_URL=$2 ;;
                    --ca-sha256) CAV_CA_SHA256=$2 ;;
                    --clamd) CAV_CLAMD_ADDR=$2 ;;
                    --scan-roots) CAV_SCAN_ROOTS=$2; scan_roots_set=1 ;;
                esac
                shift
                ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown argument $1 (see --help)" ;;
        esac
        shift
    done
    install_agent "$reinstall" "$token_stdin" "$clamav_setup"
}

main "$@"
