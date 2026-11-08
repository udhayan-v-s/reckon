#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Service Reconnaissance Pipeline Integration Tests (tests/integration/test_service_pipeline.sh)
#
# Verifies end-to-end orchestration of all service-specific enumeration modules:
#   - Remote Administration: ssh, telnet
#   - File Transfer & Shares: ftp, smb
#   - Web Infrastructure: http, https
#
# Validates upstream port propagation, zero-port skip optimizations, URL target
# compatibility pruning, heterogeneous multi-target batch execution, and audit logging.
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

RECKON_BIN="$PROJECT_ROOT/reckon"
readonly RECKON_BIN

if [[ ! -f "$RECKON_BIN" || ! -x "$RECKON_BIN" ]]; then
    printf 'Error: RECKON entry point missing or not executable at %s\n' "$RECKON_BIN" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-svcpipe-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

cleanup() {
    rm -rf -- "$TEST_ROOT"
}

trap cleanup EXIT

PASS_COUNT=0
FAIL_COUNT=0

pass() { printf '[PASS] %s\n' "$1"; ((PASS_COUNT += 1)); }
fail() { printf '[FAIL] %s\n' "$1" >&2; ((FAIL_COUNT += 1)); }

test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Service reconnaissance pipeline integration tests completed."
}

printf '%s\n' "RECKON - Service Pipeline Integration Tests"
printf '%s\n' "-------------------------------------------"

# -----------------------------------------------------------------------------
# Setup Shared Mock Infrastructure
# -----------------------------------------------------------------------------
MOCK_BIN_DIR="$TEST_ROOT/mock_bin"
mkdir -p "$MOCK_BIN_DIR"

MOCK_NMAP_SVC="$MOCK_BIN_DIR/mock_nmap.sh"
cat > "$MOCK_NMAP_SVC" <<'EOF'
#!/usr/bin/env bash
set -o nounset

out_nmap=""
out_gnmap=""
scripts=""
port=""
target=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -oN) out_nmap="$2"; shift 2 ;;
        -oG) out_gnmap="$2"; shift 2 ;;
        -p) port="$2"; shift 2 ;;
        --script) scripts="$2"; shift 2 ;;
        -*) shift ;;
        *) target="$1"; shift ;;
    esac
done

# If port discovery scan (-oG)
if [[ -n "$out_gnmap" ]]; then
    cat > "$out_gnmap" <<GNMAP_EOF
Host: ${target:-127.0.0.1} ()\tPorts: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//ssl|http///, 445/open/tcp//microsoft-ds///\tIgnored State: closed (995)
GNMAP_EOF
fi

if [[ -n "$out_nmap" ]]; then
    if [[ "$scripts" == *"ssh2-enum-algos"* ]]; then
        cat > "$out_nmap" <<SSH_EOF
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (2)
|       curve25519-sha256
|       diffie-hellman-group-exchange-sha256
|   server_host_key_algorithms: (2)
|       rsa-sha2-512
|       ssh-ed25519
|   encryption_algorithms: (2)
|       chacha20-poly1305@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (1)
|       umac-128-etm@openssh.com
| ssh-hostkey: 
|   3072 b6:a7:89:12:34:56:78:90:ab:cd:ef:01:23:45:67:89 (RSA)
|   256 12:34:56:78:90:ab:cd:ef:01:23:45:67:89:ab:cd:ef (ECDSA)
|_ssh-auth-methods: 
|   Supported authentication methods: 
|_    publickey
SSH_EOF
    elif [[ "$scripts" == *"ftp-anon"* ]]; then
        cat > "$out_nmap" <<FTP_EOF
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 0        0            2048 Nov 08 00:00 public_notes.txt
|_drwxr-xr-x   2 0        0            4096 Nov 08 00:00 downloads
| ftp-syst: 
|_  UNIX Type: L8
FTP_EOF
    elif [[ "$scripts" == *"smb-os-discovery"* ]]; then
        cat > "$out_nmap" <<SMB_EOF
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763
|   Computer name: DC-MAIN
|   Domain name: enterprise.local
|   FQDN: dc-main.enterprise.local
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-enum-shares: 
|   account_used: guest
|   \\target\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|   \\target\Public: 
|     Type: STYPE_DISKTREE
|     Comment: Public Repository
|_    Anonymous access: READ/WRITE
SMB_EOF
    elif [[ "$scripts" == *"http-methods"* ]]; then
        cat > "$out_nmap" <<HTTP_EOF
PORT   STATE SERVICE
${port:-80}/tcp open  http
| http-title: Enterprise Portal
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-server-header: nginx/1.22.0
HTTP_EOF
    elif [[ "$scripts" == *"ssl-enum-ciphers"* ]]; then
        cat > "$out_nmap" <<HTTPS_EOF
PORT    STATE SERVICE
${port:-443}/tcp open  ssl/https
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - grade: A
|     least strength: A
|   TLSv1.3: 
|     ciphers: 
|       TLS_AES_256_GCM_SHA384 - grade: A
|     least strength: A
|_  least strength: A
HTTPS_EOF
    else
        cat > "$out_nmap" <<SVC_DEFAULT_EOF
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsFTPd 3.0.3
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    nginx 1.22.0
443/tcp  open  ssl/http nginx 1.22.0
445/tcp  open  microsoft-ds Windows Server 2019
SVC_DEFAULT_EOF
    fi
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_SVC"

MOCK_NC_SVC="$MOCK_BIN_DIR/mock_nc.sh"
cat > "$MOCK_NC_SVC" <<'EOF'
#!/usr/bin/env bash
set -o nounset

port="${*: -1}"
if [[ "$port" == "21" ]]; then
    printf '%s\n' "220 (vsFTPd 3.0.3)"
elif [[ "$port" == "22" ]]; then
    printf '%s\n' "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
elif [[ "$port" == "23" ]]; then
    printf '%s\n' "Login: "
else
    printf '%s\n' "Ready"
fi
exit 0
EOF
chmod +x "$MOCK_NC_SVC"

MOCK_CURL_SVC="$MOCK_BIN_DIR/mock_curl.sh"
cat > "$MOCK_CURL_SVC" <<'EOF'
#!/usr/bin/env bash
set -o nounset

target_url="${*: -1}"
if [[ "$target_url" == https* ]]; then
    cat <<'CURL_HTTPS_EOF'
HTTP/1.1 200 OK
Server: nginx/1.22.0
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Type: text/html
CURL_HTTPS_EOF
else
    cat <<'CURL_HTTP_EOF'
HTTP/1.1 200 OK
Server: nginx/1.22.0
Content-Type: text/html
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
CURL_HTTP_EOF
fi
exit 0
EOF
chmod +x "$MOCK_CURL_SVC"

MOCK_OPENSSL_SVC="$MOCK_BIN_DIR/mock_openssl.sh"
cat > "$MOCK_OPENSSL_SVC" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ "${1:-}" == "s_client" ]]; then
    printf '%s\n' "-----BEGIN CERTIFICATE-----"
    printf '%s\n' "MII...MOCK_CERT_DATA..."
    printf '%s\n' "-----END CERTIFICATE-----"
    exit 0
elif [[ "${1:-}" == "x509" ]]; then
    cat <<'X509_EOF'
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Nov  1 00:00:00 2026 GMT
            Not After : Jan 30 00:00:00 2027 GMT
        Subject: CN = enterprise.local
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:enterprise.local, DNS:www.enterprise.local
X509_EOF
    exit 0
fi
exit 0
EOF
chmod +x "$MOCK_OPENSSL_SVC"

MOCK_KEYSCAN_SVC="$MOCK_BIN_DIR/mock_keyscan.sh"
cat > "$MOCK_KEYSCAN_SVC" <<'EOF'
#!/usr/bin/env bash
set -o nounset
target="${*: -1}"
printf '# %s:22 SSH-2.0-OpenSSH_8.9p1\n' "$target"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePipelineHostKey\n' "$target"
exit 0
EOF
chmod +x "$MOCK_KEYSCAN_SVC"

MOCK_SMBCLIENT_SVC="$MOCK_BIN_DIR/mock_smbclient.sh"
cat > "$MOCK_SMBCLIENT_SVC" <<'EOF'
#!/usr/bin/env bash
set -o nounset
cat <<'SMB_EOF'
	Sharename       Type      Comment
	---------       ----      -------
	IPC$            IPC       Remote IPC
	Public          Disk      Public Repository
SMB_EOF
exit 0
EOF
chmod +x "$MOCK_SMBCLIENT_SVC"

# -----------------------------------------------------------------------------
# Stage 1: Full Network Pipeline Execution (--network) with All 11 Modules
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Full Network Pipeline Execution (--network) with All 11 Modules"

OUT_DIR_NET="$TEST_ROOT/full_network_pipe"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_SVC"
    "$RECKON_BIN" --network --target "domain.local" --output "$OUT_DIR_NET" >/dev/null 2>&1
)
net_exit=$?

if (( net_exit == 0 )); then
    pass "full network pipeline executes successfully across domain target"
else
    fail "full network pipeline failed with exit code $net_exit"
fi

TARGET_NET_DIR="$OUT_DIR_NET/domain.local"
if [[ -d "$TARGET_NET_DIR/host" && \
      -d "$TARGET_NET_DIR/dns" && \
      -d "$TARGET_NET_DIR/port" && \
      -d "$TARGET_NET_DIR/service" && \
      -d "$TARGET_NET_DIR/os" && \
      -d "$TARGET_NET_DIR/ssh" && \
      -d "$TARGET_NET_DIR/ftp" && \
      -d "$TARGET_NET_DIR/http" && \
      -d "$TARGET_NET_DIR/https" && \
      -d "$TARGET_NET_DIR/smb" && \
      -d "$TARGET_NET_DIR/telnet" ]]; then
    pass "creates dedicated task directories for all 11 canonical network reconnaissance modules"
else
    fail "missing expected task directories among the 11 network modules under $TARGET_NET_DIR"
fi

# Verify every module generated output.txt and completed cleanly
all_completed=true
for m in host dns port service os ssh ftp http https smb telnet; do
    if [[ ! -f "$TARGET_NET_DIR/$m/output.txt" ]] || ! grep -q "Status: COMPLETED" "$TARGET_NET_DIR/$m/output.txt"; then
        all_completed=false
        break
    fi
done

if [[ "$all_completed" == true ]]; then
    pass "every network module generated output.txt and logged COMPLETED status"
else
    fail "one or more modules did not complete successfully or generate output.txt"
fi

# -----------------------------------------------------------------------------
# Stage 2: Multi-Service Interrogation Pipeline & Downstream Artifact Flow
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Multi-Service Interrogation Pipeline & Downstream Artifact Flow"

OUT_DIR_SERVICES="$TEST_ROOT/services_interrogation_pipe"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_SVC"
    "$RECKON_BIN" --module port,service,ssh,ftp,http,https,smb,telnet --target "enterprise.local" --output "$OUT_DIR_SERVICES" >/dev/null 2>&1
)
services_exit=$?

if (( services_exit == 0 )); then
    pass "service reconnaissance pipeline completes with exit code 0"
else
    fail "service reconnaissance pipeline failed with exit code $services_exit"
fi

ENT_DIR="$OUT_DIR_SERVICES/enterprise.local"

# Verify SSH artifacts
if [[ -f "$ENT_DIR/ssh/ssh_banner.txt" && -f "$ENT_DIR/ssh/ssh_host_keys.txt" && -f "$ENT_DIR/ssh/ssh_ciphers.txt" ]]; then
    pass "ssh module generates ssh_banner.txt, ssh_host_keys.txt, and ssh_ciphers.txt"
else
    fail "missing expected SSH artifacts"
fi

# Verify FTP artifacts
if [[ -f "$ENT_DIR/ftp/ftp_banner.txt" && -f "$ENT_DIR/ftp/ftp_anon.txt" ]] && \
   grep -q "Anonymous login permitted" "$ENT_DIR/ftp/ftp_anon.txt"; then
    pass "ftp module generates ftp_banner.txt and logs anonymous access in ftp_anon.txt"
else
    fail "missing expected FTP artifacts"
fi

# Verify HTTP artifacts
if [[ -f "$ENT_DIR/http/http_headers.txt" && -f "$ENT_DIR/http/http_methods.txt" ]] && \
   grep -q "Allowed Methods" "$ENT_DIR/http/http_methods.txt"; then
    pass "http module generates http_headers.txt and http_methods.txt"
else
    fail "missing expected HTTP artifacts"
fi

# Verify HTTPS artifacts
if [[ -f "$ENT_DIR/https/https_cert.txt" && -f "$ENT_DIR/https/https_tls.txt" && -f "$ENT_DIR/https/https_headers.txt" ]]; then
    pass "https module generates https_cert.txt, https_tls.txt, and https_headers.txt"
else
    fail "missing expected HTTPS artifacts"
fi

# Verify SMB artifacts
if [[ -f "$ENT_DIR/smb/smb_os.txt" && -f "$ENT_DIR/smb/smb_shares.txt" && -f "$ENT_DIR/smb/smb_security.txt" ]] && \
   grep -q "enterprise.local" "$ENT_DIR/smb/smb_os.txt"; then
    pass "smb module generates smb_os.txt, smb_shares.txt, and smb_security.txt"
else
    fail "missing expected SMB artifacts"
fi

# Verify Telnet skip optimization (port 23 was not among open ports 21, 22, 80, 443, 445)
if [[ -f "$ENT_DIR/telnet/output.txt" ]] && \
   grep -q "verified service 'telnet'.*is not open" "$ENT_DIR/telnet/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$ENT_DIR/telnet/output.txt"; then
    pass "telnet module detects port 23 closed from upstream discovery and skips interrogation"
else
    fail "telnet module did not execute skip optimization as expected"
fi

# -----------------------------------------------------------------------------
# Stage 3: Upstream Zero-Port Skip Optimization across All Service Modules
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Upstream Zero-Port Skip Optimization across All Service Modules"

# Setup target with empty open_ports.txt (0 open ports)
ZERO_TARGET_DIR="$TEST_ROOT/zero_target/filtered.local"
mkdir -p "$ZERO_TARGET_DIR/port"
: > "$ZERO_TARGET_DIR/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SVC"
    "$RECKON_BIN" --module ssh,telnet,ftp,smb,http,https --target "filtered.local" --output "$TEST_ROOT/zero_target" >/dev/null 2>&1
)
zero_exit=$?

all_skipped=true
for sm in ssh telnet ftp smb http https; do
    if [[ ! -f "$ZERO_TARGET_DIR/$sm/output.txt" ]] || \
       ! grep -q "COMPLETED | Service not active on target." "$ZERO_TARGET_DIR/$sm/output.txt"; then
        all_skipped=false
        break
    fi
done

if (( zero_exit == 0 )) && [[ "$all_skipped" == true ]]; then
    pass "all 6 service modules cleanly skip active interrogation when 0 open ports are found"
else
    fail "one or more service modules failed to skip when upstream ports were closed"
fi

# -----------------------------------------------------------------------------
# Stage 4: URL Target Compatibility Pruning & Path Propagation
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: URL Target Compatibility Pruning & Path Propagation"

OUT_DIR_URL="$TEST_ROOT/url_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_SVC"
    "$RECKON_BIN" --module ssh,ftp,http,https,smb,telnet --target "http://web.corp.local:8080/dashboard" --output "$OUT_DIR_URL" >/dev/null 2>&1
)
url_exit=$?

if (( url_exit == 0 )); then
    pass "URL pipeline execution succeeds with exit code 0"
else
    fail "URL pipeline execution failed with exit code $url_exit"
fi

URL_TARGET_DIR="$OUT_DIR_URL/http_web.corp.local_8080_dashboard"
if [[ -d "$URL_TARGET_DIR/http" && -d "$URL_TARGET_DIR/https" && \
      ! -d "$URL_TARGET_DIR/ssh" && ! -d "$URL_TARGET_DIR/ftp" && \
      ! -d "$URL_TARGET_DIR/smb" && ! -d "$URL_TARGET_DIR/telnet" ]]; then
    pass "planner schedules http/https and prunes incompatible non-web service modules for URL target"
else
    fail "incompatible service modules were scheduled or web modules missing for URL target"
fi

# -----------------------------------------------------------------------------
# Stage 5: Multi-Target File Execution with Heterogeneous Target Types
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Multi-Target File Execution with Heterogeneous Target Types"

TARGETS_FILE="$TEST_ROOT/batch_targets.txt"
cat > "$TARGETS_FILE" <<'EOF'
# Enterprise Target Batch
server.local
192.168.1.50
10.0.0.0/24
http://api.local:8080/v1
EOF

OUT_DIR_BATCH="$TEST_ROOT/batch_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_SVC"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_SVC"
    "$RECKON_BIN" --targets-file "$TARGETS_FILE" --module host,port,ssh,http --output "$OUT_DIR_BATCH" >/dev/null 2>&1
)
batch_exit=$?

if (( batch_exit == 0 )); then
    pass "multi-target batch scan across mixed target types completes with exit code 0"
else
    fail "multi-target batch scan failed with exit code $batch_exit"
fi

# Verify selective scheduling per target type
if [[ -d "$OUT_DIR_BATCH/server.local/ssh" && \
      -d "$OUT_DIR_BATCH/192.168.1.50/ssh" && \
      -d "$OUT_DIR_BATCH/http_api.local_8080_v1/http" && \
      ! -d "$OUT_DIR_BATCH/http_api.local_8080_v1/ssh" && \
      -d "$OUT_DIR_BATCH/10.0.0.0_24/host" && \
      ! -d "$OUT_DIR_BATCH/10.0.0.0_24/ssh" ]]; then
    pass "selectively schedules compatible modules per target type across batch execution"
else
    fail "module scheduling per target type in batch execution was incorrect"
fi

# -----------------------------------------------------------------------------
# Stage 6: Centralized Audit Logging Verification
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Centralized Audit Logging Verification"

LOG_FILE="$TEST_ROOT/audit_service.log"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SVC"
    "$RECKON_BIN" --module ssh,http --target "logbox.local" --log-file "$LOG_FILE" --output "$TEST_ROOT/logbox_out" >/dev/null 2>&1
)

if [[ -f "$LOG_FILE" ]] && \
   grep -q "Executing .* ssh" "$LOG_FILE" && \
   grep -q "Executing .* http" "$LOG_FILE" && \
   grep -q "Module 'ssh' completed" "$LOG_FILE" && \
   grep -q "Module 'http' completed" "$LOG_FILE" && \
   grep -q "Scan execution finished" "$LOG_FILE"; then
    pass "audit log comprehensively records dispatch and completion for service modules"
else
    fail "audit log entries for service module execution missing or incomplete"
fi

# -----------------------------------------------------------------------------
# Stage 7: Secure Permission Verification across Generated Artifacts
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Secure Permission Verification across Generated Artifacts"

invalid_task_dirs=0
invalid_artifacts=0

for sm in ssh telnet ftp smb http https; do
    s_dir="$ENT_DIR/$sm"
    if [[ -d "$s_dir" ]]; then
        d_perm="$(stat -c '%a' "$s_dir")"
        if [[ "$d_perm" != "750" && "$d_perm" != "700" ]]; then
            invalid_task_dirs=$(( invalid_task_dirs + 1 ))
        fi
        if [[ -f "$s_dir/output.txt" ]]; then
            f_perm="$(stat -c '%a' "$s_dir/output.txt")"
            if [[ "$f_perm" != "640" ]]; then
                invalid_artifacts=$(( invalid_artifacts + 1 ))
            fi
        fi
    fi
done

if (( invalid_task_dirs == 0 && invalid_artifacts == 0 )); then
    pass "enforces 0750 directory and 0640 file permissions across all service task directories"
else
    fail "permission compliance failure: $invalid_artifacts invalid artifact(s), $invalid_task_dirs invalid dir(s)"
fi

test_summary
