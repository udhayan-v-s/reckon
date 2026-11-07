#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# SSH Enumeration Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

SSH_MODULE="$PROJECT_ROOT/modules/network/services/ssh.sh"
readonly SSH_MODULE

if [[ ! -f "$SSH_MODULE" || ! -x "$SSH_MODULE" ]]; then
    printf 'Error: SSH module missing or not executable at %s\n' "$SSH_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-ssh-test.XXXXXX")" || {
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

    printf '%s\n' "SSH module unit tests completed."
}

printf '%s\n' "RECKON - SSH Module Unit Tests"
printf '%s\n' "------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$SSH_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "ssh module rejects execution with insufficient arguments (< 3)"
else
    fail "ssh module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$SSH_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "ssh module rejects empty target argument"
else
    fail "ssh module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$SSH_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "ssh module rejects empty target type argument"
else
    fail "ssh module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$SSH_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "ssh module rejects empty task directory argument"
else
    fail "ssh module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$SSH_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "ssh module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "ssh module did not write expected failure notice for CIDR target"
    fi
else
    fail "ssh module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$SSH_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "ssh module rejects multi-host IPv4 range target"
else
    fail "ssh module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http and url_https target types
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$SSH_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "ssh module rejects url_http target type"
else
    fail "ssh module succeeded on incompatible url_http target"
fi

# -----------------------------------------------------------------------------
# UT-03: Dependency & Tool Availability
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Dependency & Tool Availability"

# Test 8: Reports failure when nmap is not available in PATH
TASK_DIR_NO_TOOL="$TEST_ROOT/no_tool"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="/nonexistent/bin/nmap_missing"
    "$SSH_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service interrogation tool: nmap" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "ssh module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "ssh module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mocks (Mock Nmap, Mock NC, Mock Keyscan)
# -----------------------------------------------------------------------------
MOCK_BIN_DIR="$TEST_ROOT/mock_bin"
mkdir -p "$MOCK_BIN_DIR"

MOCK_NMAP_BIN="$MOCK_BIN_DIR/mock_nmap.sh"
cat > "$MOCK_NMAP_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ -n "${MOCK_NMAP_ARGS_LOG:-}" ]]; then
    printf '%s\n' "$*" >> "$MOCK_NMAP_ARGS_LOG"
fi

out_path=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -oN) out_path="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_path" ]]; then
    if [[ "${MOCK_SSH_NSE_MODE:-standard}" == "weak" ]]; then
        cat > "$out_path" <<'NMAP_WEAK_EOF'
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (3)
|       diffie-hellman-group1-sha1
|       diffie-hellman-group-exchange-sha1
|       curve25519-sha256
|   server_host_key_algorithms: (2)
|       ssh-rsa
|       ssh-ed25519
|   encryption_algorithms: (3)
|       3des-cbc
|       arcfour
|       aes128-ctr
|   mac_algorithms: (2)
|       hmac-md5
|       hmac-sha1-96
| ssh-hostkey: 
|   2048 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 (RSA)
|   256 SHA256:abcd1234efgh5678ijkl (ED25519)
|_ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
NMAP_WEAK_EOF
    else
        cat > "$out_path" <<'NMAP_CLEAN_EOF'
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (2)
|       curve25519-sha256
|       ecdh-sha2-nistp256
|   server_host_key_algorithms: (2)
|       rsa-sha2-512
|       ssh-ed25519
|   encryption_algorithms: (2)
|       chacha20-poly1305@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (1)
|       umac-128-etm@openssh.com
| ssh-hostkey: 
|   3072 aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00 (RSA)
|   256 99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa (ECDSA)
|_ssh-auth-methods: 
|   Supported authentication methods: 
|_    publickey
NMAP_CLEAN_EOF
    fi
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_BIN"

MOCK_NC_BIN="$MOCK_BIN_DIR/mock_nc.sh"
cat > "$MOCK_NC_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ -n "${MOCK_BANNER_CUSTOM:-}" ]]; then
    printf '%s\n' "$MOCK_BANNER_CUSTOM"
else
    printf '%s\n' "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
fi
exit 0
EOF
chmod +x "$MOCK_NC_BIN"

MOCK_KEYSCAN_BIN="$MOCK_BIN_DIR/mock_keyscan.sh"
cat > "$MOCK_KEYSCAN_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

target="${*: -1}"
printf '# %s:22 SSH-2.0-OpenSSH_8.9p1\n' "$target"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleMockHostKeyED25519\n' "$target"
printf '%s ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQExampleMockHostKeyRSA\n' "$target"
exit 0
EOF
chmod +x "$MOCK_KEYSCAN_BIN"

ARGS_LOG="$TEST_ROOT/ssh_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port & Service Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port & Service Integration"

# Test 9: Skips when upstream open_ports.txt reports 0 open ports
TARGET_ZERO="$TEST_ROOT/target_zero"
mkdir -p "$TARGET_ZERO/port" "$TARGET_ZERO/ssh"
: > "$TARGET_ZERO/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SSH_MODULE" "10.0.0.1" "ipv4" "$TARGET_ZERO/ssh" >/dev/null 2>&1
)
zero_exit=$?

if (( zero_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'ssh' (default port: 22) is not open" "$TARGET_ZERO/ssh/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$TARGET_ZERO/ssh/output.txt"; then
    pass "ssh module cleanly skips active interrogation when upstream open_ports.txt is empty"
else
    fail "ssh module did not handle empty upstream ports correctly (exit: $zero_exit)"
fi

# Test 10: Skips when open_ports.txt has other ports open but port 22 is closed
TARGET_NO_SSH="$TEST_ROOT/target_no_ssh"
mkdir -p "$TARGET_NO_SSH/port" "$TARGET_NO_SSH/ssh"
printf "80\n443\n3306\n" > "$TARGET_NO_SSH/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SSH_MODULE" "10.0.0.2" "ipv4" "$TARGET_NO_SSH/ssh" >/dev/null 2>&1
)
no_ssh_exit=$?

if (( no_ssh_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "Notice: Port scan verified service 'ssh' (default port: 22) is not open." "$TARGET_NO_SSH/ssh/output.txt"; then
    pass "ssh module skips scan when upstream open_ports.txt does not include port 22"
else
    fail "ssh module failed to skip when port 22 is not open (exit: $no_ssh_exit)"
fi

# Test 11: Resolves non-standard SSH port (2222) from upstream services.txt
TARGET_ALT="$TEST_ROOT/target_alt"
mkdir -p "$TARGET_ALT/service" "$TARGET_ALT/ssh"
printf "2222/tcp\topen\tssh\tOpenSSH 8.9p1\n" > "$TARGET_ALT/service/services.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SSH_MODULE" "10.0.0.3" "ipv4" "$TARGET_ALT/ssh" >/dev/null 2>&1
)
alt_exit=$?

if (( alt_exit == 0 )) && [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 2222" "$ARGS_LOG" && \
   grep -q "Port 2222: SSH Service Interrogation" "$TARGET_ALT/ssh/output.txt"; then
    pass "ssh module discovers and targets non-standard port 2222 from upstream services.txt"
else
    fail "ssh module failed to target alternate SSH port 2222 from services.txt (exit: $alt_exit)"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Override Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Override Fallback"

# Test 12: Standalone execution falls back to default port 22 when upstream artifacts missing
TARGET_STANDALONE="$TEST_ROOT/target_standalone"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SSH_MODULE" "10.0.0.4" "ipv4" "$TARGET_STANDALONE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 22" "$ARGS_LOG" && \
   grep -q "Port Resolution.*Canonical default port(s)" "$TARGET_STANDALONE/output.txt"; then
    pass "ssh module falls back to default port 22 in standalone execution mode"
else
    fail "ssh module standalone execution did not target default port 22"
fi

# Test 13: Respects CONFIG_EFFECTIVE_PORTS CLI override
TARGET_OVERRIDE="$TEST_ROOT/target_override"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_BIN"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="2200,2222"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SSH_MODULE" "10.0.0.5" "ipv4" "$TARGET_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 2200" "$ARGS_LOG" && grep -q -- "-p 2222" "$ARGS_LOG"; then
    pass "ssh module iterates across multiple custom ports specified in CONFIG_EFFECTIVE_PORTS"
else
    fail "ssh module failed to honor CONFIG_EFFECTIVE_PORTS override"
fi

# -----------------------------------------------------------------------------
# UT-06: Banner Grabbing & Protocol Identification
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Banner Grabbing & Protocol Identification"

# Test 14: Extracts and parses modern SSH-2.0 banner
TARGET_BANNER_OK="$TEST_ROOT/target_banner_ok"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_BANNER_CUSTOM="SSH-2.0-OpenSSH_9.3p1 Debian-1"
    "$SSH_MODULE" "target.local" "domain" "$TARGET_BANNER_OK" >/dev/null 2>&1
)
if [[ -f "$TARGET_BANNER_OK/ssh_banner.txt" ]] && \
   grep -q "Port 22: SSH-2.0-OpenSSH_9.3p1 Debian-1" "$TARGET_BANNER_OK/ssh_banner.txt" && \
   grep -q "Protocol Version.*SSH-2.0" "$TARGET_BANNER_OK/output.txt" && \
   grep -q "Software Identity.*OpenSSH_9.3p1" "$TARGET_BANNER_OK/output.txt" && \
   grep -q "Reported Platform.*Debian-1" "$TARGET_BANNER_OK/output.txt"; then
    pass "ssh module parses protocol version, software name, and platform from banner"
else
    fail "ssh module failed to parse modern SSH banner correctly"
fi

# Test 15: Flags legacy SSH-1.99 / SSH-1.x protocol version
TARGET_BANNER_LEGACY="$TEST_ROOT/target_banner_legacy"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_BANNER_CUSTOM="SSH-1.99-OpenSSH_3.9p1"
    "$SSH_MODULE" "target.local" "domain" "$TARGET_BANNER_LEGACY" >/dev/null 2>&1
)
if grep -q "Legacy protocol version detected (SSH-1.99) - vulnerable to MITM" "$TARGET_BANNER_LEGACY/output.txt" && \
   grep -q "SSH audit completed with 1 security finding(s)." "$TARGET_BANNER_LEGACY/output.txt"; then
    pass "ssh module identifies legacy protocol version (SSH-1.99) and issues security warning"
else
    fail "ssh module failed to detect legacy SSH protocol version"
fi

# -----------------------------------------------------------------------------
# UT-07: Public Host Key Collection & Fingerprinting
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Public Host Key Collection & Fingerprinting"

# Test 16: Collects public keys via ssh-keyscan into ssh_host_keys.txt
if [[ -f "$TARGET_BANNER_OK/ssh_host_keys.txt" ]] && \
   grep -q "ssh-ed25519" "$TARGET_BANNER_OK/ssh_host_keys.txt" && \
   grep -q "ssh-rsa" "$TARGET_BANNER_OK/ssh_host_keys.txt"; then
    pass "ssh module saves extracted public host keys into ssh_host_keys.txt"
else
    fail "ssh module failed to generate ssh_host_keys.txt artifact"
fi

# Test 17: Parses Nmap ssh-hostkey fingerprints into output.txt
if grep -q "RSA (3072 bits):" "$TARGET_BANNER_OK/output.txt" && \
   grep -q "ECDSA (256 bits):" "$TARGET_BANNER_OK/output.txt"; then
    pass "ssh module parses RSA and ECDSA host key fingerprints into structured output"
else
    fail "ssh module failed to parse Nmap host key fingerprints"
fi

# -----------------------------------------------------------------------------
# UT-08: Cryptographic Auditing & Weak Algorithm Detection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Cryptographic Auditing & Weak Algorithm Detection"

# Test 18: Detects weak KEX, ciphers, and MACs from NSE script output
TARGET_AUDIT_WEAK="$TEST_ROOT/target_audit_weak"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_KEYSCAN_BIN="$MOCK_KEYSCAN_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_SSH_NSE_MODE="weak"
    "$SSH_MODULE" "target.local" "domain" "$TARGET_AUDIT_WEAK" >/dev/null 2>&1
)
weak_exit=$?

if (( weak_exit == 0 )) && [[ -f "$TARGET_AUDIT_WEAK/ssh_ciphers.txt" ]] && \
   grep -q "Port 22 KEX: diffie-hellman-group1-sha1" "$TARGET_AUDIT_WEAK/ssh_ciphers.txt" && \
   grep -q "Port 22 Ciphers: 3des-cbc" "$TARGET_AUDIT_WEAK/ssh_ciphers.txt" && \
   grep -q "Port 22 MACs: hmac-md5" "$TARGET_AUDIT_WEAK/ssh_ciphers.txt" && \
   grep -q "KEX: diffie-hellman-group1-sha1 (weak SHA-1 / small DH group)" "$TARGET_AUDIT_WEAK/output.txt" && \
   grep -q "Cipher: 3des-cbc (weak / CBC mode)" "$TARGET_AUDIT_WEAK/output.txt" && \
   grep -q "Cipher: arcfour (weak / CBC mode)" "$TARGET_AUDIT_WEAK/output.txt" && \
   grep -q "MAC: hmac-md5 (insecure MD5 / truncated 96-bit MAC)" "$TARGET_AUDIT_WEAK/output.txt" && \
   grep -q "MAC: hmac-sha1-96 (insecure MD5 / truncated 96-bit MAC)" "$TARGET_AUDIT_WEAK/output.txt" && \
   grep -q "SSH audit completed with 6 security finding(s)." "$TARGET_AUDIT_WEAK/output.txt"; then
    pass "ssh module identifies weak cryptographic algorithms and aggregates security warnings"
else
    fail "ssh module failed to detect weak cryptographic algorithms properly"
fi

# -----------------------------------------------------------------------------
# UT-09: Secure Permissions & Artifact Integrity
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Secure Permissions & Artifact Integrity"

# Test 19: All generated artifact files have 0640 permissions
non_compliant_perms=0
for f in "$TARGET_AUDIT_WEAK"/*; do
    if [[ -f "$f" ]]; then
        file_perm="$(stat -c '%a' "$f")"
        if [[ "$file_perm" != "640" ]]; then
            non_compliant_perms=$(( non_compliant_perms + 1 ))
        fi
    fi
done

if (( non_compliant_perms == 0 )); then
    pass "all ssh task artifacts enforce secure 0640 permissions"
else
    fail "found $non_compliant_perms file(s) without required 0640 permissions"
fi

# Test 20: Raw Nmap NSE artifact is preserved
if [[ -f "$TARGET_AUDIT_WEAK/nmap_ssh_22.nmap" ]]; then
    pass "preserves raw nmap_ssh_22.nmap execution output artifact"
else
    fail "raw nmap_ssh_22.nmap artifact not created"
fi

test_summary
