#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# FTP Enumeration Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

FTP_MODULE="$PROJECT_ROOT/modules/network/services/ftp.sh"
readonly FTP_MODULE

if [[ ! -f "$FTP_MODULE" || ! -x "$FTP_MODULE" ]]; then
    printf 'Error: FTP module missing or not executable at %s\n' "$FTP_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-ftp-test.XXXXXX")" || {
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

    printf '%s\n' "FTP module unit tests completed."
}

printf '%s\n' "RECKON - FTP Module Unit Tests"
printf '%s\n' "------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$FTP_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "ftp module rejects execution with insufficient arguments (< 3)"
else
    fail "ftp module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$FTP_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "ftp module rejects empty target argument"
else
    fail "ftp module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$FTP_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "ftp module rejects empty target type argument"
else
    fail "ftp module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$FTP_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "ftp module rejects empty task directory argument"
else
    fail "ftp module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$FTP_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "ftp module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "ftp module did not write expected failure notice for CIDR target"
    fi
else
    fail "ftp module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$FTP_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "ftp module rejects multi-host IPv4 range target"
else
    fail "ftp module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http and url_https target types
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$FTP_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "ftp module rejects url_http target type"
else
    fail "ftp module succeeded on incompatible url_http target"
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
    "$FTP_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service interrogation tool: nmap" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "ftp module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "ftp module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mocks (Mock Nmap, Mock NC)
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
    if [[ "${MOCK_FTP_MODE:-anon_allowed}" == "anon_allowed" ]]; then
        cat > "$out_path" <<'NMAP_ANON_EOF'
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 0        0            2048 Nov 07 10:00 secret_backup.tar.gz
|_drwxr-xr-x   2 0        0            4096 Nov 07 10:05 public
| ftp-syst: 
|_  UNIX Type: L8
NMAP_ANON_EOF
    elif [[ "${MOCK_FTP_MODE:-}" == "bounce_vuln" ]]; then
        cat > "$out_path" <<'NMAP_BOUNCE_EOF'
PORT   STATE SERVICE
21/tcp open  ftp
|_ftp-anon: Anonymous login forbidden
| ftp-syst: 
|_  UNIX Type: L8
|_ftp-bounce: bounce working!
NMAP_BOUNCE_EOF
    else
        cat > "$out_path" <<'NMAP_SECURE_EOF'
PORT   STATE SERVICE
21/tcp open  ftp
|_ftp-anon: Anonymous login forbidden
| ftp-syst: 
|_  UNIX Type: L8
NMAP_SECURE_EOF
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
    printf '%s\n' "220 (vsFTPd 3.0.3)"
fi
exit 0
EOF
chmod +x "$MOCK_NC_BIN"

ARGS_LOG="$TEST_ROOT/ftp_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port & Service Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port & Service Integration"

# Test 9: Skips when upstream open_ports.txt reports 0 open ports
TARGET_ZERO="$TEST_ROOT/target_zero"
mkdir -p "$TARGET_ZERO/port" "$TARGET_ZERO/ftp"
: > "$TARGET_ZERO/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$FTP_MODULE" "10.0.0.1" "ipv4" "$TARGET_ZERO/ftp" >/dev/null 2>&1
)
zero_exit=$?

if (( zero_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'ftp' (default port: 21) is not open" "$TARGET_ZERO/ftp/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$TARGET_ZERO/ftp/output.txt"; then
    pass "ftp module cleanly skips active interrogation when upstream open_ports.txt is empty"
else
    fail "ftp module did not handle empty upstream ports correctly (exit: $zero_exit)"
fi

# Test 10: Skips when open_ports.txt has other ports open but port 21 is closed
TARGET_NO_FTP="$TEST_ROOT/target_no_ftp"
mkdir -p "$TARGET_NO_FTP/port" "$TARGET_NO_FTP/ftp"
printf "80\n443\n22\n" > "$TARGET_NO_FTP/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$FTP_MODULE" "10.0.0.2" "ipv4" "$TARGET_NO_FTP/ftp" >/dev/null 2>&1
)
no_ftp_exit=$?

if (( no_ftp_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'ftp' (default port: 21) is not open" "$TARGET_NO_FTP/ftp/output.txt"; then
    pass "ftp module skips scan when upstream open_ports.txt does not include port 21"
else
    fail "ftp module failed to skip when port 21 is not open (exit: $no_ftp_exit)"
fi

# Test 11: Resolves non-standard FTP port (2121) from upstream services.txt
TARGET_ALT="$TEST_ROOT/target_alt"
mkdir -p "$TARGET_ALT/service" "$TARGET_ALT/ftp"
printf "2121/tcp\topen\tftp\tProFTPD 1.3.5\n" > "$TARGET_ALT/service/services.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$FTP_MODULE" "10.0.0.3" "ipv4" "$TARGET_ALT/ftp" >/dev/null 2>&1
)
alt_exit=$?

if (( alt_exit == 0 )) && [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 2121" "$ARGS_LOG" && \
   grep -q "Port 2121: FTP Service Interrogation" "$TARGET_ALT/ftp/output.txt"; then
    pass "ftp module discovers and targets non-standard port 2121 from upstream services.txt"
else
    fail "ftp module failed to target alternate FTP port 2121 from services.txt (exit: $alt_exit)"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Override Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Override Fallback"

# Test 12: Standalone execution falls back to default port 21 when upstream artifacts missing
TARGET_STANDALONE="$TEST_ROOT/target_standalone"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$FTP_MODULE" "10.0.0.4" "ipv4" "$TARGET_STANDALONE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 21" "$ARGS_LOG" && \
   grep -q "Port Resolution.*Canonical default port(s)" "$TARGET_STANDALONE/output.txt"; then
    pass "ftp module falls back to default port 21 in standalone execution mode"
else
    fail "ftp module standalone execution did not target default port 21"
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
    export CONFIG_EFFECTIVE_PORTS="2121,2122"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$FTP_MODULE" "10.0.0.5" "ipv4" "$TARGET_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 2121" "$ARGS_LOG" && grep -q -- "-p 2122" "$ARGS_LOG"; then
    pass "ftp module iterates across multiple custom ports specified in CONFIG_EFFECTIVE_PORTS"
else
    fail "ftp module failed to honor CONFIG_EFFECTIVE_PORTS override"
fi

# -----------------------------------------------------------------------------
# UT-06: Banner Grabbing & Daemon Identification
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Banner Grabbing & Daemon Identification"

# Test 14: Extracts banner and identifies FTP server software
TARGET_BANNER_OK="$TEST_ROOT/target_banner_ok"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_BANNER_CUSTOM="220 ProFTPD 1.3.5 Server (Debian)"
    "$FTP_MODULE" "ftp.local" "domain" "$TARGET_BANNER_OK" >/dev/null 2>&1
)
if [[ -f "$TARGET_BANNER_OK/ftp_banner.txt" ]] && \
   grep -q "220 ProFTPD 1.3.5 Server" "$TARGET_BANNER_OK/ftp_banner.txt" && \
   grep -q "Software Identity.*ProFTPD 1.3.5" "$TARGET_BANNER_OK/output.txt"; then
    pass "ftp module captures welcome banner and extracts server software identity"
else
    fail "ftp module failed to parse FTP banner correctly"
fi

# -----------------------------------------------------------------------------
# UT-07: Anonymous FTP Access Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Anonymous FTP Access Auditing"

# Test 15: Detects permitted anonymous login and extracts directory listing
TARGET_ANON_PERMITTED="$TEST_ROOT/target_anon_permitted"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_FTP_MODE="anon_allowed"
    "$FTP_MODULE" "ftp.local" "domain" "$TARGET_ANON_PERMITTED" >/dev/null 2>&1
)
if [[ -f "$TARGET_ANON_PERMITTED/ftp_anon.txt" ]] && \
   grep -q "Anonymous login permitted" "$TARGET_ANON_PERMITTED/ftp_anon.txt" && \
   grep -q "secret_backup.tar.gz" "$TARGET_ANON_PERMITTED/ftp_anon.txt" && \
   grep -q "public" "$TARGET_ANON_PERMITTED/ftp_anon.txt" && \
   grep -q "\[SECURITY WARN\] Anonymous FTP Login Permitted" "$TARGET_ANON_PERMITTED/output.txt" && \
   grep -q "FTP audit completed with 1 security finding(s)." "$TARGET_ANON_PERMITTED/output.txt"; then
    pass "ftp module detects anonymous login permission, extracts files, and issues security warning"
else
    fail "ftp module failed to document anonymous FTP access findings"
fi

# Test 16: Recognizes disabled anonymous FTP login
TARGET_ANON_DISABLED="$TEST_ROOT/target_anon_disabled"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_FTP_MODE="secure"
    "$FTP_MODULE" "ftp.local" "domain" "$TARGET_ANON_DISABLED" >/dev/null 2>&1
)
if grep -q "Authentication Status.*Disabled / Authentication Required" "$TARGET_ANON_DISABLED/output.txt" && \
   ! grep -q "\[SECURITY WARN\]" "$TARGET_ANON_DISABLED/output.txt" && \
   grep -q "FTP audit completed. No insecure configuration identified." "$TARGET_ANON_DISABLED/output.txt"; then
    pass "ftp module verifies disabled anonymous login and reports clean status"
else
    fail "ftp module failed to handle disabled anonymous FTP status"
fi

# -----------------------------------------------------------------------------
# UT-08: FTP Bounce Attack Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: FTP Bounce Attack Auditing"

# Test 17: Detects vulnerable FTP bounce status
TARGET_BOUNCE="$TEST_ROOT/target_bounce"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_FTP_MODE="bounce_vuln"
    "$FTP_MODULE" "ftp.local" "domain" "$TARGET_BOUNCE" >/dev/null 2>&1
)
if grep -q "Bounce State.*Vulnerable" "$TARGET_BOUNCE/output.txt" && \
   grep -q "\[SECURITY WARN\] FTP Bounce Attack Supported" "$TARGET_BOUNCE/output.txt" && \
   grep -q "FTP audit completed with 1 security finding(s)." "$TARGET_BOUNCE/output.txt"; then
    pass "ftp module detects vulnerable bounce attack capability and issues security warning"
else
    fail "ftp module failed to detect FTP bounce vulnerability"
fi

# -----------------------------------------------------------------------------
# UT-09: Secure Permissions & Artifact Integrity
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Secure Permissions & Artifact Integrity"

# Test 18: All generated artifact files have 0640 permissions
non_compliant_perms=0
for f in "$TARGET_ANON_PERMITTED"/*; do
    if [[ -f "$f" ]]; then
        file_perm="$(stat -c '%a' "$f")"
        if [[ "$file_perm" != "640" ]]; then
            non_compliant_perms=$(( non_compliant_perms + 1 ))
        fi
    fi
done

if (( non_compliant_perms == 0 )); then
    pass "all ftp task artifacts enforce secure 0640 permissions"
else
    fail "found $non_compliant_perms file(s) without required 0640 permissions"
fi

# Test 19: Raw Nmap NSE artifact is preserved
if [[ -f "$TARGET_ANON_PERMITTED/nmap_ftp_21.nmap" ]]; then
    pass "preserves raw nmap_ftp_21.nmap execution output artifact"
else
    fail "raw nmap_ftp_21.nmap artifact not created"
fi

# Test 20: Raw banner artifact is preserved
if [[ -f "$TARGET_ANON_PERMITTED/ftp_banner.txt" ]]; then
    pass "preserves raw ftp_banner.txt artifact"
else
    fail "raw ftp_banner.txt artifact not created"
fi

test_summary
