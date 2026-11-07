#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Telnet Enumeration Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

TELNET_MODULE="$PROJECT_ROOT/modules/network/services/telnet.sh"
readonly TELNET_MODULE

if [[ ! -f "$TELNET_MODULE" || ! -x "$TELNET_MODULE" ]]; then
    printf 'Error: Telnet module missing or not executable at %s\n' "$TELNET_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-telnet-test.XXXXXX")" || {
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

    printf '%s\n' "Telnet module unit tests completed."
}

printf '%s\n' "RECKON - Telnet Module Unit Tests"
printf '%s\n' "---------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$TELNET_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "telnet module rejects execution with insufficient arguments (< 3)"
else
    fail "telnet module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$TELNET_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "telnet module rejects empty target argument"
else
    fail "telnet module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$TELNET_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "telnet module rejects empty target type argument"
else
    fail "telnet module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$TELNET_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "telnet module rejects empty task directory argument"
else
    fail "telnet module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$TELNET_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "telnet module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "telnet module did not write expected failure notice for CIDR target"
    fi
else
    fail "telnet module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$TELNET_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "telnet module rejects multi-host IPv4 range target"
else
    fail "telnet module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http and url_https target types
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$TELNET_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "telnet module rejects url_http target type"
else
    fail "telnet module succeeded on incompatible url_http target"
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
    "$TELNET_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service interrogation tool: nmap" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "telnet module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "telnet module did not handle missing nmap tool properly (exit: $no_tool_exit)"
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
    if [[ "${MOCK_TELNET_MODE:-cleartext}" == "encrypted" ]]; then
        cat > "$out_path" <<'NMAP_ENC_EOF'
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
| telnet-encryption: 
|_  Telnet encryption option supported.
NMAP_ENC_EOF
    elif [[ "${MOCK_TELNET_MODE:-cleartext}" == "ntlm" ]]; then
        cat > "$out_path" <<'NMAP_NTLM_EOF'
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Microsoft Windows telnetd
|_telnet-encryption: Encryption not supported
| telnet-ntlm-info: 
|   Target_Name: CORP-NET
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Server_Name: DC-PRIMARY
|   DNS_Domain_Name: corp.internal.local
|_  DNS_Server_Name: dc-primary.corp.internal.local
NMAP_NTLM_EOF
    else
        cat > "$out_path" <<'NMAP_CLEARTEXT_EOF'
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
|_telnet-encryption: Encryption not supported
NMAP_CLEARTEXT_EOF
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
    printf '%s\n' "Debian GNU/Linux 11"
    printf '%s\n' "login: "
fi
exit 0
EOF
chmod +x "$MOCK_NC_BIN"

ARGS_LOG="$TEST_ROOT/telnet_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port & Service Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port & Service Integration"

# Test 9: Skips when upstream open_ports.txt reports 0 open ports
TARGET_ZERO="$TEST_ROOT/target_zero"
mkdir -p "$TARGET_ZERO/port" "$TARGET_ZERO/telnet"
: > "$TARGET_ZERO/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$TELNET_MODULE" "10.0.0.1" "ipv4" "$TARGET_ZERO/telnet" >/dev/null 2>&1
)
zero_exit=$?

if (( zero_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'telnet' (default port: 23) is not open" "$TARGET_ZERO/telnet/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$TARGET_ZERO/telnet/output.txt"; then
    pass "telnet module cleanly skips active interrogation when upstream open_ports.txt is empty"
else
    fail "telnet module did not handle empty upstream ports correctly (exit: $zero_exit)"
fi

# Test 10: Skips when open_ports.txt has other ports open but port 23 is closed
TARGET_NO_TELNET="$TEST_ROOT/target_no_telnet"
mkdir -p "$TARGET_NO_TELNET/port" "$TARGET_NO_TELNET/telnet"
printf "80\n443\n22\n" > "$TARGET_NO_TELNET/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$TELNET_MODULE" "10.0.0.2" "ipv4" "$TARGET_NO_TELNET/telnet" >/dev/null 2>&1
)
no_telnet_exit=$?

if (( no_telnet_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'telnet' (default port: 23) is not open" "$TARGET_NO_TELNET/telnet/output.txt"; then
    pass "telnet module skips scan when upstream open_ports.txt does not include port 23"
else
    fail "telnet module failed to skip when port 23 is not open (exit: $no_telnet_exit)"
fi

# Test 11: Resolves non-standard Telnet port (2323) from upstream services.txt
TARGET_ALT="$TEST_ROOT/target_alt"
mkdir -p "$TARGET_ALT/service" "$TARGET_ALT/telnet"
printf "2323/tcp\topen\ttelnet\tLinux telnetd\n" > "$TARGET_ALT/service/services.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$TELNET_MODULE" "10.0.0.3" "ipv4" "$TARGET_ALT/telnet" >/dev/null 2>&1
)
alt_exit=$?

if (( alt_exit == 0 )) && [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 2323" "$ARGS_LOG" && \
   grep -q "Port 2323: Telnet Service Interrogation" "$TARGET_ALT/telnet/output.txt"; then
    pass "telnet module discovers and targets non-standard port 2323 from upstream services.txt"
else
    fail "telnet module failed to target alternate Telnet port 2323 from services.txt (exit: $alt_exit)"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Override Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Override Fallback"

# Test 12: Standalone execution falls back to default port 23 when upstream artifacts missing
TARGET_STANDALONE="$TEST_ROOT/target_standalone"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$TELNET_MODULE" "10.0.0.4" "ipv4" "$TARGET_STANDALONE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 23" "$ARGS_LOG" && \
   grep -q "Port Resolution.*Canonical default port(s)" "$TARGET_STANDALONE/output.txt"; then
    pass "telnet module falls back to default port 23 in standalone execution mode"
else
    fail "telnet module standalone execution did not target default port 23"
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
    export CONFIG_EFFECTIVE_PORTS="2323,2324"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$TELNET_MODULE" "10.0.0.5" "ipv4" "$TARGET_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 2323" "$ARGS_LOG" && grep -q -- "-p 2324" "$ARGS_LOG"; then
    pass "telnet module iterates across multiple custom ports specified in CONFIG_EFFECTIVE_PORTS"
else
    fail "telnet module failed to honor CONFIG_EFFECTIVE_PORTS override"
fi

# -----------------------------------------------------------------------------
# UT-06: Banner Grabbing & Login Prompt Detection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Banner Grabbing & Login Prompt Detection"

# Test 14: Extracts banner and identifies interactive login prompt & OS hint
TARGET_BANNER_OK="$TEST_ROOT/target_banner_ok"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_BANNER_CUSTOM="Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)
User Access Verification
Username: "
    "$TELNET_MODULE" "router.local" "domain" "$TARGET_BANNER_OK" >/dev/null 2>&1
)
if [[ -f "$TARGET_BANNER_OK/telnet_banner.txt" ]] && \
   grep -q "Cisco IOS Software" "$TARGET_BANNER_OK/telnet_banner.txt" && \
   grep -q "Interactive login prompt detected." "$TARGET_BANNER_OK/output.txt" && \
   grep -q "Extracted System Hint.*Cisco" "$TARGET_BANNER_OK/output.txt"; then
    pass "telnet module captures welcome banner, detects login prompt, and extracts system hint"
else
    fail "telnet module failed to capture banner or detect login prompt"
fi

# -----------------------------------------------------------------------------
# UT-07: Protocol Security Evaluation & Cleartext Warnings
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Protocol Security Evaluation & Cleartext Warnings"

# Test 15: Flags cleartext protocol security risk when encryption is unsupported
TARGET_CLEARTEXT="$TEST_ROOT/target_cleartext"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_TELNET_MODE="cleartext"
    "$TELNET_MODULE" "10.0.0.6" "ipv4" "$TARGET_CLEARTEXT" >/dev/null 2>&1
)
if grep -q "Encryption Status.*Not Supported (Cleartext Transmission)" "$TARGET_CLEARTEXT/output.txt" && \
   grep -q "\[SECURITY RISK\] Cleartext Protocol" "$TARGET_CLEARTEXT/output.txt" && \
   grep -q "Telnet audit completed with 1 security finding(s)." "$TARGET_CLEARTEXT/output.txt"; then
    pass "telnet module identifies cleartext transmission risk and documents security risk notice"
else
    fail "telnet module failed to document cleartext protocol security risk"
fi

# Test 16: Recognizes negotiated encryption support
TARGET_ENC="$TEST_ROOT/target_enc"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_TELNET_MODE="encrypted"
    "$TELNET_MODULE" "10.0.0.7" "ipv4" "$TARGET_ENC" >/dev/null 2>&1
)
if grep -q "Encryption Status.*Supported (telnet-encryption option negotiated)" "$TARGET_ENC/output.txt" && \
   ! grep -q "\[SECURITY RISK\]" "$TARGET_ENC/output.txt"; then
    pass "telnet module identifies supported encryption option and suppresses cleartext warning"
else
    fail "telnet module failed to handle supported encryption status"
fi

# -----------------------------------------------------------------------------
# UT-08: NTLM Information Disclosure Detection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: NTLM Information Disclosure Detection"

# Test 17: Extracts NTLM domain and host names and records security notice
TARGET_NTLM="$TEST_ROOT/target_ntlm"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NC_BIN="$MOCK_NC_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_TELNET_MODE="ntlm"
    "$TELNET_MODULE" "10.0.0.8" "ipv4" "$TARGET_NTLM" >/dev/null 2>&1
)
if grep -q "NTLM Information Disclosure:" "$TARGET_NTLM/output.txt" && \
   grep -q "Target Domain.*CORP-NET" "$TARGET_NTLM/output.txt" && \
   grep -q "Server NetBIOS Name.*DC-PRIMARY" "$TARGET_NTLM/output.txt" && \
   grep -q "DNS Domain Name.*corp.internal.local" "$TARGET_NTLM/output.txt" && \
   grep -q "\[SECURITY NOTICE\] Internal infrastructure naming leaked via NTLM challenge." "$TARGET_NTLM/output.txt" && \
   grep -q "Telnet audit completed with 2 security finding(s)." "$TARGET_NTLM/output.txt"; then
    pass "telnet module parses NTLM challenge leakage and logs security notice with findings"
else
    fail "telnet module failed to detect NTLM information disclosure"
fi

# -----------------------------------------------------------------------------
# UT-09: Secure Permissions & Artifact Integrity
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Secure Permissions & Artifact Integrity"

# Test 18: All generated artifact files have 0640 permissions
non_compliant_perms=0
for f in "$TARGET_NTLM"/*; do
    if [[ -f "$f" ]]; then
        file_perm="$(stat -c '%a' "$f")"
        if [[ "$file_perm" != "640" ]]; then
            non_compliant_perms=$(( non_compliant_perms + 1 ))
        fi
    fi
done

if (( non_compliant_perms == 0 )); then
    pass "all telnet task artifacts enforce secure 0640 permissions"
else
    fail "found $non_compliant_perms file(s) without required 0640 permissions"
fi

# Test 19: Raw Nmap NSE artifact is preserved
if [[ -f "$TARGET_NTLM/nmap_telnet_23.nmap" ]]; then
    pass "preserves raw nmap_telnet_23.nmap execution output artifact"
else
    fail "raw nmap_telnet_23.nmap artifact not created"
fi

# Test 20: Raw banner artifact is preserved
if [[ -f "$TARGET_NTLM/telnet_banner.txt" ]]; then
    pass "preserves raw telnet_banner.txt artifact"
else
    fail "raw telnet_banner.txt artifact not created"
fi

test_summary
