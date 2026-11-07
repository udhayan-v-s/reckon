#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# SMB Enumeration Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

SMB_MODULE="$PROJECT_ROOT/modules/network/services/smb.sh"
readonly SMB_MODULE

if [[ ! -f "$SMB_MODULE" || ! -x "$SMB_MODULE" ]]; then
    printf 'Error: SMB module missing or not executable at %s\n' "$SMB_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-smb-test.XXXXXX")" || {
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

    printf '%s\n' "SMB module unit tests completed."
}

printf '%s\n' "RECKON - SMB Module Unit Tests"
printf '%s\n' "------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$SMB_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "smb module rejects execution with insufficient arguments (< 3)"
else
    fail "smb module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$SMB_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "smb module rejects empty target argument"
else
    fail "smb module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$SMB_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "smb module rejects empty target type argument"
else
    fail "smb module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$SMB_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "smb module rejects empty task directory argument"
else
    fail "smb module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$SMB_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "smb module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "smb module did not write expected failure notice for CIDR target"
    fi
else
    fail "smb module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$SMB_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "smb module rejects multi-host IPv4 range target"
else
    fail "smb module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http and url_https target types
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$SMB_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "smb module rejects url_http target type"
else
    fail "smb module succeeded on incompatible url_http target"
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
    "$SMB_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service interrogation tool: nmap" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "smb module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "smb module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mocks (Mock Nmap, Mock smbclient)
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
    if [[ "${MOCK_SMB_MODE:-vulnerable}" == "vulnerable" ]]; then
        cat > "$out_path" <<'NMAP_SMB_VULN_EOF'
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2019
|   Computer name: DC-PRIMARY
|   NetBIOS computer name: DC-PRIMARY\x00
|   Domain name: corp.internal
|   Forest name: corp.internal
|   FQDN: dc-primary.corp.internal
|_  System time: 2026-11-07T18:00:00+00:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-enum-shares: 
|   account_used: guest
|   \\10.0.0.1\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|   \\10.0.0.1\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|   \\10.0.0.1\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|   \\10.0.0.1\Public: 
|     Type: STYPE_DISKTREE
|     Comment: Public File Share
|_    Anonymous access: READ/WRITE
NMAP_SMB_VULN_EOF
    else
        cat > "$out_path" <<'NMAP_SMB_HARDENED_EOF'
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-os-discovery: 
|   OS: Windows Server 2022 Datacenter 20348
|   Computer name: SEC-FILE-01
|   NetBIOS computer name: SEC-FILE-01\x00
|   Domain name: corp.internal
|   FQDN: sec-file-01.corp.internal
|_  System time: 2026-11-07T18:00:00+00:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing required
| smb-enum-shares: 
|   account_used: guest
|   \\10.0.0.2\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|   \\10.0.0.2\Confidential$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Strictly confidential
|_    Anonymous access: <none>
NMAP_SMB_HARDENED_EOF
    fi
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_BIN"

MOCK_SMBCLIENT_BIN="$MOCK_BIN_DIR/mock_smbclient.sh"
cat > "$MOCK_SMBCLIENT_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ -n "${MOCK_SMBCLIENT_ARGS_LOG:-}" ]]; then
    printf '%s\n' "$*" >> "$MOCK_SMBCLIENT_ARGS_LOG"
fi

if [[ "${MOCK_SMBCLIENT_MODE:-supp}" == "supp" ]]; then
    cat <<'SMBCLIENT_EOF'
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Public          Disk      Public File Share
	Backups         Disk      Internal Automated Backups
SMBCLIENT_EOF
fi

exit 0
EOF
chmod +x "$MOCK_SMBCLIENT_BIN"

ARGS_LOG="$TEST_ROOT/smb_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port & Service Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port & Service Integration"

# Test 9: Skips when upstream open_ports.txt reports 0 open ports
TARGET_ZERO="$TEST_ROOT/target_zero"
mkdir -p "$TARGET_ZERO/port" "$TARGET_ZERO/smb"
: > "$TARGET_ZERO/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SMB_MODULE" "10.0.0.1" "ipv4" "$TARGET_ZERO/smb" >/dev/null 2>&1
)
zero_exit=$?

if (( zero_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'smb'.*is not open" "$TARGET_ZERO/smb/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$TARGET_ZERO/smb/output.txt"; then
    pass "smb module cleanly skips active interrogation when upstream open_ports.txt is empty"
else
    fail "smb module did not handle empty upstream ports correctly (exit: $zero_exit)"
fi

# Test 10: Skips when open_ports.txt has other ports open but 445/139 are closed
TARGET_NO_SMB="$TEST_ROOT/target_no_smb"
mkdir -p "$TARGET_NO_SMB/port" "$TARGET_NO_SMB/smb"
printf "80\n443\n22\n" > "$TARGET_NO_SMB/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SMB_MODULE" "10.0.0.2" "ipv4" "$TARGET_NO_SMB/smb" >/dev/null 2>&1
)
no_smb_exit=$?

if (( no_smb_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'smb'.*is not open" "$TARGET_NO_SMB/smb/output.txt"; then
    pass "smb module skips scan when upstream open_ports.txt does not include SMB ports"
else
    fail "smb module failed to skip when SMB ports are closed (exit: $no_smb_exit)"
fi

# Test 11: Resolves default port 445 when present in open_ports.txt
TARGET_PORT_445="$TEST_ROOT/target_port_445"
mkdir -p "$TARGET_PORT_445/port" "$TARGET_PORT_445/smb"
printf "445\n" > "$TARGET_PORT_445/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SMB_MODULE" "10.0.0.3" "ipv4" "$TARGET_PORT_445/smb" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 445" "$ARGS_LOG" && \
   grep -q "Target Ports.*445" "$TARGET_PORT_445/smb/output.txt"; then
    pass "smb module targets port 445 resolved from upstream open_ports.txt"
else
    fail "smb module failed to target port 445 from open_ports.txt"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Override Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Override Fallback"

# Test 12: Standalone execution falls back to default ports 445,139 when upstream artifacts missing
TARGET_STANDALONE="$TEST_ROOT/target_standalone"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SMB_MODULE" "10.0.0.4" "ipv4" "$TARGET_STANDALONE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 445" "$ARGS_LOG" && grep -q -- "-p 139" "$ARGS_LOG" && \
   grep -q "Port Resolution.*Canonical default port(s)" "$TARGET_STANDALONE/output.txt"; then
    pass "smb module falls back to default ports 445 and 139 in standalone execution mode"
else
    fail "smb module standalone execution did not target default ports"
fi

# Test 13: Respects CONFIG_EFFECTIVE_PORTS CLI override
TARGET_OVERRIDE="$TEST_ROOT/target_override"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_BIN"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="4455"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SMB_MODULE" "10.0.0.5" "ipv4" "$TARGET_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 4455" "$ARGS_LOG"; then
    pass "smb module respects custom port specified in CONFIG_EFFECTIVE_PORTS"
else
    fail "smb module failed to honor CONFIG_EFFECTIVE_PORTS override"
fi

# -----------------------------------------------------------------------------
# UT-06: Infrastructure & Operating System Identification
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Infrastructure & Operating System Identification"

# Test 14: Extracts OS, computer name, domain, and system time
TARGET_VULN="$TEST_ROOT/target_vuln"
mkdir -p "$TARGET_VULN/port" "$TARGET_VULN/smb"
printf "445\n" > "$TARGET_VULN/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_SMB_MODE="vulnerable"
    "$SMB_MODULE" "dc-primary.corp.internal" "domain" "$TARGET_VULN/smb" >/dev/null 2>&1
)
if [[ -f "$TARGET_VULN/smb/smb_os.txt" ]] && \
   grep -q "OS: Windows Server 2019 Standard" "$TARGET_VULN/smb/smb_os.txt" && \
   grep -q "Computer Name: DC-PRIMARY" "$TARGET_VULN/smb/smb_os.txt" && \
   grep -q "Domain/Workgroup: corp.internal" "$TARGET_VULN/smb/smb_os.txt" && \
   grep -q "OS Version.*Windows Server 2019" "$TARGET_VULN/smb/output.txt" && \
   grep -q "FQDN.*dc-primary.corp.internal" "$TARGET_VULN/smb/output.txt"; then
    pass "smb module extracts OS, NetBIOS computer name, domain, and FQDN into smb_os.txt"
else
    fail "smb module failed to extract OS and infrastructure metadata"
fi

# -----------------------------------------------------------------------------
# UT-07: SMB Message Signing Security Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: SMB Message Signing Security Auditing"

# Test 15: Flags signing not required as a security warning
if [[ -f "$TARGET_VULN/smb/smb_security.txt" ]] && \
   grep -q "Signing: Not Required / Disabled" "$TARGET_VULN/smb/smb_security.txt" && \
   grep -q "Message Signing.*Not Required / Disabled" "$TARGET_VULN/smb/output.txt" && \
   grep -q "\[SECURITY WARN\] SMB Signing Not Required: System is vulnerable to SMB relay" "$TARGET_VULN/smb/output.txt"; then
    pass "smb module detects unforced SMB signing and issues relay vulnerability warning"
else
    fail "smb module failed to identify unforced SMB message signing vulnerability"
fi

# Test 16: Recognizes enforced / required message signing
TARGET_HARDENED="$TEST_ROOT/target_hardened"
mkdir -p "$TARGET_HARDENED/port" "$TARGET_HARDENED/smb"
printf "445\n" > "$TARGET_HARDENED/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SMBCLIENT_BIN="$MOCK_SMBCLIENT_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_SMB_MODE="hardened"
    "$SMB_MODULE" "sec-file-01.corp.internal" "domain" "$TARGET_HARDENED/smb" >/dev/null 2>&1
)
if [[ -f "$TARGET_HARDENED/smb/smb_security.txt" ]] && \
   grep -q "Signing: Required (Enforced)" "$TARGET_HARDENED/smb/smb_security.txt" && \
   grep -q "Message Signing.*Required (Enforced)" "$TARGET_HARDENED/smb/output.txt" && \
   ! grep -q "\[SECURITY WARN\] SMB Signing Not Required" "$TARGET_HARDENED/smb/output.txt"; then
    pass "smb module recognizes enforced SMB message signing and suppresses signing warning"
else
    fail "smb module failed to handle required message signing configuration"
fi

# -----------------------------------------------------------------------------
# UT-08: Share Enumeration & Anonymous Access Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Share Enumeration & Anonymous Access Auditing"

# Test 17: Enumerates shares and identifies anonymous readable/writable shares
if [[ -f "$TARGET_VULN/smb/smb_shares.txt" ]] && \
   grep -F -q "\\dc-primary.corp.internal\Public" "$TARGET_VULN/smb/smb_shares.txt" && \
   grep -q "Anonymous: READ/WRITE" "$TARGET_VULN/smb/smb_shares.txt" && \
   grep -q "\[SECURITY RISK\] Unauthenticated Access Permitted: Public" "$TARGET_VULN/smb/output.txt" && \
   grep -q "\[SECURITY RISK\] Unauthenticated Access Permitted: IPC" "$TARGET_VULN/smb/output.txt"; then
    pass "smb module enumerates shares and issues security risk findings on anonymous access"
else
    fail "smb module failed to enumerate shares or identify anonymous access"
fi

# Test 18: Supplementary shares discovered via smbclient are added
if grep -q "Backups" "$TARGET_VULN/smb/smb_shares.txt"; then
    pass "smb module incorporates supplementary shares discovered via smbclient"
else
    fail "smb module failed to include shares discovered by smbclient"
fi

# -----------------------------------------------------------------------------
# UT-09: Secure Permissions & Artifact Integrity
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Secure Permissions & Artifact Integrity"

# Test 19: All generated artifact files have 0640 permissions
non_compliant_perms=0
for f in "$TARGET_VULN/smb"/*; do
    if [[ -f "$f" ]]; then
        file_perm="$(stat -c '%a' "$f")"
        if [[ "$file_perm" != "640" ]]; then
            non_compliant_perms=$(( non_compliant_perms + 1 ))
        fi
    fi
done

if (( non_compliant_perms == 0 )); then
    pass "all smb task artifacts enforce secure 0640 permissions"
else
    fail "found $non_compliant_perms file(s) without required 0640 permissions"
fi

# Test 20: Aggregated findings count is reflected in execution footer
if grep -q "SMB audit completed with 3 security finding(s)." "$TARGET_VULN/smb/output.txt"; then
    pass "smb module aggregates signing and share findings in execution footer"
else
    fail "smb module footer findings count mismatch"
fi

test_summary
