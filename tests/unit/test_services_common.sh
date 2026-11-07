#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Service Module Common Framework Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

SERVICES_COMMON="$PROJECT_ROOT/modules/network/services/common.sh"
readonly SERVICES_COMMON

if [[ ! -f "$SERVICES_COMMON" ]]; then
    printf 'Error: Service module common library not found at %s\n' "$SERVICES_COMMON" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-svccommon-test.XXXXXX")" || {
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

    printf '%s\n' "Service module common library unit tests completed."
}

printf '%s\n' "RECKON - Service Module Common Library Unit Tests"
printf '%s\n' "------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Framework Loading & Include Guards
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Framework Loading & Include Guards"

# Test 1: Sourcing common library succeeds
# shellcheck source=modules/network/services/common.sh
if source "$SERVICES_COMMON"; then
    pass "sources service module common library without error"
else
    fail "failed to source service module common library"
fi

# Test 2: Inherits base network common functions
if declare -f net_mod_has_tool >/dev/null 2>&1 && \
   declare -f net_mod_is_single_host >/dev/null 2>&1 && \
   declare -f net_mod_resolve_nmap >/dev/null 2>&1; then
    pass "inherits base network common functions from modules/network/common.sh"
else
    fail "did not inherit base network common library functions"
fi

# -----------------------------------------------------------------------------
# UT-02: Context Initialization & Argument Validation (svc_mod_init)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Context Initialization & Target Validation"

# Test 3: Rejects insufficient arguments (< 3)
if ! svc_mod_init "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "svc_mod_init rejects execution with insufficient arguments (< 3)"
else
    fail "svc_mod_init accepted only 2 arguments"
fi

# Test 4: Rejects empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! svc_mod_init "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "svc_mod_init rejects empty target"
else
    fail "svc_mod_init accepted empty target"
fi

# Test 5: Rejects multi-host CIDR targets
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! svc_mod_init "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "svc_mod_init rejects multi-host CIDR block with structured failure notice"
    else
        fail "svc_mod_init did not write expected failure notice for CIDR"
    fi
else
    fail "svc_mod_init accepted incompatible ipv4_cidr target"
fi

# Test 6: Rejects multi-host range targets
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! svc_mod_init "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "svc_mod_init rejects multi-host IPv4 range targets"
else
    fail "svc_mod_init accepted incompatible ipv4_range target"
fi

# Test 7: Rejects URL target types
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! svc_mod_init "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "svc_mod_init rejects url_http target type"
else
    fail "svc_mod_init accepted incompatible url_http target"
fi

# Test 8: Accepts single host target and exports sibling paths
TASK_DIR_OK="$TEST_ROOT/target_host/ssh"
if svc_mod_init "target.local" "domain" "$TASK_DIR_OK"; then
    if [[ "$SVC_TARGET" == "target.local" && \
          "$SVC_TARGET_TYPE" == "domain" && \
          "$SVC_PORT_DIR" == "$TEST_ROOT/target_host/port" && \
          "$SVC_SERVICE_DIR" == "$TEST_ROOT/target_host/service" && \
          "$SVC_OPEN_PORTS_FILE" == "$TEST_ROOT/target_host/port/open_ports.txt" && \
          "$SVC_SERVICES_FILE" == "$TEST_ROOT/target_host/service/services.txt" ]]; then
        pass "svc_mod_init sets up target context and sibling artifact paths"
    else
        fail "svc_mod_init sibling artifact paths miscalculated"
    fi
else
    fail "svc_mod_init failed on valid single domain target"
fi

# -----------------------------------------------------------------------------
# UT-03: Port Resolution from Upstream services.txt (svc_mod_resolve_ports)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Port Resolution from Upstream services.txt"

TARGET_BOX="$TEST_ROOT/box_services"
mkdir -p "$TARGET_BOX/service" "$TARGET_BOX/ssh"
svc_mod_init "box.local" "domain" "$TARGET_BOX/ssh" >/dev/null 2>&1

# Emulate upstream services.txt with non-standard SSH port 2222
cat > "$TARGET_BOX/service/services.txt" <<'EOF'
2222/tcp	open	ssh	OpenSSH 8.9p1 Ubuntu
8080/tcp	open	http-proxy	Squid 4.13
EOF

# Test 9: Resolves non-standard port 2222 from services.txt
if svc_mod_resolve_ports "ssh" "22" "ssh"; then
    if (( ${#SVC_RESOLVED_PORTS[@]} == 1 )) && [[ "${SVC_RESOLVED_PORTS[0]}" == "2222" ]] && \
       [[ "$SVC_PORT_SOURCE" == "Service detection (services.txt)" ]]; then
        pass "resolves non-standard port 2222 from upstream services.txt matching regex 'ssh'"
    else
        fail "failed to resolve non-standard port from services.txt: ports=${SVC_RESOLVED_PORTS[*]}"
    fi
else
    fail "svc_mod_resolve_ports failed on existing services.txt match"
fi

# Test 10: Deduplicates repeated ports from services.txt
cat > "$TARGET_BOX/service/services.txt" <<'EOF'
22/tcp	open	ssh	OpenSSH 8.9p1
22/tcp	open	ssh	OpenSSH 8.9p1
EOF
svc_mod_resolve_ports "ssh" "22" "ssh"
if (( ${#SVC_RESOLVED_PORTS[@]} == 1 )) && [[ "${SVC_RESOLVED_PORTS[0]}" == "22" ]]; then
    pass "deduplicates repeated port occurrences from services.txt"
else
    fail "failed to deduplicate repeated ports: ${SVC_RESOLVED_PORTS[*]}"
fi

# -----------------------------------------------------------------------------
# UT-04: Port Resolution from Upstream open_ports.txt
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Port Resolution from Upstream open_ports.txt"

BOX_OPEN="$TEST_ROOT/box_open"
mkdir -p "$BOX_OPEN/port" "$BOX_OPEN/smb"
svc_mod_init "smb.local" "domain" "$BOX_OPEN/smb" >/dev/null 2>&1

# Emulate upstream open_ports.txt with open SMB ports (445 and 139)
printf "80\n139\n445\n" > "$BOX_OPEN/port/open_ports.txt"

# Test 11: Resolves default ports present in open_ports.txt
if svc_mod_resolve_ports "smb" "445,139" "microsoft-ds|netbios-ssn|smb"; then
    if (( ${#SVC_RESOLVED_PORTS[@]} == 2 )) && \
       [[ "${SVC_RESOLVED_PORTS[0]}" == "445" && "${SVC_RESOLVED_PORTS[1]}" == "139" ]] && \
       [[ "$SVC_PORT_SOURCE" == "Port scan verification (open_ports.txt)" ]]; then
        pass "resolves default SMB ports (445, 139) verified active in open_ports.txt"
    else
        fail "failed to resolve default ports from open_ports.txt: ports=${SVC_RESOLVED_PORTS[*]}"
    fi
else
    fail "svc_mod_resolve_ports failed on open_ports.txt"
fi

# -----------------------------------------------------------------------------
# UT-05: Inactive Service Skip Optimization (svc_mod_should_skip)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Inactive Service Skip Optimization"

BOX_CLOSED="$TEST_ROOT/box_closed"
mkdir -p "$BOX_CLOSED/port" "$BOX_CLOSED/telnet"
svc_mod_init "closed.local" "domain" "$BOX_CLOSED/telnet" >/dev/null 2>&1

# Emulate open_ports.txt where telnet (port 23) is NOT open
printf "80\n443\n" > "$BOX_CLOSED/port/open_ports.txt"

# Test 12: Flags service as skipped when ports are not open
if ! svc_mod_resolve_ports "telnet" "23" "telnet"; then
    if [[ "$SVC_SKIP_SCAN" == true ]] && svc_mod_should_skip && \
       [[ "$SVC_SKIP_REASON" == *"not open"* ]]; then
        pass "svc_mod_should_skip returns 0 and sets skip reason when port is verified closed"
    else
        fail "did not flag skip state properly when port was closed"
    fi
else
    fail "svc_mod_resolve_ports succeeded despite closed port"
fi

# -----------------------------------------------------------------------------
# UT-06: Standalone Execution Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Standalone Execution Fallback"

BOX_STANDALONE="$TEST_ROOT/box_standalone/ftp"
mkdir -p "$BOX_STANDALONE"
svc_mod_init "ftp.local" "domain" "$BOX_STANDALONE" >/dev/null 2>&1

# Neither services.txt nor open_ports.txt exists
# Test 13: Falls back to canonical default port (21)
if svc_mod_resolve_ports "ftp" "21" "ftp"; then
    if (( ${#SVC_RESOLVED_PORTS[@]} == 1 )) && [[ "${SVC_RESOLVED_PORTS[0]}" == "21" ]] && \
       [[ "$SVC_PORT_SOURCE" == "Canonical default port(s)" ]]; then
        pass "standalone execution falls back to canonical default port (21)"
    else
        fail "standalone fallback failed: ports=${SVC_RESOLVED_PORTS[*]}, source=$SVC_PORT_SOURCE"
    fi
else
    fail "svc_mod_resolve_ports failed in standalone mode"
fi

# -----------------------------------------------------------------------------
# UT-07: Explicit CLI Port Override
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Explicit CLI Port Override"

BOX_OVERRIDE="$TEST_ROOT/box_override"
mkdir -p "$BOX_OVERRIDE/port" "$BOX_OVERRIDE/http"
svc_mod_init "web.local" "domain" "$BOX_OVERRIDE/http" >/dev/null 2>&1

# Upstream open_ports.txt has 80, but CLI specifies 8000, 8080
printf "80\n" > "$BOX_OVERRIDE/port/open_ports.txt"
CONFIG_EFFECTIVE_PORTS="8000, 8080"

# Test 14: Honors CONFIG_EFFECTIVE_PORTS override over upstream discovery
if svc_mod_resolve_ports "http" "80" "http"; then
    if (( ${#SVC_RESOLVED_PORTS[@]} == 2 )) && \
       [[ "${SVC_RESOLVED_PORTS[0]}" == "8000" && "${SVC_RESOLVED_PORTS[1]}" == "8080" ]] && \
       [[ "$SVC_PORT_SOURCE" == "CLI configuration override" ]]; then
        pass "CONFIG_EFFECTIVE_PORTS overrides upstream artifacts with user-specified ports (8000, 8080)"
    else
        fail "CLI override failed: ports=${SVC_RESOLVED_PORTS[*]}, source=$SVC_PORT_SOURCE"
    fi
else
    fail "svc_mod_resolve_ports failed on CLI override"
fi
CONFIG_EFFECTIVE_PORTS=""

# -----------------------------------------------------------------------------
# UT-08: Skipped Service Notice & Graceful Completion (svc_mod_handle_skipped)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Skipped Service Notice & Graceful Completion"

BOX_SKIP_HANDLE="$TEST_ROOT/box_skip_handle/telnet"
mkdir -p "$BOX_SKIP_HANDLE"
svc_mod_init "skip.local" "domain" "$BOX_SKIP_HANDLE" >/dev/null 2>&1
SVC_SKIP_REASON="Port scan verified port 23 is closed."

# Test 15: svc_mod_handle_skipped creates output.txt and exits with 0
if svc_mod_handle_skipped "telnet" "Telnet Enumeration"; then
    if [[ -f "$BOX_SKIP_HANDLE/output.txt" ]] && \
       grep -q "Notice: Port scan verified port 23 is closed." "$BOX_SKIP_HANDLE/output.txt" && \
       grep -q "Status: COMPLETED | Service not active on target." "$BOX_SKIP_HANDLE/output.txt"; then
        pass "svc_mod_handle_skipped writes structured notice and completes cleanly with exit 0"
    else
        fail "svc_mod_handle_skipped output.txt structure mismatch"
    fi
else
    fail "svc_mod_handle_skipped returned non-zero"
fi

# -----------------------------------------------------------------------------
# UT-09: Service Header Formatting (svc_mod_write_service_header)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Service Header Formatting"

BOX_HEADER="$TEST_ROOT/box_header/ssh"
mkdir -p "$BOX_HEADER"
svc_mod_init "header.local" "domain" "$BOX_HEADER" >/dev/null 2>&1
SVC_RESOLVED_PORTS=("22" "2222")
SVC_PORT_SOURCE="Custom resolution"

svc_mod_write_service_header "ssh" "SSH Enumeration" "nmap, ssh-audit"
net_mod_write_footer "COMPLETED" "Test completed."
net_mod_finish 0

# Test 16: Formats standard service target info header
if [[ -f "$BOX_HEADER/output.txt" ]] && \
   grep -q "Target Ports             : 22,2222" "$BOX_HEADER/output.txt" && \
   grep -q "Port Resolution          : Custom resolution" "$BOX_HEADER/output.txt" && \
   grep -q "Audit Engine(s)          : nmap, ssh-audit" "$BOX_HEADER/output.txt"; then
    pass "svc_mod_write_service_header renders standard target and resolution metadata"
else
    fail "svc_mod_write_service_header output mismatch"
fi

# -----------------------------------------------------------------------------
# UT-10: Banner Grabbing (svc_mod_banner_grab)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-10: Banner Grabbing"

# Test 17: Rejects empty host or port
if ! svc_mod_banner_grab "" "22" >/dev/null 2>&1 && \
   ! svc_mod_banner_grab "127.0.0.1" "" >/dev/null 2>&1; then
    pass "svc_mod_banner_grab rejects empty host or port parameters"
else
    fail "svc_mod_banner_grab accepted empty parameters"
fi

# Test 18: Returns non-zero on closed connection without hanging
if ! svc_mod_banner_grab "127.0.0.1" "65534" 1 >/dev/null 2>&1; then
    pass "svc_mod_banner_grab returns non-zero on unreachable socket within timeout"
else
    fail "svc_mod_banner_grab succeeded on closed socket 65534"
fi

# -----------------------------------------------------------------------------
# UT-11: Task Finalization & Permissions (svc_mod_finish)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-11: Task Finalization & Permissions"

BOX_FINISH="$TEST_ROOT/box_finish/ftp"
mkdir -p "$BOX_FINISH"
svc_mod_init "finish.local" "domain" "$BOX_FINISH" >/dev/null 2>&1

echo "dummy artifact 1" > "$BOX_FINISH/banner.txt"
echo "dummy artifact 2" > "$BOX_FINISH/output.txt"

# Test 19: Enforces 0640 permissions on created files
svc_mod_finish 0
perm_b="$(stat -c '%a' "$BOX_FINISH/banner.txt" 2>/dev/null || stat -f '%Lp' "$BOX_FINISH/banner.txt" 2>/dev/null || echo "unknown")"
perm_o="$(stat -c '%a' "$BOX_FINISH/output.txt" 2>/dev/null || stat -f '%Lp' "$BOX_FINISH/output.txt" 2>/dev/null || echo "unknown")"

if [[ "$perm_b" == "640" && "$perm_o" == "640" ]]; then
    pass "svc_mod_finish enforces 0640 permissions across all files in task directory"
else
    fail "file permissions not 0640: banner=$perm_b, output=$perm_o"
fi

# Test 20: Preserves custom exit code (42)
ret_code=0
svc_mod_finish 42 || ret_code=$?
if (( ret_code == 42 )); then
    pass "svc_mod_finish preserves non-zero exit code (42)"
else
    fail "svc_mod_finish did not preserve exit code (got: $ret_code)"
fi

test_summary
