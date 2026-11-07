#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Service Detection Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

SERVICE_MODULE="$PROJECT_ROOT/modules/network/service.sh"
readonly SERVICE_MODULE

if [[ ! -f "$SERVICE_MODULE" || ! -x "$SERVICE_MODULE" ]]; then
    printf 'Error: Service detection module missing or not executable at %s\n' "$SERVICE_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-service-test.XXXXXX")" || {
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

    printf '%s\n' "Service detection module unit tests completed."
}

printf '%s\n' "RECKON - Service Detection Module Unit Tests"
printf '%s\n' "--------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$SERVICE_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "service module rejects execution with insufficient arguments (< 3)"
else
    fail "service module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$SERVICE_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "service module rejects empty target argument"
else
    fail "service module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$SERVICE_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "service module rejects empty target type argument"
else
    fail "service module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$SERVICE_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "service module rejects empty task directory argument"
else
    fail "service module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$SERVICE_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "Incompatible target type" "$TASK_DIR_CIDR/output.txt"; then
        pass "service module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "service module did not write expected failure notice for CIDR target"
    fi
else
    fail "service module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$SERVICE_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_RANGE/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_RANGE/output.txt"; then
        pass "service module rejects multi-host IPv4 range with incompatible target notice"
    else
        fail "service module did not write expected failure notice for range target"
    fi
else
    fail "service module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http target type
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$SERVICE_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "service module rejects url_http target type"
else
    fail "service module succeeded on incompatible url_http target"
fi

# Test 8: Rejects url_https target type
TASK_DIR_URLS="$TEST_ROOT/incompat_urls"
if ! "$SERVICE_MODULE" "https://example.com" "url_https" "$TASK_DIR_URLS" >/dev/null 2>&1; then
    pass "service module rejects url_https target type"
else
    fail "service module succeeded on incompatible url_https target"
fi

# -----------------------------------------------------------------------------
# UT-03: Dependency & Tool Availability
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Dependency & Tool Availability"

# Test 9: Reports failure when nmap is not available in PATH
TASK_DIR_NO_TOOL="$TEST_ROOT/no_tool"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="/nonexistent/bin/nmap_missing"
    "$SERVICE_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service detection tool" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "service module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "service module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mock Nmap Service Engine
# -----------------------------------------------------------------------------
MOCK_NMAP_BIN="$TEST_ROOT/mock_nmap_service.sh"
cat > "$MOCK_NMAP_BIN" <<'EOF'
#!/usr/bin/env bash
# Flexible mock Nmap binary for service unit testing
set -o nounset

if [[ -n "${MOCK_NMAP_ARGS_LOG:-}" ]]; then
    printf '%s\n' "$*" > "$MOCK_NMAP_ARGS_LOG"
fi

gnmap_path=""
nmap_path=""
target=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -oG) gnmap_path="$2"; shift 2 ;;
        -oN) nmap_path="$2"; shift 2 ;;
        -*) shift ;;
        *) target="$1"; shift ;;
    esac
done

if [[ -n "${MOCK_NMAP_FORCE_FAIL:-}" ]]; then
    exit "$MOCK_NMAP_FORCE_FAIL"
fi

if [[ "${MOCK_NMAP_MODE:-}" == "empty" ]]; then
    if [[ -n "$gnmap_path" ]]; then
        printf "# Nmap scan initiated\nHost: %s ()\tStatus: Up\tIgnored State: closed (1000)\n# Nmap done\n" "${target:-127.0.0.1}" > "$gnmap_path"
    fi
    if [[ -n "$nmap_path" ]]; then
        printf "Starting Nmap...\nAll 1000 scanned ports on %s are in ignored states.\nNmap done\n" "${target:-127.0.0.1}" > "$nmap_path"
    fi
    exit 0
fi

if [[ "${MOCK_NMAP_MODE:-}" == "nmap_only" ]]; then
    if [[ -n "$nmap_path" ]]; then
        cat > "$nmap_path" <<NMAP_ONLY_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up.

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  ssl/http nginx 1.18.0

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
NMAP_ONLY_EOF
    fi
    exit 0
fi

# Default Mode: emit both gnmap and nmap
if [[ -n "$gnmap_path" ]]; then
    cat > "$gnmap_path" <<GNMAP_DEFAULT_EOF
# Nmap 7.94 scan initiated Sat Nov  7 21:00:00 2026 as: nmap ...
Host: ${target:-127.0.0.1} (target.local)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu 3ubuntu0.1/, 80/open/tcp//http//Apache httpd 2.4.52 ((Ubuntu))/, 443/open/tcp//ssl|http//nginx 1.18.0/\tIgnored State: closed (997)
# Nmap done at Sat Nov  7 21:00:01 2026 -- 1 IP address (1 host up) scanned in 0.45 seconds
GNMAP_DEFAULT_EOF
fi

if [[ -n "$nmap_path" ]]; then
    cat > "$nmap_path" <<NMAP_DEFAULT_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up.

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  ssl/http nginx 1.18.0

Nmap done: 1 IP address (1 host up) scanned
NMAP_DEFAULT_EOF
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_BIN"

ARGS_LOG="$TEST_ROOT/service_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port Integration (open_ports.txt)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port Integration (open_ports.txt)"

TARGET_BASE_DIR="$TEST_ROOT/target_upstream"
mkdir -p "$TARGET_BASE_DIR/port" "$TARGET_BASE_DIR/service"

# Test 10: Targets upstream open ports when open_ports.txt is present
printf "22\n80\n443\n" > "$TARGET_BASE_DIR/port/open_ports.txt"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SERVICE_MODULE" "192.0.2.1" "ipv4" "$TARGET_BASE_DIR/service" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 22,80,443" "$ARGS_LOG"; then
    pass "service module targets upstream open ports from open_ports.txt (-p 22,80,443)"
else
    fail "service module did not target upstream ports (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 11: Skips active scan when upstream open_ports.txt is empty (0 open ports)
ZERO_BASE_DIR="$TEST_ROOT/target_zero"
mkdir -p "$ZERO_BASE_DIR/port" "$ZERO_BASE_DIR/service"
: > "$ZERO_BASE_DIR/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SERVICE_MODULE" "192.0.2.1" "ipv4" "$ZERO_BASE_DIR/service" >/dev/null 2>&1
)
zero_port_exit=$?

if (( zero_port_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "Port scanning detected 0 open ports" "$ZERO_BASE_DIR/service/output.txt" && \
   grep -q "COMPLETED | No open ports available for service detection." "$ZERO_BASE_DIR/service/output.txt"; then
    pass "service module cleanly skips active probing when upstream open_ports.txt is empty"
else
    fail "service module did not handle empty upstream ports correctly (exit: $zero_port_exit)"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Scope Resolution
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Scope Resolution"

# Test 12: Falls back to CONFIG_EFFECTIVE_PORTS when upstream artifact is missing
STANDALONE_DIR="$TEST_ROOT/standalone_custom"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="80,443,8080"
    "$SERVICE_MODULE" "192.0.2.1" "ipv4" "$STANDALONE_DIR" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 80,443,8080" "$ARGS_LOG"; then
    pass "standalone execution falls back to configured ports (-p 80,443,8080)"
else
    fail "standalone execution failed to use configured ports (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 13: Falls back to default top-1000 ports when no configuration provided
STANDALONE_DEF="$TEST_ROOT/standalone_default"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$SERVICE_MODULE" "192.0.2.1" "ipv4" "$STANDALONE_DEF" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--top-ports 1000" "$ARGS_LOG"; then
    pass "standalone execution defaults to '--top-ports 1000'"
else
    fail "standalone execution did not default to top-1000 (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-06: Flag Propagation & Options
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Flag Propagation & Options"

# Test 14: Passes -sV, -Pn, -n, --system-dns, -T4, and version intensity
TASK_DIR_FLAGS="$TEST_ROOT/flags_test"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_RATE_LIMIT=120
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_TIMEOUT=60
    "$SERVICE_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FLAGS" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && \
   grep -q -- "-sV" "$ARGS_LOG" && \
   grep -q -- "-Pn" "$ARGS_LOG" && \
   grep -q -- "-n" "$ARGS_LOG" && \
   grep -q -- "--system-dns" "$ARGS_LOG" && \
   grep -q -- "-T4" "$ARGS_LOG" && \
   grep -q -- "--version-intensity 7" "$ARGS_LOG" && \
   grep -q -- "--min-rate 120" "$ARGS_LOG" && \
   grep -q -- "--host-timeout 60s" "$ARGS_LOG"; then
    pass "propagates all standard service versioning, timing, and rate limiting flags"
else
    fail "missing expected flags in nmap execution (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-07: Service Output Parsing & Artifact Generation (.gnmap)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Service Output Parsing & Artifact Generation (.gnmap)"

TASK_DIR_SCAN="$TEST_ROOT/scan_gnmap"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    "$SERVICE_MODULE" "srv.example.com" "domain" "$TASK_DIR_SCAN" >/dev/null 2>&1
)
scan_status=$?

# Test 15: Exit code 0 on successful service scan
if (( scan_status == 0 )); then
    pass "service scan executes successfully and exits with code 0"
else
    fail "service scan failed with exit code $scan_status"
fi

# Test 16: Emits tab-delimited records to services.txt
SERVICES_FILE="$TASK_DIR_SCAN/services.txt"
if [[ -f "$SERVICES_FILE" ]] && \
   grep -q "22/tcp	open	ssh	OpenSSH 8.9p1" "$SERVICES_FILE" && \
   grep -q "80/tcp	open	http	Apache httpd" "$SERVICES_FILE" && \
   grep -q "443/tcp	open	ssl|http	nginx 1.18.0" "$SERVICES_FILE"; then
    pass "services.txt contains parsed service records (ssh, http, nginx)"
else
    fail "services.txt content did not match expected structure (saw: $(cat "$SERVICES_FILE" 2>/dev/null))"
fi

# Test 17: Emits structured output.txt with table and status
OUTPUT_FILE="$TASK_DIR_SCAN/output.txt"
if [[ -f "$OUTPUT_FILE" ]] && \
   grep -q "RECKON Network Reconnaissance - Service Detection" "$OUTPUT_FILE" && \
   grep -q "Total Services           : 3" "$OUTPUT_FILE" && \
   grep -q "Service Names            : ssh, http, ssl|http" "$OUTPUT_FILE" && \
   grep -q "22/tcp" "$OUTPUT_FILE" && \
   grep -q "80/tcp" "$OUTPUT_FILE" && \
   grep -q "COMPLETED | Identified 3 active service(s)." "$OUTPUT_FILE"; then
    pass "output.txt contains structured findings table, service names, and completion footer"
else
    fail "output.txt format did not match expected structure"
fi

# Test 18: File permissions enforced to 0640
file_perm="$(stat -c '%a' "$SERVICES_FILE" 2>/dev/null || stat -f '%Lp' "$SERVICES_FILE" 2>/dev/null || echo "unknown")"
if [[ "$file_perm" == "640" ]]; then
    pass "services.txt permissions restricted to 0640"
else
    fail "services.txt permissions ($file_perm) are not 0640"
fi

# -----------------------------------------------------------------------------
# UT-08: Standard Nmap Output Fallback (.nmap)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Standard Nmap Output Fallback (.nmap)"

TASK_DIR_FALLBACK="$TEST_ROOT/scan_nmap_only"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_MODE="nmap_only"
    "$SERVICE_MODULE" "10.0.0.5" "ipv4" "$TASK_DIR_FALLBACK" >/dev/null 2>&1
)

# Test 19: Fallback parser extracts services from standard .nmap
if [[ -f "$TASK_DIR_FALLBACK/services.txt" ]] && \
   grep -q "22/tcp	open	ssh	OpenSSH 8.9p1" "$TASK_DIR_FALLBACK/services.txt" && \
   grep -q "80/tcp	open	http	Apache httpd" "$TASK_DIR_FALLBACK/services.txt"; then
    pass "fallback parser correctly extracts services and version info from standard .nmap output"
else
    fail "fallback parser failed to extract services from .nmap (saw: $(cat "$TASK_DIR_FALLBACK/services.txt" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-09: Catastrophic Execution Failure
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Catastrophic Execution Failure"

TASK_DIR_FAIL="$TEST_ROOT/scan_fail"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_FORCE_FAIL=14
    "$SERVICE_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FAIL" >/dev/null 2>&1
)
fail_exit=$?

# Test 20: Returns nmap exit code and logs failure notice
if (( fail_exit == 14 )) && [[ -f "$TASK_DIR_FAIL/output.txt" ]] && grep -q "Nmap service scan execution failed with exit code 14" "$TASK_DIR_FAIL/output.txt"; then
    pass "catastrophic nmap failure returns exit code 14 and logs failure notice"
else
    fail "did not handle catastrophic failure properly (exit: $fail_exit)"
fi

# -----------------------------------------------------------------------------
# UT-10: Engine Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-10: Engine Integration"

# Test 21: Dispatches seamlessly through engine_run
ENGINE_TEST_DIR="$TEST_ROOT/engine_run_service"
(
    # shellcheck source=core/engine.sh
    source "$PROJECT_ROOT/core/engine.sh"
    # shellcheck source=lib/fs.sh
    source "$PROJECT_ROOT/lib/fs.sh"
    # shellcheck source=lib/exec.sh
    source "$PROJECT_ROOT/lib/exec.sh"

    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"

    TARGET_VALUE=("192.0.2.1")
    TARGET_TYPE=("ipv4")

    engine_init
    engine_resolve_modules "false" "false" "service" ""
    engine_plan_scan
    engine_run "false" "$ENGINE_TEST_DIR" 0 0
)
engine_exit=$?

if (( engine_exit == 0 )) && [[ -f "$ENGINE_TEST_DIR/192.0.2.1/service/services.txt" ]] && [[ -f "$ENGINE_TEST_DIR/192.0.2.1/service/output.txt" ]]; then
    pass "engine_run dispatches service module and creates task artifacts"
else
    fail "engine_run integration failed (exit: $engine_exit)"
fi

test_summary
