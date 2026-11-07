#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Port Scanning Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

PORT_MODULE="$PROJECT_ROOT/modules/network/port.sh"
readonly PORT_MODULE

if [[ ! -f "$PORT_MODULE" || ! -x "$PORT_MODULE" ]]; then
    printf 'Error: Port scanning module missing or not executable at %s\n' "$PORT_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-port-test.XXXXXX")" || {
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

    printf '%s\n' "Port scanning module unit tests completed."
}

printf '%s\n' "RECKON - Port Scanning Module Unit Tests"
printf '%s\n' "-----------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$PORT_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "port module rejects execution with insufficient arguments (< 3)"
else
    fail "port module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$PORT_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "port module rejects empty target argument"
else
    fail "port module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$PORT_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "port module rejects empty target type argument"
else
    fail "port module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$PORT_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "port module rejects empty task directory argument"
else
    fail "port module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$PORT_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "Incompatible target type" "$TASK_DIR_CIDR/output.txt"; then
        pass "port module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "port module did not write expected failure notice for CIDR target"
    fi
else
    fail "port module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$PORT_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_RANGE/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_RANGE/output.txt"; then
        pass "port module rejects multi-host IPv4 range with incompatible target notice"
    else
        fail "port module did not write expected failure notice for range target"
    fi
else
    fail "port module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http target type
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$PORT_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_URL/output.txt" ]] && grep -q "Incompatible target type" "$TASK_DIR_URL/output.txt"; then
        pass "port module rejects url_http target with incompatible target notice"
    else
        fail "port module did not write expected failure notice for url_http target"
    fi
else
    fail "port module succeeded on incompatible url_http target"
fi

# Test 8: Rejects url_https target type
TASK_DIR_URLS="$TEST_ROOT/incompat_urls"
if ! "$PORT_MODULE" "https://example.com" "url_https" "$TASK_DIR_URLS" >/dev/null 2>&1; then
    pass "port module rejects url_https target type"
else
    fail "port module succeeded on incompatible url_https target"
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
    "$PORT_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required port scanning tool" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "port module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "port module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mock Nmap Engine
# -----------------------------------------------------------------------------
MOCK_NMAP_BIN="$TEST_ROOT/mock_nmap.sh"
cat > "$MOCK_NMAP_BIN" <<'EOF'
#!/usr/bin/env bash
# Flexible mock Nmap binary for unit testing
set -o nounset

# Log invocation arguments if requested
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

# Simulated catastrophic failure
if [[ -n "${MOCK_NMAP_FORCE_FAIL:-}" ]]; then
    exit "$MOCK_NMAP_FORCE_FAIL"
fi

# Mode: empty scan (no open ports)
if [[ "${MOCK_NMAP_MODE:-}" == "empty" ]]; then
    if [[ -n "$gnmap_path" ]]; then
        printf "# Nmap scan initiated\nHost: %s ()\tStatus: Up\tIgnored State: closed (1000)\n# Nmap done\n" "${target:-127.0.0.1}" > "$gnmap_path"
    fi
    if [[ -n "$nmap_path" ]]; then
        printf "Starting Nmap...\nAll 1000 scanned ports on %s are in ignored states.\nNmap done: 1 IP address (1 host up)\n" "${target:-127.0.0.1}" > "$nmap_path"
    fi
    exit 0
fi

# Mode: standard nmap only (no gnmap output generated)
if [[ "${MOCK_NMAP_MODE:-}" == "nmap_only" ]]; then
    if [[ -n "$nmap_path" ]]; then
        cat > "$nmap_path" <<NMAP_ONLY_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up (0.0010s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp closed http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
NMAP_ONLY_EOF
    fi
    exit 0
fi

# Default Mode: emit both gnmap and nmap with standard findings
if [[ -n "$gnmap_path" ]]; then
    cat > "$gnmap_path" <<GNMAP_DEFAULT_EOF
# Nmap 7.94 scan initiated Sat Nov  7 21:00:00 2026 as: nmap ...
Host: ${target:-127.0.0.1} (target.local)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu/, 80/open/tcp//http//Apache httpd 2.4.52/, 443/open/tcp//https///, 3306/closed/tcp//mysql///\tIgnored State: closed (997)
# Nmap done at Sat Nov  7 21:00:01 2026 -- 1 IP address (1 host up) scanned in 0.45 seconds
GNMAP_DEFAULT_EOF
fi

if [[ -n "$nmap_path" ]]; then
    cat > "$nmap_path" <<NMAP_DEFAULT_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up.

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
443/tcp  open  https
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned
NMAP_DEFAULT_EOF
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_BIN"

# -----------------------------------------------------------------------------
# UT-04: Port Scope & Configuration Mapping
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Port Scope & Configuration Mapping"

ARGS_LOG="$TEST_ROOT/nmap_args.log"

# Test 10: Default port scope applies --top-ports 1000
TASK_DIR_DEF="$TEST_ROOT/scope_default"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_DEF" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--top-ports 1000" "$ARGS_LOG"; then
    pass "default port scope maps to '--top-ports 1000'"
else
    fail "default port scope did not pass '--top-ports 1000' (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 11: CONFIG_EFFECTIVE_PROFILE=fast applies --top-ports 100
TASK_DIR_FAST="$TEST_ROOT/scope_fast"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PROFILE="fast"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FAST" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--top-ports 100" "$ARGS_LOG"; then
    pass "profile 'fast' maps to '--top-ports 100'"
else
    fail "profile 'fast' did not pass '--top-ports 100'"
fi

# Test 12: CONFIG_EFFECTIVE_PORTS=top-100 applies --top-ports 100
TASK_DIR_TOP100="$TEST_ROOT/scope_top100"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="top-100"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_TOP100" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--top-ports 100" "$ARGS_LOG"; then
    pass "ports 'top-100' maps to '--top-ports 100'"
else
    fail "ports 'top-100' did not pass '--top-ports 100'"
fi

# Test 13: CONFIG_EFFECTIVE_PORTS=top-1000 applies --top-ports 1000
TASK_DIR_TOP1000="$TEST_ROOT/scope_top1000"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="top-1000"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_TOP1000" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--top-ports 1000" "$ARGS_LOG"; then
    pass "ports 'top-1000' maps to '--top-ports 1000'"
else
    fail "ports 'top-1000' did not pass '--top-ports 1000'"
fi

# Test 14: CONFIG_EFFECTIVE_PORTS=full applies -p-
TASK_DIR_FULL="$TEST_ROOT/scope_full"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="full"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FULL" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p-" "$ARGS_LOG"; then
    pass "ports 'full' maps to '-p-'"
else
    fail "ports 'full' did not pass '-p-'"
fi

# Test 15: CONFIG_EFFECTIVE_PORTS custom port list
TASK_DIR_CUSTOM="$TEST_ROOT/scope_custom"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="22, 80, 443, 8080"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_CUSTOM" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 22,80,443,8080" "$ARGS_LOG"; then
    pass "ports custom list strips whitespace and maps to '-p 22,80,443,8080'"
else
    fail "ports custom list was not formatted correctly (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-05: Execution Flags & Scan Techniques
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Execution Flags & Scan Techniques"

# Test 16: Passes timing -T4, -Pn, -n, and --max-retries
TASK_DIR_FLAGS="$TEST_ROOT/flags_test"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_RETRIES=2
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FLAGS" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-T4" "$ARGS_LOG" && grep -q -- "-Pn" "$ARGS_LOG" && grep -q -- "-n" "$ARGS_LOG" && grep -q -- "--max-retries 2" "$ARGS_LOG"; then
    pass "applies -T4, -Pn, -n, and configured --max-retries"
else
    fail "missing standard nmap timing or flags (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 17: Passes --min-rate and --host-timeout when configured
TASK_DIR_RATE="$TEST_ROOT/rate_test"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_RATE_LIMIT=150
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_TIMEOUT=45
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_RATE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--min-rate 150" "$ARGS_LOG" && grep -q -- "--host-timeout 45s" "$ARGS_LOG"; then
    pass "passes configured --min-rate and --host-timeout options"
else
    fail "did not pass --min-rate or --host-timeout properly (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 18: Honors RECKON_MOCK_SCAN_TYPE override
TASK_DIR_SCAN_TYPE="$TEST_ROOT/scan_type_test"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SCAN_TYPE="-sS"
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_SCAN_TYPE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-sS" "$ARGS_LOG"; then
    pass "honors scan technique override (-sS stealth scan)"
else
    fail "did not honor scan technique override (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-06: Grepable Output (.gnmap) Parsing & Artifact Generation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Grepable Output (.gnmap) Parsing & Artifact Generation"

TASK_DIR_SCAN="$TEST_ROOT/scan_gnmap"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    "$PORT_MODULE" "target.example.com" "domain" "$TASK_DIR_SCAN" >/dev/null 2>&1
)
scan_status=$?

# Test 19: Exit code 0 on successful scan
if (( scan_status == 0 )); then
    pass "port scan executes successfully and exits with code 0"
else
    fail "port scan failed with exit code $scan_status"
fi

# Test 20: Discovered open ports written to open_ports.txt
OPEN_PORTS_FILE="$TASK_DIR_SCAN/open_ports.txt"
if [[ -f "$OPEN_PORTS_FILE" ]]; then
    open_p_content="$(tr '\n' ' ' < "$OPEN_PORTS_FILE" | xargs)"
    if [[ "$open_p_content" == "22 80 443" ]]; then
        pass "open_ports.txt contains newline-delimited open port numbers (22, 80, 443)"
    else
        fail "open_ports.txt content '$open_p_content' did not match expected '22 80 443'"
    fi
else
    fail "open_ports.txt was not generated"
fi

# Test 21: Formats structured output.txt with table and status
OUTPUT_FILE="$TASK_DIR_SCAN/output.txt"
if [[ -f "$OUTPUT_FILE" ]] && \
   grep -q "RECKON Network Reconnaissance - Port Scanning" "$OUTPUT_FILE" && \
   grep -q "Total Open Ports         : 3" "$OUTPUT_FILE" && \
   grep -q "22/tcp" "$OUTPUT_FILE" && \
   grep -q "80/tcp" "$OUTPUT_FILE" && \
   grep -q "443/tcp" "$OUTPUT_FILE" && \
   grep -q "COMPLETED | Identified 3 open port(s)." "$OUTPUT_FILE"; then
    pass "output.txt contains structured findings table, metrics, and completion footer"
else
    fail "output.txt format does not match expected structure"
fi

# Test 22: Enforces 0640 permissions on created artifacts
file_perm="$(stat -c '%a' "$OPEN_PORTS_FILE" 2>/dev/null || stat -f '%Lp' "$OPEN_PORTS_FILE" 2>/dev/null || echo "unknown")"
if [[ "$file_perm" == "640" ]]; then
    pass "open_ports.txt permissions restricted to 0640"
else
    fail "open_ports.txt permissions ($file_perm) are not 0640"
fi

# -----------------------------------------------------------------------------
# UT-07: Standard Nmap Output Fallback (.nmap)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Standard Nmap Output Fallback (.nmap)"

TASK_DIR_FALLBACK="$TEST_ROOT/scan_nmap_only"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_MODE="nmap_only"
    "$PORT_MODULE" "10.0.0.5" "ipv4" "$TASK_DIR_FALLBACK" >/dev/null 2>&1
)

# Test 23: Fallback parser extracts ports from standard .nmap
if [[ -f "$TASK_DIR_FALLBACK/open_ports.txt" ]]; then
    nmap_only_ports="$(tr '\n' ' ' < "$TASK_DIR_FALLBACK/open_ports.txt" | xargs)"
    if [[ "$nmap_only_ports" == "22 80 443" ]]; then
        pass "fallback parser correctly extracts open ports from standard .nmap output"
    else
        fail "fallback parser produced '$nmap_only_ports' (expected '22 80 443')"
    fi
else
    fail "open_ports.txt not generated in nmap_only fallback mode"
fi

# -----------------------------------------------------------------------------
# UT-08: Zero Open Ports Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Zero Open Ports Handling"

TASK_DIR_ZERO="$TEST_ROOT/scan_zero_ports"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_MODE="empty"
    "$PORT_MODULE" "192.0.2.100" "ipv4" "$TASK_DIR_ZERO" >/dev/null 2>&1
)
zero_status=$?

# Test 24: Exits 0 and generates empty open_ports.txt when no open ports detected
if (( zero_status == 0 )) && [[ -f "$TASK_DIR_ZERO/open_ports.txt" ]] && [[ ! -s "$TASK_DIR_ZERO/open_ports.txt" ]]; then
    if grep -q "Total Open Ports         : 0" "$TASK_DIR_ZERO/output.txt" && \
       grep -q "None (no open ports detected)" "$TASK_DIR_ZERO/output.txt" && \
       grep -q "COMPLETED | No open ports detected." "$TASK_DIR_ZERO/output.txt"; then
        pass "zero open ports handled cleanly: empty open_ports.txt and completed status"
    else
        fail "zero open ports output.txt did not match expected structure"
    fi
else
    fail "zero open ports scan failed or open_ports.txt is not empty (exit: $zero_status)"
fi

# -----------------------------------------------------------------------------
# UT-09: Catastrophic Execution Failure
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Catastrophic Execution Failure"

TASK_DIR_FAIL="$TEST_ROOT/scan_fail"
(
    # shellcheck disable=SC2030,SC2031
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_FORCE_FAIL=12
    "$PORT_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FAIL" >/dev/null 2>&1
)
fail_exit=$?

# Test 25: Returns nmap exit code and logs failure notice
if (( fail_exit == 12 )) && [[ -f "$TASK_DIR_FAIL/output.txt" ]] && grep -q "Nmap scan execution failed with exit code 12" "$TASK_DIR_FAIL/output.txt"; then
    pass "catastrophic nmap failure returns exit code 12 and logs failure notice"
else
    fail "did not handle catastrophic failure properly (exit: $fail_exit)"
fi

# -----------------------------------------------------------------------------
# UT-10: Engine Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-10: Engine Integration"

# Test 26: Dispatches seamlessly through engine_run
ENGINE_TEST_DIR="$TEST_ROOT/engine_run_port"
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
    engine_resolve_modules "false" "false" "port" ""
    engine_plan_scan
    engine_run "false" "$ENGINE_TEST_DIR" 0 0
)
engine_exit=$?

if (( engine_exit == 0 )) && [[ -f "$ENGINE_TEST_DIR/192.0.2.1/port/open_ports.txt" ]] && [[ -f "$ENGINE_TEST_DIR/192.0.2.1/port/output.txt" ]]; then
    pass "engine_run dispatches port module and creates task artifacts"
else
    fail "engine_run integration failed (exit: $engine_exit)"
fi

test_summary
