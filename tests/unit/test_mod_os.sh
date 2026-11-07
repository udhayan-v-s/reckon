#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# OS Fingerprinting Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

OS_MODULE="$PROJECT_ROOT/modules/network/os.sh"
readonly OS_MODULE

if [[ ! -f "$OS_MODULE" || ! -x "$OS_MODULE" ]]; then
    printf 'Error: OS detection module missing or not executable at %s\n' "$OS_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-os-test.XXXXXX")" || {
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

    printf '%s\n' "OS detection module unit tests completed."
}

printf '%s\n' "RECKON - OS Detection Module Unit Tests"
printf '%s\n' "---------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$OS_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "os module rejects execution with insufficient arguments (< 3)"
else
    fail "os module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$OS_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "os module rejects empty target argument"
else
    fail "os module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$OS_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "os module rejects empty target type argument"
else
    fail "os module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$OS_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "os module rejects empty task directory argument"
else
    fail "os module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$OS_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "Incompatible target type" "$TASK_DIR_CIDR/output.txt"; then
        pass "os module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "os module did not write expected failure notice for CIDR target"
    fi
else
    fail "os module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$OS_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_RANGE/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_RANGE/output.txt"; then
        pass "os module rejects multi-host IPv4 range with incompatible target notice"
    else
        fail "os module did not write expected failure notice for range target"
    fi
else
    fail "os module succeeded on incompatible ipv4_range target"
fi

# Test 7: Rejects url_http target type
TASK_DIR_URL="$TEST_ROOT/incompat_url"
if ! "$OS_MODULE" "http://example.com" "url_http" "$TASK_DIR_URL" >/dev/null 2>&1; then
    pass "os module rejects url_http target type"
else
    fail "os module succeeded on incompatible url_http target"
fi

# Test 8: Rejects url_https target type
TASK_DIR_URLS="$TEST_ROOT/incompat_urls"
if ! "$OS_MODULE" "https://example.com" "url_https" "$TASK_DIR_URLS" >/dev/null 2>&1; then
    pass "os module rejects url_https target type"
else
    fail "os module succeeded on incompatible url_https target"
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
    "$OS_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required OS detection tool" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "os module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "os module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mock Nmap OS Engine
# -----------------------------------------------------------------------------
MOCK_NMAP_BIN="$TEST_ROOT/mock_nmap_os.sh"
cat > "$MOCK_NMAP_BIN" <<'EOF'
#!/usr/bin/env bash
# Flexible mock Nmap binary for OS fingerprinting unit testing
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

if [[ "${MOCK_NMAP_MODE:-}" == "unknown" ]]; then
    if [[ -n "$nmap_path" ]]; then
        cat > "$nmap_path" <<NMAP_UNK_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up.
All 100 scanned ports on ${target:-127.0.0.1} are filtered.
Too many fingerprints match this host to give specific OS details.
Nmap done: 1 IP address (1 host up) scanned
NMAP_UNK_EOF
    fi
    exit 0
fi

if [[ "${MOCK_NMAP_MODE:-}" == "banner_only" ]]; then
    if [[ -n "$nmap_path" ]]; then
        cat > "$nmap_path" <<NMAP_BANNER_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up.

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned
NMAP_BANNER_EOF
    fi
    exit 0
fi

# Default Mode: emit explicit OS detection report (-O)
if [[ -n "$gnmap_path" ]]; then
    cat > "$gnmap_path" <<GNMAP_DEFAULT_EOF
# Nmap 7.94 scan initiated Sat Nov  7 21:00:00 2026 as: nmap ...
Host: ${target:-127.0.0.1} ()\tPorts: 22/open/tcp//ssh///\tOS: Linux 5.4 - 5.15\tSeq: 12345
# Nmap done
GNMAP_DEFAULT_EOF
fi

if [[ -n "$nmap_path" ]]; then
    cat > "$nmap_path" <<NMAP_DEFAULT_EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ${target:-127.0.0.1}
Host is up.

Device type: general purpose
Running: Linux 5.X|6.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.4 - 5.15
Aggressive OS guesses: Linux 5.4 - 5.15 (96%)
Network Distance: 1 hop

Nmap done: 1 IP address (1 host up) scanned
NMAP_DEFAULT_EOF
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_BIN"

ARGS_LOG="$TEST_ROOT/os_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port Integration (open_ports.txt)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port Integration (open_ports.txt)"

TARGET_BASE_DIR="$TEST_ROOT/target_upstream"
mkdir -p "$TARGET_BASE_DIR/port" "$TARGET_BASE_DIR/os"

# Test 10: Targets upstream open ports when open_ports.txt is present
printf "22\n80\n" > "$TARGET_BASE_DIR/port/open_ports.txt"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$OS_MODULE" "192.0.2.1" "ipv4" "$TARGET_BASE_DIR/os" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 22,80" "$ARGS_LOG"; then
    pass "os module targets upstream open ports from open_ports.txt (-p 22,80)"
else
    fail "os module did not target upstream ports (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 11: Skips active scan when upstream open_ports.txt is empty (0 open ports)
ZERO_BASE_DIR="$TEST_ROOT/target_zero"
mkdir -p "$ZERO_BASE_DIR/port" "$ZERO_BASE_DIR/os"
: > "$ZERO_BASE_DIR/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$OS_MODULE" "192.0.2.1" "ipv4" "$ZERO_BASE_DIR/os" >/dev/null 2>&1
)
zero_port_exit=$?

if (( zero_port_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "Port scanning detected 0 open ports" "$ZERO_BASE_DIR/os/output.txt" && \
   grep -q "COMPLETED | No open ports available for OS fingerprinting." "$ZERO_BASE_DIR/os/output.txt"; then
    pass "os module cleanly skips active probing when upstream open_ports.txt is empty"
else
    fail "os module did not handle empty upstream ports correctly (exit: $zero_port_exit)"
fi

# -----------------------------------------------------------------------------
# UT-05: Privilege & Scan Technique Mapping
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Privilege & Scan Technique Mapping"

# Test 12: Privileged execution selects -O fingerprinting
TASK_DIR_ROOT="$TEST_ROOT/priv_root"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OS_ROOT="true"
    "$OS_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_ROOT" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-O" "$ARGS_LOG" && grep -q -- "--osscan-guess" "$ARGS_LOG"; then
    pass "privileged execution invokes '-O --osscan-guess --max-os-tries 1'"
else
    fail "privileged execution did not select -O (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 13: Unprivileged execution selects banner heuristics (-sV)
TASK_DIR_UNPRIV="$TEST_ROOT/priv_unpriv"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OS_ROOT="false"
    "$OS_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_UNPRIV" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-sV" "$ARGS_LOG" && grep -q -- "--version-intensity 5" "$ARGS_LOG"; then
    pass "unprivileged execution falls back to banner heuristics ('-sV --version-intensity 5')"
else
    fail "unprivileged execution did not select -sV heuristics (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# Test 14: Honors custom scan args override
TASK_DIR_OVERRIDE="$TEST_ROOT/custom_args"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OS_SCAN_ARGS="--fuzzy"
    "$OS_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "--fuzzy" "$ARGS_LOG"; then
    pass "honors RECKON_MOCK_OS_SCAN_ARGS override"
else
    fail "did not honor custom scan args override (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-06: Flag Propagation & Options
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Flag Propagation & Options"

# Test 15: Propagates -Pn, -n, --system-dns, -T4, --min-rate, --host-timeout
TASK_DIR_FLAGS="$TEST_ROOT/flags_test"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_RATE_LIMIT=100
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_TIMEOUT=50
    "$OS_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FLAGS" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && \
   grep -q -- "-Pn" "$ARGS_LOG" && \
   grep -q -- "-n" "$ARGS_LOG" && \
   grep -q -- "--system-dns" "$ARGS_LOG" && \
   grep -q -- "-T4" "$ARGS_LOG" && \
   grep -q -- "--min-rate 100" "$ARGS_LOG" && \
   grep -q -- "--host-timeout 50s" "$ARGS_LOG"; then
    pass "propagates timing, rate limiting, and resolution flags"
else
    fail "missing expected flags in os nmap execution (saw: $(cat "$ARGS_LOG" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-07: OS Output Parsing & Artifact Generation (Stack Fingerprint & Heuristics)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: OS Output Parsing & Artifact Generation"

TASK_DIR_SCAN="$TEST_ROOT/scan_explicit"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    "$OS_MODULE" "host.example.com" "domain" "$TASK_DIR_SCAN" >/dev/null 2>&1
)
scan_status=$?

# Test 16: Exit code 0 on successful OS scan
if (( scan_status == 0 )); then
    pass "os scan executes successfully and exits with code 0"
else
    fail "os scan failed with exit code $scan_status"
fi

# Test 17: Emits key-value records to os_info.txt
OS_INFO_FILE="$TASK_DIR_SCAN/os_info.txt"
if [[ -f "$OS_INFO_FILE" ]] && \
   grep -q "OS: Linux 5.4 - 5.15" "$OS_INFO_FILE" && \
   grep -q "Running: Linux 5.X|6.X" "$OS_INFO_FILE" && \
   grep -q "Device: general purpose" "$OS_INFO_FILE" && \
   grep -q "CPE: cpe:/o:linux:linux_kernel:5" "$OS_INFO_FILE"; then
    pass "os_info.txt contains parsed OS details, kernel family, device, and CPE"
else
    fail "os_info.txt content did not match expected structure (saw: $(cat "$OS_INFO_FILE" 2>/dev/null))"
fi

# Test 18: Emits structured output.txt with section metrics and completion footer
OUTPUT_FILE="$TASK_DIR_SCAN/output.txt"
if [[ -f "$OUTPUT_FILE" ]] && \
   grep -q "RECKON Network Reconnaissance - OS Detection" "$OUTPUT_FILE" && \
   grep -q "OS Details               : Linux 5.4 - 5.15" "$OUTPUT_FILE" && \
   grep -q "OS Family / Kernel       : Linux 5.X|6.X" "$OUTPUT_FILE" && \
   grep -q "COMPLETED | Identified OS: Linux 5.4 - 5.15." "$OUTPUT_FILE"; then
    pass "output.txt contains structured findings, target metadata, and completion footer"
else
    fail "output.txt format did not match expected structure"
fi

# Test 19: File permissions enforced to 0640
file_perm="$(stat -c '%a' "$OS_INFO_FILE" 2>/dev/null || stat -f '%Lp' "$OS_INFO_FILE" 2>/dev/null || echo "unknown")"
if [[ "$file_perm" == "640" ]]; then
    pass "os_info.txt permissions restricted to 0640"
else
    fail "os_info.txt permissions ($file_perm) are not 0640"
fi

# -----------------------------------------------------------------------------
# UT-08: Secondary Heuristic Extraction (Banner-Based Fallback)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Secondary Heuristic Extraction (Banner-Based Fallback)"

TASK_DIR_BANNER="$TEST_ROOT/scan_banner"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_MODE="banner_only"
    "$OS_MODULE" "10.0.0.2" "ipv4" "$TASK_DIR_BANNER" >/dev/null 2>&1
)

# Test 20: Extracts OS from Service Info / SSH banner
if [[ -f "$TASK_DIR_BANNER/os_info.txt" ]] && \
   grep -q "OS: Linux" "$TASK_DIR_BANNER/os_info.txt" && \
   grep -q "CPE: cpe:/o:linux:linux_kernel" "$TASK_DIR_BANNER/os_info.txt"; then
    pass "extracts OS family and CPE from service banner heuristics"
else
    fail "banner heuristic extraction failed (saw: $(cat "$TASK_DIR_BANNER/os_info.txt" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
# UT-09: Unidentified OS Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Unidentified OS Handling"

TASK_DIR_UNK="$TEST_ROOT/scan_unknown"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_MODE="unknown"
    "$OS_MODULE" "192.0.2.55" "ipv4" "$TASK_DIR_UNK" >/dev/null 2>&1
)
unk_status=$?

# Test 21: Handles unidentifiable OS gracefully
if (( unk_status == 0 )) && [[ -f "$TASK_DIR_UNK/output.txt" ]] && \
   grep -q "Unknown (insufficient fingerprint responses)" "$TASK_DIR_UNK/output.txt" && \
   grep -q "COMPLETED | Operating system could not be fingerprinted." "$TASK_DIR_UNK/output.txt"; then
    pass "unidentified OS handled cleanly with Unknown report and completed status"
else
    fail "unidentified OS handling failed (exit: $unk_status)"
fi

# -----------------------------------------------------------------------------
# UT-10: Catastrophic Execution Failure
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-10: Catastrophic Execution Failure"

TASK_DIR_FAIL="$TEST_ROOT/scan_fail"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_FORCE_FAIL=18
    "$OS_MODULE" "192.0.2.1" "ipv4" "$TASK_DIR_FAIL" >/dev/null 2>&1
)
fail_exit=$?

# Test 22: Returns nmap exit code and logs failure notice
if (( fail_exit == 18 )) && [[ -f "$TASK_DIR_FAIL/output.txt" ]] && grep -q "Nmap OS scan execution failed with exit code 18" "$TASK_DIR_FAIL/output.txt"; then
    pass "catastrophic nmap failure returns exit code 18 and logs failure notice"
else
    fail "did not handle catastrophic failure properly (exit: $fail_exit)"
fi

# -----------------------------------------------------------------------------
# UT-11: Engine Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-11: Engine Integration"

# Test 23: Dispatches seamlessly through engine_run
ENGINE_TEST_DIR="$TEST_ROOT/engine_run_os"
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
    engine_resolve_modules "false" "false" "os" ""
    engine_plan_scan
    engine_run "false" "$ENGINE_TEST_DIR" 0 0
)
engine_exit=$?

if (( engine_exit == 0 )) && [[ -f "$ENGINE_TEST_DIR/192.0.2.1/os/os_info.txt" ]] && [[ -f "$ENGINE_TEST_DIR/192.0.2.1/os/output.txt" ]]; then
    pass "engine_run dispatches os module and creates task artifacts"
else
    fail "engine_run integration failed (exit: $engine_exit)"
fi

test_summary
