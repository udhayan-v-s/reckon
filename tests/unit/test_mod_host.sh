#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Host Discovery Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

HOST_MODULE="$PROJECT_ROOT/modules/network/host.sh"
readonly HOST_MODULE

if [[ ! -f "$HOST_MODULE" || ! -x "$HOST_MODULE" ]]; then
    printf 'Error: Host discovery module missing or not executable at %s\n' "$HOST_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-host-test.XXXXXX")" || {
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

    printf '%s\n' "Host discovery module unit tests completed."
}

printf '%s\n' "RECKON - Host Discovery Module Unit Tests"
printf '%s\n' "-----------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$HOST_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "host module rejects execution with insufficient arguments (< 3)"
else
    fail "host module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$HOST_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "host module rejects empty target argument"
else
    fail "host module accepted empty target"
fi

# Test 3: Automatically creates task output directory if missing
TASK_DIR_AUTO="$TEST_ROOT/auto_created_dir"
if (
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="echo"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="true"
    "$HOST_MODULE" "127.0.0.1" "ipv4" "$TASK_DIR_AUTO" >/dev/null 2>&1
); then
    if [[ -d "$TASK_DIR_AUTO" && -f "$TASK_DIR_AUTO/output.txt" ]]; then
        pass "host module creates missing task directory and output.txt on invocation"
    else
        fail "host module did not create directory or output.txt"
    fi
else
    fail "host module invocation failed during directory creation check"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Range Parsing Helper (_host_parse_range)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Range Parsing Helper"

# Source module in subshell to test internal helper directly
# Test 4: Parses full start-end IP range
range_res_1="$(
    # shellcheck source=modules/network/common.sh
    source "$PROJECT_ROOT/modules/network/common.sh"
    # shellcheck source=modules/network/host.sh
    source "$HOST_MODULE"
    _host_parse_range "192.168.1.1-192.168.1.50"
)"
if [[ "$range_res_1" == "192.168.1.1 192.168.1.50" ]]; then
    pass "_host_parse_range parses full start-end IP range"
else
    fail "_host_parse_range produced '$range_res_1' (expected '192.168.1.1 192.168.1.50')"
fi

# Test 5: Parses short end octet range
range_res_2="$(
    # shellcheck source=modules/network/common.sh
    source "$PROJECT_ROOT/modules/network/common.sh"
    # shellcheck source=modules/network/host.sh
    source "$HOST_MODULE"
    _host_parse_range "10.0.0.5-25"
)"
if [[ "$range_res_2" == "10.0.0.5 10.0.0.25" ]]; then
    pass "_host_parse_range expands short end octet to full IP"
else
    fail "_host_parse_range produced '$range_res_2' (expected '10.0.0.5 10.0.0.25')"
fi

# -----------------------------------------------------------------------------
# UT-03: Fping Discovery Sweep (Mocked)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Fping Discovery Sweep (Mocked)"

TASK_DIR_FPING="$TEST_ROOT/fping_sweep"
MOCK_FPING_SCRIPT="$TEST_ROOT/mock_fping.sh"

cat > "$MOCK_FPING_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Mock fping: emits live hosts
printf "192.168.1.1\n192.168.1.5\n192.168.1.20\n"
exit 0
EOF
chmod +x "$MOCK_FPING_SCRIPT"

MOCK_NMAP_NOOP="$TEST_ROOT/mock_nmap_noop.sh"
cat > "$MOCK_NMAP_NOOP" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$MOCK_NMAP_NOOP"

# Test 6: Executes fping for CIDR block and collects live hosts
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="$MOCK_FPING_SCRIPT"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_NOOP"
    "$HOST_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_FPING" >/dev/null 2>&1
)
fping_status=$?

if (( fping_status == 0 )) && \
   [[ -f "$TASK_DIR_FPING/hosts_live.txt" ]] && \
   grep -q "192.168.1.1" "$TASK_DIR_FPING/hosts_live.txt" && \
   grep -q "192.168.1.5" "$TASK_DIR_FPING/hosts_live.txt" && \
   grep -q "192.168.1.20" "$TASK_DIR_FPING/hosts_live.txt" && \
   grep -q "Total Live Hosts         : 3" "$TASK_DIR_FPING/output.txt"; then
    pass "host module discovers and logs live hosts via fping sweep across CIDR"
else
    fail "host module failed fping sweep parsing on CIDR target"
fi

# Test 7: Executes fping for IPv4 range target
TASK_DIR_RANGE="$TEST_ROOT/fping_range"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="$MOCK_FPING_SCRIPT"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_NOOP"
    "$HOST_MODULE" "192.168.1.1-192.168.1.50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1
)
if [[ -f "$TASK_DIR_RANGE/hosts_live.txt" ]] && grep -q "192.168.1.5" "$TASK_DIR_RANGE/hosts_live.txt"; then
    pass "host module discovers live hosts via fping sweep across IPv4 range"
else
    fail "host module failed fping sweep on IPv4 range"
fi

# -----------------------------------------------------------------------------
# UT-04: Nmap Multi-Probe Discovery Sweep (Mocked)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Nmap Multi-Probe Discovery Sweep (Mocked)"

TASK_DIR_NMAP="$TEST_ROOT/nmap_sweep"
MOCK_NMAP_SCRIPT="$TEST_ROOT/mock_nmap.sh"

cat > "$MOCK_NMAP_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Mock nmap -sn: generates grepable output file passed via -oG
gnmap_out=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-oG" ]]; then
        gnmap_out="$2"
        shift 2
    else
        shift
    fi
done

if [[ -n "$gnmap_out" ]]; then
    cat > "$gnmap_out" <<'GNMAP'
# Nmap 7.94SVN scan initiated
Host: 10.0.0.1 (gateway.lan)	Status: Up
Host: 10.0.0.2 ()	Status: Down
Host: 10.0.0.50 (webserver.lan)	Status: Up
Host: 10.0.0.100 (database.lan)	Status: Up
# Nmap done
GNMAP
fi
exit 0
EOF
chmod +x "$MOCK_NMAP_SCRIPT"

MOCK_FPING_NOOP="$TEST_ROOT/mock_fping_noop.sh"
cat > "$MOCK_FPING_NOOP" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$MOCK_FPING_NOOP"

# Test 8: Nmap discovery extracts live hosts from gnmap output
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="$MOCK_FPING_NOOP"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SCRIPT"
    "$HOST_MODULE" "10.0.0.0/24" "ipv4_cidr" "$TASK_DIR_NMAP" >/dev/null 2>&1
)
if [[ -f "$TASK_DIR_NMAP/hosts_live.txt" ]] && \
   grep -q "10.0.0.1" "$TASK_DIR_NMAP/hosts_live.txt" && \
   grep -q "10.0.0.50" "$TASK_DIR_NMAP/hosts_live.txt" && \
   grep -q "10.0.0.100" "$TASK_DIR_NMAP/hosts_live.txt" && \
   ! grep -q "10.0.0.2" "$TASK_DIR_NMAP/hosts_live.txt"; then
    pass "host module parses nmap grepable output to extract only 'Status: Up' live hosts"
else
    fail "host module failed to parse nmap gnmap output correctly"
fi

# Test 9: Deduplication across dual discovery engines (fping + nmap finding same host)
TASK_DIR_DEDUP="$TEST_ROOT/dedup_sweep"
MOCK_FPING_OVERLAP="$TEST_ROOT/mock_fping_overlap.sh"
cat > "$MOCK_FPING_OVERLAP" <<'EOF'
#!/usr/bin/env bash
printf "10.0.0.1\n10.0.0.25\n"
exit 0
EOF
chmod +x "$MOCK_FPING_OVERLAP"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="$MOCK_FPING_OVERLAP"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_SCRIPT"
    "$HOST_MODULE" "10.0.0.0/24" "ipv4_cidr" "$TASK_DIR_DEDUP" >/dev/null 2>&1
)
# 10.0.0.1 is found by BOTH tools. It should appear only ONCE.
# Total unique: 10.0.0.1, 10.0.0.25 (fping) + 10.0.0.50, 10.0.0.100 (nmap) = 4 hosts.
unique_count=$(wc -l < "$TASK_DIR_DEDUP/hosts_live.txt" | tr -d '[:space:]')
occurrences_of_1=$(grep -c -x "10.0.0.1" "$TASK_DIR_DEDUP/hosts_live.txt")

if (( unique_count == 4 && occurrences_of_1 == 1 )); then
    pass "host module combines and deduplicates live hosts across both fping and nmap discovery engines"
else
    fail "host module failed deduplication: count=$unique_count (expected 4), occurrences of 10.0.0.1=$occurrences_of_1 (expected 1)"
fi

# -----------------------------------------------------------------------------
# UT-05: Missing Tools & Zero Hosts Scenarios
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Missing Tools & Zero Hosts Scenarios"

# Test 10: Zero live hosts discovered reports clean completion without failure
TASK_DIR_EMPTY="$TEST_ROOT/empty_sweep"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="$MOCK_FPING_NOOP"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_NOOP"
    "$HOST_MODULE" "192.168.200.0/24" "ipv4_cidr" "$TASK_DIR_EMPTY" >/dev/null 2>&1
)
empty_status=$?

if (( empty_status == 0 )) && \
   grep -q "Total Live Hosts         : 0" "$TASK_DIR_EMPTY/output.txt" && \
   grep -q "Discovered Hosts         : None (no responsive systems detected)" "$TASK_DIR_EMPTY/output.txt" && \
   [[ ! -s "$TASK_DIR_EMPTY/hosts_live.txt" ]]; then
    pass "host module handles zero responsive hosts cleanly with COMPLETED status"
else
    fail "host module failed zero responsive hosts reporting"
fi

# Test 11: Missing both discovery tools reports FAILED on subnets
TASK_DIR_MISSING="$TEST_ROOT/missing_sweep"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_FPING_BIN="nonexistent_fping_cmd_xyz"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="nonexistent_nmap_cmd_xyz"
    "$HOST_MODULE" "192.168.100.0/24" "ipv4_cidr" "$TASK_DIR_MISSING" >/dev/null 2>&1
)
missing_status=$?

if (( missing_status != 0 )) && grep -q "Status: FAILED" "$TASK_DIR_MISSING/output.txt"; then
    pass "host module returns failure status when discovery tools are missing"
else
    fail "host module did not return failure when tools were missing"
fi

# -----------------------------------------------------------------------------
# UT-06: Artifacts Generation & File Permissions
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Artifacts Generation & File Permissions"

# Test 12: output.txt contains standard RECKON header, section dividers, and footer
if grep -q "RECKON Network Reconnaissance - Host Discovery (host)" "$TASK_DIR_DEDUP/output.txt" && \
   grep -q "\[--- Target Information ---\]" "$TASK_DIR_DEDUP/output.txt" && \
   grep -q "\[--- Discovered Live Hosts ---\]" "$TASK_DIR_DEDUP/output.txt" && \
   grep -q "Status: COMPLETED | Discovered 4 active live host(s)." "$TASK_DIR_DEDUP/output.txt"; then
    pass "host module generates standardized output.txt with header, sections, and footer"
else
    fail "host module output.txt structure mismatch"
fi

# Test 13: hosts_live.txt permissions are secured (0640)
live_perm="$(stat -c "%a" "$TASK_DIR_DEDUP/hosts_live.txt" 2>/dev/null || stat -f "%Lp" "$TASK_DIR_DEDUP/hosts_live.txt" 2>/dev/null)"
if [[ "$live_perm" == "640" ]]; then
    pass "host module sets secure permissions (0640) on hosts_live.txt artifact"
else
    fail "host module hosts_live.txt permissions mismatch: $live_perm (expected 640)"
fi

test_summary
