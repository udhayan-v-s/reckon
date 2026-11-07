#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Network Module Common Library Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/network/common.sh
if ! source "$PROJECT_ROOT/modules/network/common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-net-common-test.XXXXXX")" || {
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

    printf '%s\n' "Network module common library unit tests completed."
}

printf '%s\n' "RECKON - Network Module Common Library Unit Tests"
printf '%s\n' "------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Initialization & Argument Validation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Initialization & Argument Validation"

# Test 1: Idempotent re-sourcing guard
if source "$PROJECT_ROOT/modules/network/common.sh"; then
    pass "Idempotent re-sourcing causes no errors or conflicts"
else
    fail "Re-sourcing modules/network/common.sh failed"
fi

# Test 2: Rejects insufficient arguments (< 3 arguments)
if ! net_mod_init "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    if [[ -n "$NET_MOD_ERROR" ]]; then
        pass "net_mod_init rejects insufficient arguments (< 3) and records NET_MOD_ERROR"
    else
        fail "net_mod_init failed without recording error message"
    fi
else
    fail "net_mod_init succeeded with only 2 arguments"
fi

# Test 3: Rejects empty target string
if ! net_mod_init "" "ipv4" "$TEST_ROOT/out" >/dev/null 2>&1; then
    pass "net_mod_init rejects empty target argument"
else
    fail "net_mod_init accepted empty target"
fi

# Test 4: Rejects empty target type
if ! net_mod_init "192.168.1.1" "" "$TEST_ROOT/out" >/dev/null 2>&1; then
    pass "net_mod_init rejects empty target type argument"
else
    fail "net_mod_init accepted empty target type"
fi

# Test 5: Rejects empty task output directory
if ! net_mod_init "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "net_mod_init rejects empty task directory argument"
else
    fail "net_mod_init accepted empty task directory"
fi

# Test 6: Valid arguments export runtime context variables
TASK_DIR_1="$TEST_ROOT/task_out_1"
if net_mod_init "192.168.1.1" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    if [[ "$NET_TARGET" == "192.168.1.1" && \
          "$NET_TARGET_TYPE" == "ipv4" && \
          "$NET_TASK_DIR" == "$TASK_DIR_1" && \
          "$NET_OUTPUT_FILE" == "${TASK_DIR_1}/output.txt" ]]; then
        pass "net_mod_init exports NET_TARGET, NET_TARGET_TYPE, NET_TASK_DIR, and NET_OUTPUT_FILE"
    else
        fail "net_mod_init variable assignment mismatch: target=$NET_TARGET, type=$NET_TARGET_TYPE, dir=$NET_TASK_DIR"
    fi
else
    fail "net_mod_init failed with valid arguments"
fi

# Test 7: Automatically creates non-existent task directory with secure mode
TASK_DIR_NEW="$TEST_ROOT/nested/task_dir"
if net_mod_init "10.0.0.1" "ipv4" "$TASK_DIR_NEW" >/dev/null 2>&1; then
    if [[ -d "$TASK_DIR_NEW" ]]; then
        pass "net_mod_init creates non-existent task output directory automatically"
    else
        fail "net_mod_init did not create task output directory on disk"
    fi
else
    fail "net_mod_init failed when directory did not pre-exist"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Classification Helpers
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Classification Helpers"

# Test 8: net_mod_is_ip classification
net_mod_init "192.168.1.1" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1
is_ip_ipv4=$(net_mod_is_ip && echo true || echo false)

net_mod_init "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_1" >/dev/null 2>&1
is_ip_cidr=$(net_mod_is_ip && echo true || echo false)

net_mod_init "example.com" "domain" "$TASK_DIR_1" >/dev/null 2>&1
is_ip_domain=$(net_mod_is_ip && echo true || echo false)

if [[ "$is_ip_ipv4" == "true" && "$is_ip_cidr" == "true" && "$is_ip_domain" == "false" ]]; then
    pass "net_mod_is_ip correctly identifies IP types and rejects domain targets"
else
    fail "net_mod_is_ip classification mismatch: ipv4=$is_ip_ipv4, cidr=$is_ip_cidr, domain=$is_ip_domain"
fi

# Test 9: net_mod_is_cidr classification
net_mod_init "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_1" >/dev/null 2>&1
is_cidr_yes=$(net_mod_is_cidr && echo true || echo false)

net_mod_init "192.168.1.1" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1
is_cidr_no=$(net_mod_is_cidr && echo true || echo false)

if [[ "$is_cidr_yes" == "true" && "$is_cidr_no" == "false" ]]; then
    pass "net_mod_is_cidr identifies ipv4_cidr and rejects single IPs"
else
    fail "net_mod_is_cidr mismatch: cidr=$is_cidr_yes, single=$is_cidr_no"
fi

# Test 10: net_mod_is_range classification
net_mod_init "192.168.1.1-192.168.1.50" "ipv4_range" "$TASK_DIR_1" >/dev/null 2>&1
is_range_yes=$(net_mod_is_range && echo true || echo false)

net_mod_init "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_1" >/dev/null 2>&1
is_range_no=$(net_mod_is_range && echo true || echo false)

if [[ "$is_range_yes" == "true" && "$is_range_no" == "false" ]]; then
    pass "net_mod_is_range identifies ipv4_range and rejects CIDRs"
else
    fail "net_mod_is_range mismatch: range=$is_range_yes, cidr=$is_range_no"
fi

# Test 11: net_mod_is_subnet classification
net_mod_init "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_1" >/dev/null 2>&1
is_sub_cidr=$(net_mod_is_subnet && echo true || echo false)

net_mod_init "192.168.1.1-192.168.1.50" "ipv4_range" "$TASK_DIR_1" >/dev/null 2>&1
is_sub_range=$(net_mod_is_subnet && echo true || echo false)

net_mod_init "192.168.1.1" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1
is_sub_single=$(net_mod_is_subnet && echo true || echo false)

if [[ "$is_sub_cidr" == "true" && "$is_sub_range" == "true" && "$is_sub_single" == "false" ]]; then
    pass "net_mod_is_subnet identifies CIDR blocks and IP ranges as multi-host subnets"
else
    fail "net_mod_is_subnet mismatch: cidr=$is_sub_cidr, range=$is_sub_range, single=$is_sub_single"
fi

# Test 12: net_mod_is_single_host classification
net_mod_init "192.168.1.1" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1
is_single_ip=$(net_mod_is_single_host && echo true || echo false)

net_mod_init "example.com" "domain" "$TASK_DIR_1" >/dev/null 2>&1
is_single_domain=$(net_mod_is_single_host && echo true || echo false)

net_mod_init "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_1" >/dev/null 2>&1
is_single_cidr=$(net_mod_is_single_host && echo true || echo false)

if [[ "$is_single_ip" == "true" && "$is_single_domain" == "true" && "$is_single_cidr" == "false" ]]; then
    pass "net_mod_is_single_host identifies single IPs and domains, rejecting subnets"
else
    fail "net_mod_is_single_host mismatch: ip=$is_single_ip, domain=$is_single_domain, cidr=$is_single_cidr"
fi

# Test 13: net_mod_is_domain classification
net_mod_init "example.com" "domain" "$TASK_DIR_1" >/dev/null 2>&1
is_dom_domain=$(net_mod_is_domain && echo true || echo false)

net_mod_init "myhost" "hostname" "$TASK_DIR_1" >/dev/null 2>&1
is_dom_host=$(net_mod_is_domain && echo true || echo false)

net_mod_init "192.168.1.1" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1
is_dom_ip=$(net_mod_is_domain && echo true || echo false)

if [[ "$is_dom_domain" == "true" && "$is_dom_host" == "true" && "$is_dom_ip" == "false" ]]; then
    pass "net_mod_is_domain identifies domain and hostname targets, rejecting raw IPs"
else
    fail "net_mod_is_domain mismatch: domain=$is_dom_domain, host=$is_dom_host, ip=$is_dom_ip"
fi

# -----------------------------------------------------------------------------
# UT-03: Tool Inspection & Fallback Selection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Tool Inspection & Fallback Selection"

# Test 14: net_mod_has_tool identifies existing binary
if net_mod_has_tool "bash"; then
    pass "net_mod_has_tool returns 0 for existing system binary"
else
    fail "net_mod_has_tool failed to find bash"
fi

# Test 15: net_mod_has_tool returns 1 for missing binary
if ! net_mod_has_tool "definitely_nonexistent_binary_xyz_12345"; then
    pass "net_mod_has_tool returns non-zero for missing binary"
else
    fail "net_mod_has_tool reported missing tool as present"
fi

# Test 16: net_mod_require_tool succeeds when tool is present
if net_mod_require_tool "bash" >/dev/null 2>&1; then
    pass "net_mod_require_tool succeeds when required tool exists"
else
    fail "net_mod_require_tool failed on available tool"
fi

# Test 17: net_mod_require_tool fails and records error when tool is missing
if ! net_mod_require_tool "missing_recon_binary_12345" >/dev/null 2>&1; then
    if [[ "$NET_MOD_ERROR" == *"missing_recon_binary_12345"* ]]; then
        pass "net_mod_require_tool reports error and populates NET_MOD_ERROR when tool is absent"
    else
        fail "net_mod_require_tool failed to set descriptive error message"
    fi
else
    fail "net_mod_require_tool succeeded on non-existent tool"
fi

# Test 18: net_mod_select_tool selects primary tool if present
selected_tool="$(net_mod_select_tool "bash" "sh" 2>/dev/null)"
if [[ "$selected_tool" == "bash" ]]; then
    pass "net_mod_select_tool selects primary tool when available"
else
    fail "net_mod_select_tool selected $selected_tool (expected bash)"
fi

# Test 19: net_mod_select_tool falls back to secondary tool if primary is missing
selected_fallback="$(net_mod_select_tool "missing_tool_abc" "bash" 2>/dev/null)"
if [[ "$selected_fallback" == "bash" ]]; then
    pass "net_mod_select_tool falls back to secondary tool when primary is missing"
else
    fail "net_mod_select_tool fallback mismatch: selected $selected_fallback (expected bash)"
fi

# Test 20: net_mod_select_tool fails if both tools are missing
if ! net_mod_select_tool "missing_one" "missing_two" >/dev/null 2>&1; then
    if [[ "$NET_MOD_ERROR" == *"missing_one"* && "$NET_MOD_ERROR" == *"missing_two"* ]]; then
        pass "net_mod_select_tool fails with clear error when both options are missing"
    else
        fail "net_mod_select_tool did not record missing tools in NET_MOD_ERROR"
    fi
else
    fail "net_mod_select_tool succeeded despite missing both tools"
fi

# -----------------------------------------------------------------------------
# UT-04: Structured Output & Finding Serialization
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Structured Output & Finding Serialization"

TASK_DIR_SERIAL="$TEST_ROOT/task_out_serial"
net_mod_init "192.168.1.100" "ipv4" "$TASK_DIR_SERIAL" >/dev/null 2>&1

# Test 21: net_mod_write_header writes header to output.txt
net_mod_write_header "testmod" "Test Module Title"
if [[ -f "$NET_OUTPUT_FILE" ]] && grep -q "RECKON Network Reconnaissance - Test Module Title (testmod)" "$NET_OUTPUT_FILE" && grep -q "Target: 192.168.1.100" "$NET_OUTPUT_FILE"; then
    pass "net_mod_write_header formats and writes standard reconnaissance header banner"
else
    fail "net_mod_write_header missing expected header content in $NET_OUTPUT_FILE"
fi

# Test 22: net_mod_write_section writes section banner
net_mod_write_section "Discovered Open Ports"
if grep -q "\[--- Discovered Open Ports ---\]" "$NET_OUTPUT_FILE"; then
    pass "net_mod_write_section formats and writes structured section divider"
else
    fail "net_mod_write_section missing expected section divider in $NET_OUTPUT_FILE"
fi

# Test 23: net_mod_write_kv writes aligned key-value pair
net_mod_write_kv "Port 22/tcp" "Open (OpenSSH 8.9p1)"
if grep -q "  Port 22/tcp              : Open (OpenSSH 8.9p1)" "$NET_OUTPUT_FILE"; then
    pass "net_mod_write_kv formats and writes aligned key-value finding"
else
    fail "net_mod_write_kv missing expected key-value alignment in $NET_OUTPUT_FILE"
fi

# Test 24: net_mod_write_raw appends raw text
net_mod_write_raw "Raw banner data: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
if grep -q "Raw banner data: SSH-2.0-OpenSSH_8.9p1" "$NET_OUTPUT_FILE"; then
    pass "net_mod_write_raw appends verbatim finding data to output.txt"
else
    fail "net_mod_write_raw missing raw text in $NET_OUTPUT_FILE"
fi

# Test 25: net_mod_write_footer writes completion status and footer
net_mod_write_footer "COMPLETED" "1 open port discovered."
if grep -q "Status: COMPLETED | 1 open port discovered." "$NET_OUTPUT_FILE"; then
    pass "net_mod_write_footer formats and writes execution summary and footer banner"
else
    fail "net_mod_write_footer missing expected footer in $NET_OUTPUT_FILE"
fi

# Test 26: net_mod_finish sets permissions and preserves exit code
if net_mod_finish 0; then
    file_perm="$(stat -c "%a" "$NET_OUTPUT_FILE" 2>/dev/null || stat -f "%Lp" "$NET_OUTPUT_FILE" 2>/dev/null)"
    if [[ "$file_perm" == "640" ]]; then
        pass "net_mod_finish secures output file permissions (0640) and preserves exit code 0"
    else
        fail "net_mod_finish set unexpected permissions: $file_perm (expected 640)"
    fi
else
    fail "net_mod_finish returned non-zero on 0 argument"
fi

# Test 27: net_mod_finish propagates non-zero exit code
ret_code=0
net_mod_finish 42 || ret_code=$?
if (( ret_code == 42 )); then
    pass "net_mod_finish propagates non-zero return code (42)"
else
    fail "net_mod_finish returned $ret_code (expected 42)"
fi

test_summary
