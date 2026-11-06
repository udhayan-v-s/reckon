#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Dependency management library unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/term.sh
if ! source "$PROJECT_ROOT/lib/term.sh"; then
    printf 'Error: Unable to load terminal presentation library component.\n' >&2
    exit 1
fi

# shellcheck source=lib/deps.sh
if ! source "$PROJECT_ROOT/lib/deps.sh"; then
    printf 'Error: Unable to load dependency management library component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-deps-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
    rm -rf -- "$TEST_ROOT"
}

trap cleanup EXIT

pass() { printf '[PASS] %s\n' "$1"; ((PASS_COUNT += 1)); }
fail() { printf '[FAIL] %s\n' "$1" >&2; ((FAIL_COUNT += 1)); }

test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Dependency library unit tests completed."
}

printf '%s\n' "RECKON - Dependency Library Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Initialization & Include Guards
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Initialization & Include Guards"

# Test 1: Idempotent re-sourcing guard
if source "$PROJECT_ROOT/lib/deps.sh"; then
    pass "Idempotent re-sourcing causes no errors or conflicts"
else
    fail "Re-sourcing lib/deps.sh failed"
fi

# Test 2: deps_init clears state
DEPS_AVAILABLE_TOOLS=("dummy1")
DEPS_MISSING_TOOLS=("dummy2")
DEPS_CHECKED_MODULES=("dummy_mod")
DEPS_ERROR="stale error"
deps_init
if (( ${#DEPS_AVAILABLE_TOOLS[@]} == 0 && ${#DEPS_MISSING_TOOLS[@]} == 0 && ${#DEPS_CHECKED_MODULES[@]} == 0 )) && [[ -z "$DEPS_ERROR" ]]; then
    pass "deps_init resets all tracking arrays and error variables"
else
    fail "deps_init failed to clear state"
fi

# -----------------------------------------------------------------------------
# UT-02: Tool Metadata & Functional Descriptions (deps_get_tool_desc)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Tool Metadata & Functional Descriptions (deps_get_tool_desc)"

# Test 3: Functional descriptions for all 19 tools
all_desc_valid=true
contains_install_hint=false

while IFS= read -r tool; do
    desc="$(deps_get_tool_desc "$tool")"
    if [[ -z "$desc" ]]; then
        all_desc_valid=false
    fi
    # Verify no package manager or install instructions are present
    if [[ "$desc" =~ (apt|yum|dnf|pacman|brew|install|apk) ]]; then
        contains_install_hint=true
    fi
done < <(deps_get_all_tools)

if [[ "$all_desc_valid" == true ]]; then
    pass "deps_get_tool_desc returns descriptions for all canonical tools"
else
    fail "deps_get_tool_desc returned empty description for a canonical tool"
fi

# Test 4: Verify strictly no installation commands in descriptions
if [[ "$contains_install_hint" == false ]]; then
    pass "Tool descriptions contain purely functional descriptions with zero install commands"
else
    fail "Tool descriptions unexpectedly contained package installation commands"
fi

# Test 5: Fallback description for unknown tools
unknown_desc="$(deps_get_tool_desc "some_unrecognized_custom_binary")"
if [[ "$unknown_desc" == "External reconnaissance utility" ]]; then
    pass "deps_get_tool_desc returns generic fallback for unknown tool"
else
    fail "deps_get_tool_desc fallback mismatch: '$unknown_desc'"
fi

# -----------------------------------------------------------------------------
# UT-03: Canonical Inventory & Mappings
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Canonical Inventory & Mappings"

# Test 6: Exactly 25 modules in canonical inventory
module_count=0
while IFS= read -r mod; do
    ((module_count += 1))
done < <(deps_get_all_modules)

if (( module_count == 25 )); then
    pass "deps_get_all_modules outputs exactly 25 canonical modules"
else
    fail "deps_get_all_modules count mismatch: expected 25, got $module_count"
fi

# Test 7: Exactly 19 unique external tools
tool_count=0
while IFS= read -r tool; do
    ((tool_count += 1))
done < <(deps_get_all_tools)

if (( tool_count == 19 )); then
    pass "deps_get_all_tools outputs exactly 19 canonical tools"
else
    fail "deps_get_all_tools count mismatch: expected 19, got $tool_count"
fi

# Test 8: All 25 modules map to non-empty tool lists
all_mapped=true
while IFS= read -r mod; do
    mod_tools=()
    while IFS= read -r t; do
        [[ -n "$t" ]] && mod_tools+=("$t")
    done < <(deps_get_module_tools "$mod")

    if (( ${#mod_tools[@]} == 0 )); then
        all_mapped=false
    fi
done < <(deps_get_all_modules)

if [[ "$all_mapped" == true ]]; then
    pass "All 25 modules successfully resolve to non-empty tool requirements"
else
    fail "One or more modules failed to resolve tool requirements"
fi

# Test 9: deps_get_module_tools rejects invalid module
if ! deps_get_module_tools "non_existent_module_xyz" >/dev/null 2>&1; then
    if [[ "$DEPS_ERROR" == *"Invalid module identifier"* ]]; then
        pass "deps_get_module_tools rejects invalid module and records DEPS_ERROR"
    else
        fail "deps_get_module_tools did not set expected DEPS_ERROR: $DEPS_ERROR"
    fi
else
    fail "deps_get_module_tools accepted invalid module identifier"
fi

# Test 10: deps_get_module_tools rejects empty module string
if ! deps_get_module_tools "" >/dev/null 2>&1; then
    if [[ -n "$DEPS_ERROR" ]]; then
        pass "deps_get_module_tools rejects empty module identifier"
    else
        fail "deps_get_module_tools did not record DEPS_ERROR on empty module"
    fi
else
    fail "deps_get_module_tools accepted empty module identifier"
fi

# -----------------------------------------------------------------------------
# UT-04: Single Tool Presence Detection (deps_has_tool)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Single Tool Presence Detection (deps_has_tool)"

# Test 11: deps_has_tool detects existing binary
if deps_has_tool "bash"; then
    pass "deps_has_tool detects standard system executable 'bash'"
else
    fail "deps_has_tool failed to detect 'bash'"
fi

# Test 12: deps_has_tool detects missing binary
if ! deps_has_tool "non_existent_recon_binary_99999"; then
    pass "deps_has_tool returns non-zero for missing binary"
else
    fail "deps_has_tool falsely reported missing binary as present"
fi

# Test 13: deps_has_tool returns non-zero on empty input
if ! deps_has_tool ""; then
    pass "deps_has_tool returns non-zero on empty tool string"
else
    fail "deps_has_tool accepted empty string"
fi

# -----------------------------------------------------------------------------
# UT-05: Multi-Tool Dependency Checking (deps_check_tools)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Multi-Tool Dependency Checking (deps_check_tools)"

# Test 14: Empty tool list returns 0
deps_init
if deps_check_tools; then
    if (( ${#DEPS_AVAILABLE_TOOLS[@]} == 0 && ${#DEPS_MISSING_TOOLS[@]} == 0 )); then
        pass "deps_check_tools on empty argument list returns 0 with empty arrays"
    else
        fail "deps_check_tools on empty arguments populated arrays unexpectedly"
    fi
else
    fail "deps_check_tools on empty argument list returned non-zero"
fi

# Test 15: Controlled environment with mock binaries
MOCK_BIN_DIR="$TEST_ROOT/mock_bin"
mkdir -p "$MOCK_BIN_DIR"
touch "$MOCK_BIN_DIR/mock_nmap" "$MOCK_BIN_DIR/mock_curl"
chmod 755 "$MOCK_BIN_DIR/mock_nmap" "$MOCK_BIN_DIR/mock_curl"

# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_BIN_DIR"
    deps_init
    deps_check_tools "mock_nmap" "mock_curl"
    (( ${#DEPS_AVAILABLE_TOOLS[@]} == 2 && ${#DEPS_MISSING_TOOLS[@]} == 0 ))
); then
    pass "deps_check_tools identifies all available tools in controlled PATH"
else
    fail "deps_check_tools failed to identify mock tools in controlled PATH"
fi

# Test 16: Controlled environment with missing tools
# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_BIN_DIR"
    deps_init
    ! deps_check_tools "mock_nmap" "mock_missing_tool" && \
    (( ${#DEPS_AVAILABLE_TOOLS[@]} == 1 && ${#DEPS_MISSING_TOOLS[@]} == 1 )) && \
    [[ "${DEPS_AVAILABLE_TOOLS[0]}" == "mock_nmap" && "${DEPS_MISSING_TOOLS[0]}" == "mock_missing_tool" ]]
); then
    pass "deps_check_tools accurately separates available and missing tools"
else
    fail "deps_check_tools failed to correctly categorize available vs missing tools"
fi

# Test 17: Deduplication of tool list
# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_BIN_DIR"
    deps_init
    deps_check_tools "mock_nmap" "mock_nmap" "mock_missing" "mock_missing"
    (( ${#DEPS_AVAILABLE_TOOLS[@]} == 1 && ${#DEPS_MISSING_TOOLS[@]} == 1 ))
); then
    pass "deps_check_tools deduplicates repeated tool arguments"
else
    fail "deps_check_tools did not properly deduplicate repeated tools"
fi

# -----------------------------------------------------------------------------
# UT-06: Module-Based Dependency Checking (deps_check_modules)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Module-Based Dependency Checking (deps_check_modules)"

# Test 18: deps_check_modules rejects invalid module
deps_init
if ! deps_check_modules "invalid_mod_name"; then
    if [[ "$DEPS_ERROR" == *"Invalid module identifier"* ]]; then
        pass "deps_check_modules rejects invalid module identifier and records DEPS_ERROR"
    else
        fail "deps_check_modules recorded unexpected error: $DEPS_ERROR"
    fi
else
    fail "deps_check_modules accepted invalid module identifier"
fi

# Test 19: deps_check_modules records DEPS_CHECKED_MODULES
if (
    deps_init
    deps_check_modules "dns" "waf" >/dev/null 2>&1 || true
    (( ${#DEPS_CHECKED_MODULES[@]} == 2 )) && \
    [[ "${DEPS_CHECKED_MODULES[0]}" == "dns" && "${DEPS_CHECKED_MODULES[1]}" == "waf" ]]
); then
    pass "deps_check_modules records checked module identifiers in DEPS_CHECKED_MODULES"
else
    fail "deps_check_modules failed to track checked module identifiers"
fi

# Test 20: deps_check_modules aggregates and deduplicates tools across modules
if (
    # 'port', 'service', 'os' all require 'nmap'
    # 'host' requires 'nmap' and 'fping'
    deps_init
    deps_check_modules "port" "service" "os" "host" >/dev/null 2>&1 || true
    total_tools=$(( ${#DEPS_AVAILABLE_TOOLS[@]} + ${#DEPS_MISSING_TOOLS[@]} ))
    (( total_tools == 2 ))
); then
    pass "deps_check_modules deduplicates tools shared across multiple modules (nmap, fping)"
else
    fail "deps_check_modules failed to deduplicate tools across modules"
fi

# Test 21: Controlled mock module check where all dependencies are satisfied
touch "$MOCK_BIN_DIR/dig"
chmod 755 "$MOCK_BIN_DIR/dig"

# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_BIN_DIR"
    deps_init
    deps_check_modules "dns" && \
    (( ${#DEPS_AVAILABLE_TOOLS[@]} == 1 && ${#DEPS_MISSING_TOOLS[@]} == 0 )) && \
    [[ "${DEPS_AVAILABLE_TOOLS[0]}" == "dig" ]]
); then
    pass "deps_check_modules returns 0 when all module tools are satisfied in PATH"
else
    fail "deps_check_modules failed when all dependencies were satisfied"
fi

# -----------------------------------------------------------------------------
# UT-07: Full Toolkit Dependency Checking (deps_check_all)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Full Toolkit Dependency Checking (deps_check_all)"

# Test 22: deps_check_all checks all 19 tools and records 25 modules
deps_init
deps_check_all >/dev/null 2>&1 || true
total_checked=$(( ${#DEPS_AVAILABLE_TOOLS[@]} + ${#DEPS_MISSING_TOOLS[@]} ))
if (( total_checked == 19 && ${#DEPS_CHECKED_MODULES[@]} == 25 )); then
    pass "deps_check_all evaluates all 19 canonical tools across all 25 modules"
else
    fail "deps_check_all counts mismatch: checked $total_checked tools, recorded ${#DEPS_CHECKED_MODULES[@]} modules"
fi

# Test 23: deps_check_all returns 0 when all 19 tools are present
MOCK_ALL_DIR="$TEST_ROOT/mock_all"
mkdir -p "$MOCK_ALL_DIR"
while IFS= read -r tool; do
    touch "$MOCK_ALL_DIR/$tool"
    chmod 755 "$MOCK_ALL_DIR/$tool"
done < <(deps_get_all_tools)

# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_ALL_DIR"
    deps_init
    deps_check_all && \
    (( ${#DEPS_AVAILABLE_TOOLS[@]} == 19 && ${#DEPS_MISSING_TOOLS[@]} == 0 ))
); then
    pass "deps_check_all returns 0 when all 19 tools are present in PATH"
else
    fail "deps_check_all failed when all tools were present in controlled PATH"
fi

# Test 24: deps_check_all returns 1 when any tool is missing
rm -f "$MOCK_ALL_DIR/testssl.sh"

# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_ALL_DIR"
    deps_init
    ! deps_check_all && \
    (( ${#DEPS_AVAILABLE_TOOLS[@]} == 18 && ${#DEPS_MISSING_TOOLS[@]} == 1 )) && \
    [[ "${DEPS_MISSING_TOOLS[0]}" == "testssl.sh" ]]
); then
    pass "deps_check_all returns 1 when at least one tool is missing"
else
    fail "deps_check_all did not return 1 or identify missing tool accurately"
fi

# -----------------------------------------------------------------------------
# UT-08: Dependency Status Reporting (deps_render_report)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Dependency Status Reporting (deps_render_report)"

# Test 25: Uninspected state returns 1
deps_init
uninspected_output="$(deps_render_report 2>&1 || true)"
if [[ "$uninspected_output" == *"No dependency inspection has been performed"* ]]; then
    pass "deps_render_report returns error when called prior to dependency check"
else
    fail "deps_render_report unexpected output on uninspected state: $uninspected_output"
fi

# Test 26: Full report output structure
term_init "never"
deps_init
deps_check_all || true
full_report="$(deps_render_report)"
if [[ "$full_report" == *"RECKON - Dependency Status"* && \
      "$full_report" == *"Scope: All Modules (25 modules)"* && \
      "$full_report" == *"Summary: 19 total inspected"* ]]; then
    pass "deps_render_report renders valid header, scope, and summary structure"
else
    fail "deps_render_report missing expected structural elements"
fi

# Test 27: Report return code 0 when all dependencies satisfied
mock_satisfied_report=""
touch "$MOCK_ALL_DIR/testssl.sh"
chmod 755 "$MOCK_ALL_DIR/testssl.sh"
# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_ALL_DIR"
    deps_init
    deps_check_all
    mock_satisfied_report="$(deps_render_report)"
    [[ "$mock_satisfied_report" == *"All required external dependencies are satisfied."* ]]
); then
    pass "deps_render_report returns 0 and success message when all dependencies exist"
else
    fail "deps_render_report failed on satisfied dependency set"
fi

# Test 28: Report return code 1 when dependencies missing
# shellcheck disable=SC2030,SC2031
if (
    export PATH="$MOCK_BIN_DIR"
    deps_init
    deps_check_tools "mock_nmap" "mock_missing" || true
    ! deps_render_report >/dev/null 2>&1
); then
    pass "deps_render_report returns 1 when required dependencies are missing"
else
    fail "deps_render_report returned 0 despite missing dependencies"
fi

# Test 29: Report output contains strictly zero package manager or installation commands
has_install_text=false
if [[ "$full_report" =~ (apt|yum|dnf|pacman|brew|install|apk|rpm) ]]; then
    has_install_text=true
fi
if [[ "$has_install_text" == false ]]; then
    pass "deps_render_report contains zero package manager or installation commands"
else
    fail "deps_render_report unexpectedly contained installation commands"
fi

# Test 30: Color integration produces ANSI escape codes when enabled and none when disabled
color_report="$(term_init "always" && deps_render_report)"
plain_report="$(term_init "never" && deps_render_report)"
esc=$'\033'

if [[ "$color_report" == *"$esc"* && "$plain_report" != *"$esc"* ]]; then
    pass "deps_render_report respects terminal color configuration (ANSI present when enabled, absent when disabled)"
else
    fail "deps_render_report color handling failed"
fi

# Test 31: Custom scope override parameter in header
custom_scope_report="$(term_init "never" && deps_render_report "Custom Profile (Discovery)")"
if [[ "$custom_scope_report" == *"Scope: Custom Profile (Discovery)"* ]]; then
    pass "deps_render_report supports custom scope override in header"
else
    fail "deps_render_report failed to display custom scope override"
fi

test_summary
