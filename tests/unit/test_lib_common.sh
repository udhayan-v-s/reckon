#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Common system and utility helpers library unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/common.sh
if ! source "$PROJECT_ROOT/lib/common.sh"; then
    printf 'Error: Unable to load common library component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-common-test.XXXXXX")" || {
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

    printf '%s\n' "Common library unit tests completed."
}

printf '%s\n' "RECKON - Common Library Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Command Verification (common_has_command & common_require_command)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Command Verification (common_has_command & common_require_command)"

# Test 1: common_has_command detects existing system command
if common_has_command "bash"; then
    pass "common_has_command detects existing system command"
else
    fail "common_has_command failed to detect bash"
fi

# Test 2: common_has_command returns 1 for non-existent command
if ! common_has_command "non_existent_binary_xyz_123"; then
    pass "common_has_command returns 1 for non-existent command"
else
    fail "common_has_command succeeded on non-existent command"
fi

# Test 3: common_has_command returns 1 on empty argument
if ! common_has_command ""; then
    pass "common_has_command returns 1 on empty argument"
else
    fail "common_has_command succeeded on empty argument"
fi

# Test 4: common_require_command succeeds on existing command
if common_require_command "sh"; then
    pass "common_require_command succeeds for available command"
else
    fail "common_require_command failed on available command"
fi

# Test 5: common_require_command fails and populates COMMON_ERROR for missing command
if ! common_require_command "non_existent_tool_456" "apt install foo"; then
    if [[ "$COMMON_ERROR" =~ "Required external tool not found" && "$COMMON_ERROR" =~ "apt install foo" ]]; then
        pass "common_require_command populates COMMON_ERROR with tool name and hint"
    else
        fail "common_require_command error message missing expected format: '$COMMON_ERROR'"
    fi
else
    fail "common_require_command succeeded on missing tool"
fi

# Test 6: common_require_command rejects empty argument
if ! common_require_command ""; then
    pass "common_require_command rejects empty command argument"
else
    fail "common_require_command accepted empty command argument"
fi

# -----------------------------------------------------------------------------
# UT-02: Numeric Validation Primitives
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Numeric Validation Primitives"

# Test 7: common_is_integer accepts valid signed and unsigned integers
if common_is_integer "0" && common_is_integer "42" && common_is_integer "-15" && common_is_integer "+7"; then
    pass "common_is_integer accepts positive, zero, and negative integers"
else
    fail "common_is_integer rejected valid integer"
fi

# Test 8: common_is_integer rejects floats, strings, and empty values
if ! common_is_integer "3.14" && ! common_is_integer "abc" && ! common_is_integer "" && ! common_is_integer "12a"; then
    pass "common_is_integer rejects floats, alphabetic strings, and empty input"
else
    fail "common_is_integer accepted non-integer value"
fi

# Test 9: common_is_positive_integer accepts >= 1
if common_is_positive_integer "1" && common_is_positive_integer "100"; then
    pass "common_is_positive_integer accepts values >= 1"
else
    fail "common_is_positive_integer rejected positive integer"
fi

# Test 10: common_is_positive_integer rejects 0, negatives, and non-integers
if ! common_is_positive_integer "0" && ! common_is_positive_integer "-5" && ! common_is_positive_integer "abc"; then
    pass "common_is_positive_integer rejects zero, negatives, and strings"
else
    fail "common_is_positive_integer accepted invalid positive integer"
fi

# Test 11: common_is_non_negative_integer accepts 0 and positives
if common_is_non_negative_integer "0" && common_is_non_negative_integer "5"; then
    pass "common_is_non_negative_integer accepts zero and positive integers"
else
    fail "common_is_non_negative_integer rejected zero or positive integer"
fi

# Test 12: common_is_non_negative_integer rejects negatives
if ! common_is_non_negative_integer "-1" && ! common_is_non_negative_integer "xyz"; then
    pass "common_is_non_negative_integer rejects negative numbers and strings"
else
    fail "common_is_non_negative_integer accepted negative number or string"
fi

# -----------------------------------------------------------------------------
# UT-03: String Manipulation Utilities
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: String Manipulation Utilities"

# Test 13: common_trim strips leading and trailing whitespace
trimmed="$(common_trim "   recon target   ")"
if [[ "$trimmed" == "recon target" ]]; then
    pass "common_trim removes surrounding spaces while preserving internal spaces"
else
    fail "common_trim failed: '$trimmed'"
fi

# Test 14: common_trim handles tabs and newlines
tab_str=$'\t  sample text \t '
trimmed="$(common_trim "$tab_str")"
if [[ "$trimmed" == "sample text" ]]; then
    pass "common_trim removes surrounding tabs and mixed whitespace"
else
    fail "common_trim failed on tab whitespace: '$trimmed'"
fi

# Test 15: common_trim on all-whitespace returns empty
trimmed="$(common_trim "    ")"
if [[ -z "$trimmed" ]]; then
    pass "common_trim on whitespace-only input returns empty string"
else
    fail "common_trim on whitespace-only string returned: '$trimmed'"
fi

# Test 16: common_to_lower converts to lowercase
lowered="$(common_to_lower "ReCkOn CLI Toolkit")"
if [[ "$lowered" == "reckon cli toolkit" ]]; then
    pass "common_to_lower converts ASCII characters to lowercase"
else
    fail "common_to_lower failed: '$lowered'"
fi

# Test 17: common_to_upper converts to uppercase
uppered="$(common_to_upper "reckon cli toolkit")"
if [[ "$uppered" == "RECKON CLI TOOLKIT" ]]; then
    pass "common_to_upper converts ASCII characters to uppercase"
else
    fail "common_to_upper failed: '$uppered'"
fi

# -----------------------------------------------------------------------------
# UT-04: Array Inspection Utilities
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Array Inspection Utilities"
sample_array=("host" "port" "service" "ssh" "http")

# Test 18: common_contains_element finds existing element
if common_contains_element "service" "${sample_array[@]}"; then
    pass "common_contains_element finds matching element in array"
else
    fail "common_contains_element failed to find existing element"
fi

# Test 19: common_contains_element returns 1 for missing element
if ! common_contains_element "smb" "${sample_array[@]}"; then
    pass "common_contains_element returns 1 for non-existent element"
else
    fail "common_contains_element found non-existent element"
fi

# Test 20: common_contains_element enforces exact match (rejects substring)
if ! common_contains_element "serv" "${sample_array[@]}"; then
    pass "common_contains_element enforces exact match against array elements"
else
    fail "common_contains_element matched partial substring"
fi

# -----------------------------------------------------------------------------
# UT-05: Directory Inspection (common_is_empty_dir)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Directory Inspection (common_is_empty_dir)"
empty_dir="$TEST_ROOT/empty_dir"
non_empty_dir="$TEST_ROOT/non_empty_dir"
dotfile_dir="$TEST_ROOT/dotfile_dir"

mkdir -p "$empty_dir"
mkdir -p "$non_empty_dir" && touch "$non_empty_dir/file.txt"
mkdir -p "$dotfile_dir" && touch "$dotfile_dir/.hidden"

# Test 21: Identifies truly empty directory
if common_is_empty_dir "$empty_dir"; then
    pass "common_is_empty_dir returns 0 for empty directory"
else
    fail "common_is_empty_dir failed on empty directory"
fi

# Test 22: Returns 1 for directory containing regular files
if ! common_is_empty_dir "$non_empty_dir"; then
    pass "common_is_empty_dir returns 1 for directory containing regular files"
else
    fail "common_is_empty_dir returned 0 for non-empty directory"
fi

# Test 23: Returns 1 for directory containing hidden dotfiles
if ! common_is_empty_dir "$dotfile_dir"; then
    pass "common_is_empty_dir returns 1 for directory containing hidden dotfiles"
else
    fail "common_is_empty_dir returned 0 for directory containing hidden dotfiles"
fi

# Test 24: Returns 1 for non-existent path
if ! common_is_empty_dir "$TEST_ROOT/non_existent_path"; then
    pass "common_is_empty_dir returns 1 for non-existent path"
else
    fail "common_is_empty_dir succeeded on non-existent path"
fi

# Test 25: Returns 1 for file path
if ! common_is_empty_dir "$non_empty_dir/file.txt"; then
    pass "common_is_empty_dir returns 1 for regular file path"
else
    fail "common_is_empty_dir accepted file path as a directory"
fi

test_summary
