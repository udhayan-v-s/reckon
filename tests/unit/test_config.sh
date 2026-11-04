#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Configuration unit tests
#

set -o nounset

# Resolve the project root.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# Load the configuration component.
# shellcheck source=core/config.sh
if ! source "$PROJECT_ROOT/core/config.sh"; then
    printf 'Error: Unable to load configuration component.\n' >&2
    exit 1
fi

# jq is required for JSON-loading tests.
if ! command -v jq >/dev/null 2>&1; then
    printf 'Error: jq is required to run configuration unit tests.\n' >&2
    exit 1
fi

# Create an isolated temporary test directory.
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-config-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

PASS_COUNT=0
FAIL_COUNT=0

# Clean up temporary test files.
cleanup() {
    rm -rf -- "$TEST_ROOT"
}

trap cleanup EXIT

# Display a successful test result.
pass() {
    printf '[PASS] %s\n' "$1"
    ((PASS_COUNT += 1))
}

# Display a failed test result.
fail() {
    printf '[FAIL] %s\n' "$1" >&2
    ((FAIL_COUNT += 1))
}

# Display the test summary.
test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Configuration unit tests completed."
}

# Test suite header.
printf '%s\n' "RECKON - Configuration Unit Tests"
printf '%s\n' "--------------------------------------"

# UT-01: Configuration initialization tests.
test_config_initialization() {

    printf '\n%s\n' "UT-01: Configuration Initialization"

    # Test 1: Default configuration state.
    config_init

    if [[ "$CONFIG_FILE" == "" &&
          "$CONFIG_JSON" == "" &&
          "$CONFIG_LOADED" == false &&
          "$CONFIG_ERROR" == "" ]]; then
        pass "Default configuration state"
    else
        fail "Default configuration state"
    fi

    # Test 2: Initialization resets previous state.
    CONFIG_FILE="previous.json"
    CONFIG_JSON='{"schema_version":1}'
    CONFIG_LOADED=true
    CONFIG_ERROR="Previous error"

    config_init

    if [[ "$CONFIG_FILE" == "" &&
          "$CONFIG_JSON" == "" &&
          "$CONFIG_LOADED" == false &&
          "$CONFIG_ERROR" == "" ]]; then
        pass "Initialization resets previous state"
    else
        fail "Initialization resets previous state"
    fi
}

# UT-02: Configuration dependency tests.
test_config_dependencies() {

    printf '\n%s\n' "UT-02: Dependency Checking"

    local original_path
    original_path="$PATH"

    # Test 1: No configuration file means jq is not required.
    CONFIG_FILE=""

    if config_check_dependencies; then
        pass "Optional configuration does not require jq"
    else
        fail "Optional configuration does not require jq"
    fi

    # Test 2: jq is required when a configuration file is supplied.
    CONFIG_FILE="$TEST_ROOT/valid.json"
    PATH="$TEST_ROOT"

    if config_check_dependencies; then
        fail "Missing jq dependency is rejected"
    else
        if [[ "$CONFIG_ERROR" == *"jq is required"* ]]; then
            pass "Missing jq dependency is rejected"
        else
            fail "Missing jq dependency is rejected (incorrect error)"
        fi
    fi

    PATH="$original_path"
    CONFIG_FILE=""
    CONFIG_ERROR=""
}

# UT-03: Configuration file validation tests.
test_config_file_validation() {

    printf '\n%s\n' "UT-03: File Validation"

    local valid_file
    local missing_file
    local test_directory

    valid_file="$TEST_ROOT/valid.json"
    missing_file="$TEST_ROOT/missing.json"
    test_directory="$TEST_ROOT/config-directory"

    printf '%s\n' '{"schema_version":1}' > "$valid_file"
    mkdir -p -- "$test_directory"

    # Test 1: Optional configuration is accepted.
    CONFIG_FILE=""

    if config_validate_file; then
        pass "Optional configuration file"
    else
        fail "Optional configuration file"
    fi

    # Test 2: Existing readable regular file is accepted.
    CONFIG_FILE="$valid_file"

    if config_validate_file; then
        pass "Existing configuration file is accepted"
    else
        fail "Existing configuration file is accepted"
    fi

    # Test 3: Missing configuration file is rejected.
    CONFIG_FILE="$missing_file"

    if config_validate_file; then
        fail "Missing configuration file is rejected"
    elif [[ "$CONFIG_ERROR" == *"does not exist"* ]]; then
        pass "Missing configuration file is rejected"
    else
        fail "Missing configuration file is rejected (incorrect error)"
    fi

    # Test 4: Directory is rejected as a configuration file.
    CONFIG_FILE="$test_directory"

    if config_validate_file; then
        fail "Directory is rejected as a configuration file"
    else
        pass "Directory is rejected as a configuration file"
    fi

    CONFIG_FILE=""
    CONFIG_ERROR=""
}

# UT-04: JSON configuration loading tests.
test_config_loading() {

    printf '\n%s\n' "UT-04: JSON Configuration Loading"

    local valid_file
    local invalid_file
    local empty_file
    local multiple_file

    valid_file="$TEST_ROOT/valid.json"
    invalid_file="$TEST_ROOT/invalid.json"
    empty_file="$TEST_ROOT/empty.json"
    multiple_file="$TEST_ROOT/multiple.json"

    printf '%s\n' '{"schema_version":1}' > "$valid_file"
    printf '%s\n' '{"schema_version":1' > "$invalid_file"
    : > "$empty_file"

    printf '%s\n' \
        '{"schema_version":1}' \
        '{"schema_version":1}' > "$multiple_file"

    # Test 1: Valid JSON configuration loads successfully.
    config_init
    CONFIG_FILE="$valid_file"

    if config_load; then
        if [[ "$CONFIG_LOADED" == true &&
              "$CONFIG_JSON" == '{"schema_version":1}' &&
              "$CONFIG_ERROR" == "" ]]; then
            pass "Valid JSON configuration loads successfully"
        else
            fail "Valid JSON configuration loads successfully (incorrect state)"
        fi
    else
        fail "Valid JSON configuration loads successfully"
    fi

    # Test 2: Invalid JSON is rejected.
    config_init
    CONFIG_FILE="$invalid_file"

    if config_load; then
        fail "Invalid JSON configuration is rejected"
    elif [[ "$CONFIG_LOADED" == false &&
            "$CONFIG_JSON" == "" &&
            "$CONFIG_ERROR" == *"Invalid JSON configuration file"* ]]; then
        pass "Invalid JSON configuration is rejected"
    else
        fail "Invalid JSON configuration is rejected (incorrect state)"
    fi

    # Test 3: Empty JSON file is rejected.
    config_init
    CONFIG_FILE="$empty_file"

    if config_load; then
        fail "Empty configuration file is rejected"
    elif [[ "$CONFIG_LOADED" == false &&
            "$CONFIG_ERROR" == *"Invalid JSON configuration file"* ]]; then
        pass "Empty configuration file is rejected"
    else
        fail "Empty configuration file is rejected (incorrect state)"
    fi

    # Test 4: Multiple JSON documents are rejected.
    config_init
    CONFIG_FILE="$multiple_file"

    if config_load; then
        fail "Multiple JSON documents are rejected"
    elif [[ "$CONFIG_LOADED" == false &&
            "$CONFIG_ERROR" == *"Invalid JSON configuration file"* ]]; then
        pass "Multiple JSON documents are rejected"
    else
        fail "Multiple JSON documents are rejected (incorrect state)"
    fi
}

# UT-05: Optional configuration loading tests.
test_config_optional_loading() {

    printf '\n%s\n' "UT-05: Optional Configuration"

    # Test 1: Loading without a configuration file succeeds.
    config_init

    if config_load; then
        if [[ "$CONFIG_LOADED" == false &&
              "$CONFIG_JSON" == "" &&
              "$CONFIG_ERROR" == "" ]]; then
            pass "Application starts without a configuration file"
        else
            fail "Application starts without a configuration file (incorrect state)"
        fi
    else
        fail "Application starts without a configuration file"
    fi
}

# Run UT-01 through UT-05.
test_config_initialization
test_config_dependencies
test_config_file_validation
test_config_loading
test_config_optional_loading

test_summary
