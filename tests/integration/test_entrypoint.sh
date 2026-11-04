#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Application entry-point integration tests
#

set -o nounset

# Resolve the project root.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# Create an isolated temporary test directory.
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

PASS_COUNT=0

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

# Display a failure and stop the test suite.
fail() {
    printf '[FAIL] %s\n' "$1" >&2
    exit 1
}

# Execute a command and expect success.
assert_success() {
    local description="$1"
    shift

    local output
    local status

    if output="$("$@" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if (( status != 0 )); then
        printf '%s\n' "$output" >&2
        fail "$description (exit code: $status)"
    fi

    pass "$description"
}

# Execute a command, expect success, and verify its output.
assert_success_output() {
    local description="$1"
    local expected_output="$2"
    local unexpected_output="$3"
    shift 3

    local output
    local status

    if output="$("$@" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if (( status != 0 )); then
        printf '%s\n' "$output" >&2
        fail "$description (exit code: $status)"
    fi

    if [[ "$output" != *"$expected_output"* ]]; then
        printf '%s\n' "$output" >&2
        fail "$description (expected output not found)"
    fi

    if [[ -n "$unexpected_output" &&
          "$output" == *"$unexpected_output"* ]]; then
        printf '%s\n' "$output" >&2
        fail "$description (unexpected output found)"
    fi

    pass "$description"
}

# Execute a command and expect a specific failure.
assert_failure() {
    local description="$1"
    local expected_status="$2"
    local expected_message="$3"
    shift 3

    local output
    local status

    if output="$("$@" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if (( status != expected_status )); then
        printf '%s\n' "$output" >&2
        fail "$description (expected exit code $expected_status, received $status)"
    fi

    if [[ "$output" != *"$expected_message"* ]]; then
        printf '%s\n' "$output" >&2
        fail "$description (expected error message not found)"
    fi

    pass "$description"
}

# Execute a command from a specified directory.
run_from_directory() {
    local directory="$1"
    shift

    (
        cd -- "$directory" || exit 1
        "$@"
    )
}

# Create an isolated copy of the application.
prepare_test_copy() {
    local destination="$1"

    mkdir -p "$destination/core" || fail "Create test directory"

    cp -p "$PROJECT_ROOT/reckon" "$destination/reckon" ||
        fail "Copy application launcher"

    cp -p "$PROJECT_ROOT/core/metadata.sh" "$destination/core/metadata.sh" ||
        fail "Copy metadata component"

    cp -p "$PROJECT_ROOT/core/main.sh" "$destination/core/main.sh" ||
        fail "Copy main component"

    cp -p "$PROJECT_ROOT/core/cli.sh" "$destination/core/cli.sh" ||
        fail "Copy CLI component"

    cp -p "$PROJECT_ROOT/core/config.sh" "$destination/core/config.sh" ||
        fail "Copy configuration component"
}

printf '%s\n' "RECKON - Entry-Point Integration Tests"
printf '%s\n' "--------------------------------------"

# Test 1: Application starts without a configuration file.
assert_success \
    "Application starts without a configuration file" \
    "$PROJECT_ROOT/reckon"

# Test 2: Explicit Bash execution.
assert_success \
    "Explicit Bash execution" \
    bash "$PROJECT_ROOT/reckon"

# Test 3: Execution from /tmp.
assert_success \
    "Execution from /tmp" \
    run_from_directory /tmp "$PROJECT_ROOT/reckon"

# Test 4: Execution from filesystem root.
assert_success \
    "Execution from /" \
    run_from_directory / "$PROJECT_ROOT/reckon"

# Test 5: Execution from a path containing spaces.
SPACE_COPY="$TEST_ROOT/reckon test"
prepare_test_copy "$SPACE_COPY"

assert_success \
    "Execution from a directory containing spaces" \
    "$SPACE_COPY/reckon"

# Test 6: Unsupported shell.
assert_failure \
    "Reject execution through sh" \
    1 \
    "RECKON requires the Bash shell." \
    sh "$PROJECT_ROOT/reckon"

# Test 7: Missing metadata component.
MISSING_METADATA="$TEST_ROOT/missing-metadata"
prepare_test_copy "$MISSING_METADATA"

rm -- "$MISSING_METADATA/core/metadata.sh"

assert_failure \
    "Detect missing metadata component" \
    1 \
    "metadata.sh" \
    "$MISSING_METADATA/reckon"

# Test 8: Missing main component.
MISSING_MAIN="$TEST_ROOT/missing-main"
prepare_test_copy "$MISSING_MAIN"

rm -- "$MISSING_MAIN/core/main.sh"

assert_failure \
    "Detect missing main component" \
    1 \
    "main.sh" \
    "$MISSING_MAIN/reckon"

# Test 9: Failed metadata loading.
FAILED_METADATA="$TEST_ROOT/failed-metadata"
prepare_test_copy "$FAILED_METADATA"

printf '\nfalse\n' >> "$FAILED_METADATA/core/metadata.sh"

assert_failure \
    "Detect failed metadata loading" \
    1 \
    "Failed to load application metadata." \
    "$FAILED_METADATA/reckon"

# Test 10: Help takes priority over version.
assert_success_output \
    "Help takes priority over version" \
    "Usage:" \
    "RECKON 0.1.0" \
    "$PROJECT_ROOT/reckon" --help --version

# Test 11: Help priority is independent of argument order.
assert_success_output \
    "Help priority with reversed argument order" \
    "Usage:" \
    "RECKON 0.1.0" \
    "$PROJECT_ROOT/reckon" --version --help

# Test 12: Version information is displayed.
assert_success_output \
    "Version information" \
    "RECKON 0.1.0" \
    "" \
    "$PROJECT_ROOT/reckon" --version

# Test 13: Valid network scan arguments are accepted.
assert_success_output \
    "Valid network scan arguments" \
    "Version: 0.1.0" \
    "" \
    "$PROJECT_ROOT/reckon" --network --target 192.0.2.10

# Test 14: Invalid arguments are rejected.
assert_failure \
    "Reject invalid CLI arguments" \
    2 \
    "Unknown option: --invalid-option" \
    "$PROJECT_ROOT/reckon" --invalid-option

# Test 15: Network scanning without a target is rejected.
assert_failure \
    "Reject network scan without a target" \
    2 \
    "A target is required" \
    "$PROJECT_ROOT/reckon" --network

# Test 16: Valid JSON configuration is loaded through the CLI.
VALID_CONFIG="$TEST_ROOT/valid-config.json"

printf '%s\n' '{"schema_version":1}' > "$VALID_CONFIG"

assert_success_output \
    "Load valid JSON configuration through CLI" \
    "Version: 0.1.0" \
    "Error:" \
    "$PROJECT_ROOT/reckon" --config "$VALID_CONFIG"

# Test 17: Invalid JSON configuration is rejected.
INVALID_CONFIG="$TEST_ROOT/invalid-config.json"

printf '%s\n' '{"schema_version":1' > "$INVALID_CONFIG"

assert_failure \
    "Reject invalid JSON configuration through CLI" \
    1 \
    "Invalid JSON configuration file" \
    "$PROJECT_ROOT/reckon" --config "$INVALID_CONFIG"

# Test 18: Missing configuration file is rejected.
MISSING_CONFIG="$TEST_ROOT/missing-config.json"

assert_failure \
    "Reject missing configuration file through CLI" \
    2 \
    "does not exist or is not a regular file" \
    "$PROJECT_ROOT/reckon" --config "$MISSING_CONFIG"

# Test 19: Help bypasses configuration loading.
assert_success_output \
    "Help bypasses invalid configuration loading" \
    "Usage:" \
    "Invalid JSON configuration file" \
    "$PROJECT_ROOT/reckon" --config "$INVALID_CONFIG" --help

# Test 20: Version bypasses configuration loading.
assert_success_output \
    "Version bypasses invalid configuration loading" \
    "RECKON 0.1.0" \
    "Invalid JSON configuration file" \
    "$PROJECT_ROOT/reckon" --config "$INVALID_CONFIG" --version

# Final summary.
printf '%s\n' "--------------------------------------"
printf 'Tests passed: %s\n' "$PASS_COUNT"
printf '%s\n' "Integration tests completed."