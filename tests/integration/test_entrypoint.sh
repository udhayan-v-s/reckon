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
}

printf '%s\n' "RECKON - Entry-Point Integration Tests"
printf '%s\n' "--------------------------------------"

# Test 1: Normal execution.
assert_success \
    "Normal application execution" \
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

# Final summary.
printf '%s\n' "--------------------------------------"
printf 'Tests passed: %s\n' "$PASS_COUNT"
printf '%s\n' "Integration tests completed."