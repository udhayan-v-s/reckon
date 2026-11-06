#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Safe command execution wrapper library unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/exec.sh
if ! source "$PROJECT_ROOT/lib/exec.sh"; then
    printf 'Error: Unable to load execution library component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-exec-test.XXXXXX")" || {
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

    printf '%s\n' "Execution library unit tests completed."
}

printf '%s\n' "RECKON - Execution Library Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Basic Execution & Exit Codes (exec_run)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Basic Execution & Exit Codes (exec_run)"

# Test 1: Successful command returns 0
if exec_run "" "" 0 true; then
    pass "exec_run returns 0 on successful command"
else
    fail "exec_run failed on successful command"
fi

# Test 2: Non-zero exit code is preserved
code=0
exec_run "" "" 0 bash -c "exit 42" || code=$?
if (( code == 42 && EXEC_EXIT_CODE == 42 )); then
    pass "exec_run preserves non-zero exit codes (42)"
else
    fail "exec_run did not preserve exit code 42 (got $code, EXEC_EXIT_CODE=$EXEC_EXIT_CODE)"
fi

# Test 3: Insufficient arguments returns 1 and sets EXEC_ERROR
if ! exec_run "" ""; then
    if [[ -n "$EXEC_ERROR" ]]; then
        pass "exec_run rejects insufficient arguments and records EXEC_ERROR"
    else
        fail "exec_run failed without setting EXEC_ERROR"
    fi
else
    fail "exec_run succeeded with insufficient arguments"
fi

# -----------------------------------------------------------------------------
# UT-02: Stream Routing & Redirection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Stream Routing & Redirection"

stdout_target="$TEST_ROOT/stdout.txt"
stderr_target="$TEST_ROOT/stderr.txt"

# Test 4: Stdout directed to file, stderr discarded
exec_run "$stdout_target" "" 0 echo "stdout message"
if [[ -f "$stdout_target" ]] && grep -q "stdout message" "$stdout_target"; then
    pass "exec_run routes stdout to destination file"
else
    fail "exec_run failed to capture stdout to file"
fi

# Test 5: Stderr directed to file, stdout discarded
exec_run "" "$stderr_target" 0 bash -c "echo 'stderr message' >&2"
if [[ -f "$stderr_target" ]] && grep -q "stderr message" "$stderr_target"; then
    pass "exec_run routes stderr to destination file"
else
    fail "exec_run failed to capture stderr to file"
fi

# Test 6: Simultaneous separate stream routing
rm -f "$stdout_target" "$stderr_target"
exec_run "$stdout_target" "$stderr_target" 0 bash -c "echo 'out line'; echo 'err line' >&2"
if grep -q "out line" "$stdout_target" && grep -q "err line" "$stderr_target"; then
    pass "exec_run routes stdout and stderr simultaneously to distinct files"
else
    fail "exec_run failed simultaneous dual-stream routing"
fi

# -----------------------------------------------------------------------------
# UT-03: Variable Capture (exec_capture)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Variable Capture (exec_capture)"

# Test 7: Captures stdout directly into EXEC_STDOUT
exec_capture 0 echo "captured line"
if [[ "$EXEC_STDOUT" == "captured line" ]]; then
    pass "exec_capture captures stdout into EXEC_STDOUT"
else
    fail "exec_capture stdout mismatch: '$EXEC_STDOUT'"
fi

# Test 8: Captures stderr directly into EXEC_STDERR
exec_capture 0 bash -c "echo 'captured error' >&2"
if [[ "$EXEC_STDERR" == "captured error" ]]; then
    pass "exec_capture captures stderr into EXEC_STDERR"
else
    fail "exec_capture stderr mismatch: '$EXEC_STDERR'"
fi

# Test 9: Captures both streams and preserves exit code
status=0
exec_capture 0 bash -c "echo 'multi out'; echo 'multi err' >&2; exit 7" || status=$?
if (( status == 7 )) && [[ "$EXEC_STDOUT" == "multi out" && "$EXEC_STDERR" == "multi err" ]]; then
    pass "exec_capture captures dual streams and preserves exit status 7"
else
    fail "exec_capture dual stream/exit code mismatch"
fi

# -----------------------------------------------------------------------------
# UT-04: Argument Safety & Injection Prevention
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Argument Safety & Injection Prevention"

# Test 10: Arguments with whitespace are preserved as single parameters
# shellcheck disable=SC2016
exec_capture 0 bash -c 'printf "[%s]\n" "$1"' _ "arg with spaces"
if [[ "$EXEC_STDOUT" == "[arg with spaces]" ]]; then
    pass "exec_run preserves arguments containing whitespace as single parameters"
else
    fail "exec_run split whitespace argument: '$EXEC_STDOUT'"
fi

# Test 11: Shell metacharacters are passed literally (no command injection)
trap_file="$TEST_ROOT/injected.txt"
# shellcheck disable=SC2016
exec_capture 0 bash -c 'printf "%s\n" "$1"' _ "; touch $trap_file; echo injected"
if [[ ! -e "$trap_file" ]]; then
    pass "exec_run safely prevents shell injection from metacharacters (; | &&)"
else
    fail "exec_run allowed command injection!"
fi

# -----------------------------------------------------------------------------
# UT-05: Timeout Enforcement & Detection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Timeout Enforcement & Detection"

# Test 12: Fast command completes without timeout
exec_run "" "" 5 true
if ! exec_is_timed_out && [[ "$EXEC_TIMED_OUT" == false ]]; then
    pass "Normal command completes without triggering timeout"
else
    fail "Normal command incorrectly flagged as timed out"
fi

# Test 13: Exceeded timeout terminates process and sets EXEC_TIMED_OUT
if command -v timeout >/dev/null 2>&1; then
    exec_run "" "" 1 sleep 3
    if exec_is_timed_out && (( EXEC_EXIT_CODE == 124 )); then
        pass "Exceeded timeout terminates command with status 124 and sets EXEC_TIMED_OUT"
    else
        fail "Timeout enforcement failed (exit code $EXEC_EXIT_CODE, timed_out=$EXEC_TIMED_OUT)"
    fi
else
    pass "[SKIP] timeout binary not available in environment"
fi

# Test 14: Execution duration is measured
if (( EXEC_DURATION >= 0 )); then
    pass "Execution duration is measured in EXEC_DURATION (${EXEC_DURATION}s)"
else
    fail "EXEC_DURATION is invalid: '$EXEC_DURATION'"
fi

# -----------------------------------------------------------------------------
# UT-06: Silent Execution (exec_silent)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Silent Execution (exec_silent)"

# Test 15: exec_silent succeeds cleanly
if exec_silent true; then
    pass "exec_silent returns 0 on successful command"
else
    fail "exec_silent failed on successful command"
fi

# Test 16: exec_silent preserves non-zero exit code
code=0
exec_silent bash -c "exit 19" || code=$?
if (( code == 19 )); then
    pass "exec_silent preserves non-zero exit code (19)"
else
    fail "exec_silent failed to preserve exit code 19 (got $code)"
fi

test_summary
