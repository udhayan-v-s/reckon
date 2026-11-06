#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Logging framework library unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/log.sh
if ! source "$PROJECT_ROOT/lib/log.sh"; then
    printf 'Error: Unable to load logging library component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-log-test.XXXXXX")" || {
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

    printf '%s\n' "Logging library unit tests completed."
}

printf '%s\n' "RECKON - Logging Library Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Logging Initialization & Setters
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Logging Initialization & Setters"

# Test 1: Default initialization
log_init
if [[ "$LOG_VERBOSE" == false && "$LOG_QUIET" == false && "$LOG_DEBUG" == false && "$LOG_FILE" == "" ]]; then
    pass "Default initialization sets all flags to false and empty log file"
else
    fail "Default initialization state mismatch"
fi

# Test 2: Positional argument initialization
log_init true false true "/tmp/test.log"
if [[ "$LOG_VERBOSE" == true && "$LOG_QUIET" == false && "$LOG_DEBUG" == true && "$LOG_FILE" == "/tmp/test.log" ]]; then
    pass "Positional argument initialization sets all options correctly"
else
    fail "Positional argument initialization state mismatch"
fi

# Test 3: Explicit setters
log_init
log_set_file "/tmp/custom.log"
log_set_debug true
log_set_verbose true
log_set_quiet true
if [[ "$LOG_FILE" == "/tmp/custom.log" && "$LOG_DEBUG" == true && "$LOG_VERBOSE" == true && "$LOG_QUIET" == true ]]; then
    pass "Explicit setters update state variables correctly"
else
    fail "Explicit setters failed to update state variables"
fi

# -----------------------------------------------------------------------------
# UT-02: Stream Routing (stdout vs stderr)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Stream Routing (stdout vs stderr)"
log_init false false false ""
term_init "never"

# Test 4: log_info routes to stdout
stdout_file="$TEST_ROOT/info_stdout.txt"
stderr_file="$TEST_ROOT/info_stderr.txt"
log_info "Info message" >"$stdout_file" 2>"$stderr_file"
if [[ -s "$stdout_file" && ! -s "$stderr_file" ]]; then
    pass "log_info routes message to stdout only"
else
    fail "log_info did not route exclusively to stdout"
fi

# Test 5: log_success routes to stdout
stdout_file="$TEST_ROOT/success_stdout.txt"
stderr_file="$TEST_ROOT/success_stderr.txt"
log_success "Success message" >"$stdout_file" 2>"$stderr_file"
if [[ -s "$stdout_file" && ! -s "$stderr_file" ]]; then
    pass "log_success routes message to stdout only"
else
    fail "log_success did not route exclusively to stdout"
fi

# Test 6: log_warn routes to stderr
stdout_file="$TEST_ROOT/warn_stdout.txt"
stderr_file="$TEST_ROOT/warn_stderr.txt"
log_warn "Warning message" >"$stdout_file" 2>"$stderr_file"
if [[ ! -s "$stdout_file" && -s "$stderr_file" ]]; then
    pass "log_warn routes message to stderr only"
else
    fail "log_warn did not route exclusively to stderr"
fi

# Test 7: log_error routes to stderr
stdout_file="$TEST_ROOT/error_stdout.txt"
stderr_file="$TEST_ROOT/error_stderr.txt"
log_error "Error message" >"$stdout_file" 2>"$stderr_file"
if [[ ! -s "$stdout_file" && -s "$stderr_file" ]]; then
    pass "log_error routes message to stderr only"
else
    fail "log_error did not route exclusively to stderr"
fi

# Test 8: log_debug routes to stderr when enabled
log_set_debug true
stdout_file="$TEST_ROOT/debug_stdout.txt"
stderr_file="$TEST_ROOT/debug_stderr.txt"
log_debug "Debug message" >"$stdout_file" 2>"$stderr_file"
if [[ ! -s "$stdout_file" && -s "$stderr_file" ]]; then
    pass "log_debug routes message to stderr only"
else
    fail "log_debug did not route exclusively to stderr"
fi

# -----------------------------------------------------------------------------
# UT-03: Filtering & Verbosity Modes
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Filtering & Verbosity Modes"

# Test 9: Normal mode suppresses debug messages
log_init false false false ""
out_file="$TEST_ROOT/debug_normal.txt"
log_debug "Hidden debug" >"$out_file" 2>&1
if [[ ! -s "$out_file" ]]; then
    pass "Normal mode suppresses log_debug messages"
else
    fail "log_debug was not suppressed in normal mode"
fi

# Test 10: Quiet mode suppresses info messages
log_init false true false ""
out_file="$TEST_ROOT/info_quiet.txt"
log_info "Suppressed info" >"$out_file" 2>&1
if [[ ! -s "$out_file" ]]; then
    pass "Quiet mode suppresses log_info messages"
else
    fail "log_info was not suppressed in quiet mode"
fi

# Test 11: Quiet mode suppresses success messages
log_init false true false ""
out_file="$TEST_ROOT/success_quiet.txt"
log_success "Suppressed success" >"$out_file" 2>&1
if [[ ! -s "$out_file" ]]; then
    pass "Quiet mode suppresses log_success messages"
else
    fail "log_success was not suppressed in quiet mode"
fi

# Test 12: Quiet mode preserves warning messages
log_init false true false ""
out_file="$TEST_ROOT/warn_quiet.txt"
log_warn "Active warning" >"$out_file" 2>&1
if [[ -s "$out_file" ]]; then
    pass "Quiet mode permits log_warn messages"
else
    fail "log_warn was suppressed in quiet mode"
fi

# Test 13: Quiet mode preserves error messages
log_init false true false ""
out_file="$TEST_ROOT/error_quiet.txt"
log_error "Active error" >"$out_file" 2>&1
if [[ -s "$out_file" ]]; then
    pass "Quiet mode permits log_error messages"
else
    fail "log_error was suppressed in quiet mode"
fi

# -----------------------------------------------------------------------------
# UT-04: Color Formatting Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Color Formatting Integration"

# Test 14: Color enabled includes ANSI code in tag
term_init "always"
log_init false false false ""
out="$(log_warn "Color test" 2>&1)"
if [[ "$out" =~ $'\033[33m' ]]; then
    pass "Color enabled includes ANSI escape sequence in warning tag"
else
    fail "ANSI escape sequence not found in warning tag: '$out'"
fi

# Test 15: Color disabled outputs plain tag without ANSI codes
term_init "never"
log_init false false false ""
out="$(log_error "No color test" 2>&1)"
if [[ "$out" == "[ERROR] No color test" ]]; then
    pass "Color disabled outputs plain unadorned tag"
else
    fail "Plain tag mismatch when color disabled: '$out'"
fi

# -----------------------------------------------------------------------------
# UT-05: Persistent File Logging
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Persistent File Logging"
test_log="$TEST_ROOT/test_output.log"
term_init "always"
log_init false false false "$test_log"

# Test 16: File logging appends entry with timestamp and tag
log_info "First file record" >/dev/null
if [[ -f "$test_log" ]] && grep -q '\[INFO\] First file record' "$test_log"; then
    pass "log_info appends formatted entry to log file"
else
    fail "log_info failed to write expected record to file"
fi

# Test 17: Log file records multiple severity levels
log_warn "Second record" 2>/dev/null
log_error "Third record" 2>/dev/null
log_success "Fourth record" >/dev/null
if grep -q '\[WARN\] Second record' "$test_log" && \
   grep -q '\[ERROR\] Third record' "$test_log" && \
   grep -q '\[SUCCESS\] Fourth record' "$test_log"; then
    pass "Log file records multiple severity levels correctly"
else
    fail "Log file missing expected multi-severity records"
fi

# Test 18: File logs are stripped of ANSI escape sequences
# Even when term_init "always" is active, file content should be plain text
if ! grep -q $'\033' "$test_log"; then
    pass "Log file contains clean text with ANSI escape codes stripped"
else
    fail "Log file contains unstripped ANSI escape sequences"
fi

# Test 19: Timestamp format matches [YYYY-MM-DD HH:MM:SS]
if grep -E '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\]' "$test_log" >/dev/null; then
    pass "Log file entries contain valid ISO date-time timestamps"
else
    fail "Log file timestamp format invalid"
fi

# Test 20: Quiet mode still writes INFO entries to log file
log_set_quiet true
log_info "Audited quiet event" >/dev/null
if grep -q 'Audited quiet event' "$test_log"; then
    pass "Quiet mode continues to record informational events in log file"
else
    fail "Quiet mode suppressed file log entry"
fi

# Test 21: Auto-creation of nested log directory
nested_log="$TEST_ROOT/nested/sub/dir/reckon.log"
log_set_file "$nested_log"
log_warn "Nested path message" 2>/dev/null
if [[ -f "$nested_log" ]] && grep -q 'Nested path message' "$nested_log"; then
    pass "Missing parent directories for log file are created automatically"
else
    fail "Failed to auto-create nested directory for log file"
fi

test_summary
