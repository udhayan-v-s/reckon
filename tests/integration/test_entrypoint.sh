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
    rm -rf -- "$PROJECT_ROOT/results"
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

    mkdir -p "$destination/core" "$destination/lib" || fail "Create test directory"

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

    cp -p "$PROJECT_ROOT/core/targets.sh" "$destination/core/targets.sh" ||
        fail "Copy target processing component"

    cp -p "$PROJECT_ROOT/core/engine.sh" "$destination/core/engine.sh" ||
        fail "Copy execution engine component"

    cp -p "$PROJECT_ROOT/lib/term.sh" "$destination/lib/term.sh" ||
        fail "Copy term library component"

    cp -p "$PROJECT_ROOT/lib/log.sh" "$destination/lib/log.sh" ||
        fail "Copy log library component"

    cp -p "$PROJECT_ROOT/lib/fs.sh" "$destination/lib/fs.sh" ||
        fail "Copy fs library component"

    cp -p "$PROJECT_ROOT/lib/common.sh" "$destination/lib/common.sh" ||
        fail "Copy common library component"

    cp -p "$PROJECT_ROOT/lib/exec.sh" "$destination/lib/exec.sh" ||
        fail "Copy exec library component"

    cp -p "$PROJECT_ROOT/lib/deps.sh" "$destination/lib/deps.sh" ||
        fail "Copy deps library component"

    cp -p "$PROJECT_ROOT/lib/results.sh" "$destination/lib/results.sh" ||
        fail "Copy results library component"

    cp -p "$PROJECT_ROOT/lib/reporting.sh" "$destination/lib/reporting.sh" ||
        fail "Copy reporting library component"
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
    "RECKON 1.0.0" \
    "$PROJECT_ROOT/reckon" --help --version

# Test 11: Help priority is independent of argument order.
assert_success_output \
    "Help priority with reversed argument order" \
    "Usage:" \
    "RECKON 1.0.0" \
    "$PROJECT_ROOT/reckon" --version --help

# Test 12: Version information is displayed.
assert_success_output \
    "Version information" \
    "RECKON 1.0.0" \
    "" \
    "$PROJECT_ROOT/reckon" --version

# Test 13: Valid network scan arguments are accepted.
assert_success_output \
    "Valid network scan arguments" \
    "Version: 1.0.0" \
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
    "Version: 1.0.0" \
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
    "RECKON 1.0.0" \
    "Invalid JSON configuration file" \
    "$PROJECT_ROOT/reckon" --config "$INVALID_CONFIG" --version

# Test 21: Targets file processed through the CLI.
TARGETS_FILE="$TEST_ROOT/targets.txt"

cat > "$TARGETS_FILE" <<'EOF'
# Test targets
192.0.2.10
example.com

invalid_target_!@#
EOF

assert_success_output \
    "Targets file accepted through CLI" \
    "Version: 1.0.0" \
    "Error:" \
    "$PROJECT_ROOT/reckon" --network --targets-file "$TARGETS_FILE"

# Test 22: Empty targets file rejected.
EMPTY_TARGETS="$TEST_ROOT/empty-targets.txt"
: > "$EMPTY_TARGETS"

assert_failure \
    "Empty targets file rejected through CLI" \
    2 \
    "no usable targets" \
    "$PROJECT_ROOT/reckon" --network --targets-file "$EMPTY_TARGETS"

# Test 23: Targets file with mixed valid/invalid lines — warnings printed,
# execution succeeds.
MIXED_TARGETS="$TEST_ROOT/mixed-targets.txt"

cat > "$MIXED_TARGETS" <<'EOF'
# header
192.0.2.10
invalid_!@#
example.com
EOF

assert_success_output \
    "Mixed targets file: warnings printed, execution succeeds" \
    "Warning:" \
    "" \
    "$PROJECT_ROOT/reckon" --network --targets-file "$MIXED_TARGETS"

# Test 24: Invalid single target rejected at prepare stage.
assert_failure \
    "Invalid single target rejected" \
    2 \
    "Target '" \
    "$PROJECT_ROOT/reckon" --network --target "not_a_valid_target!@#"

# Test 25: Config + CLI target — CLI target survives precedence and is prepared.
PRECEDENCE_CONFIG="$TEST_ROOT/precedence-config.json"

printf '%s\n' '{"schema_version":1,"execution":{"timeout":60}}' > "$PRECEDENCE_CONFIG"

assert_success_output \
    "Config + CLI target: precedence applied, target prepared" \
    "Version: 1.0.0" \
    "Error:" \
    "$PROJECT_ROOT/reckon" --config "$PRECEDENCE_CONFIG" --network --target example.com

# Test 26: Missing CLI component detected.
MISSING_CLI="$TEST_ROOT/missing-cli"
prepare_test_copy "$MISSING_CLI"

rm -- "$MISSING_CLI/core/cli.sh"

assert_failure \
    "Detect missing CLI component" \
    1 \
    "cli.sh" \
    "$MISSING_CLI/reckon"

# Test 27: Missing library component detected.
MISSING_LIB="$TEST_ROOT/missing-lib"
prepare_test_copy "$MISSING_LIB"

rm -- "$MISSING_LIB/lib/term.sh"

assert_failure \
    "Detect missing library component" \
    1 \
    "term.sh" \
    "$MISSING_LIB/reckon"

# Test 28: Logging to file via --log-file option.
AUDIT_LOG="$TEST_ROOT/pipeline_audit.log"

assert_success_output \
    "Pipeline execution initializes log file" \
    "Version: 1.0.0" \
    "Error:" \
    "$PROJECT_ROOT/reckon" --network --target 192.0.2.10 --log-file "$AUDIT_LOG"

if [[ -f "$AUDIT_LOG" ]]; then
    pass "Audit log file was created during execution"
else
    fail "Audit log file was not created"
fi

# Test 30: Missing deps library component detected.
MISSING_DEPS="$TEST_ROOT/missing-deps"
prepare_test_copy "$MISSING_DEPS"

rm -- "$MISSING_DEPS/lib/deps.sh"

assert_failure \
    "Detect missing deps library component" \
    1 \
    "deps.sh" \
    "$MISSING_DEPS/reckon"

# Test 31: CLI --check executes cleanly without target.
CHECK_OUTPUT="$("$PROJECT_ROOT/reckon" --check 2>&1 || true)"
if [[ "$CHECK_OUTPUT" == *"RECKON - Dependency Status"* && \
      "$CHECK_OUTPUT" == *"Summary: 19 total inspected"* ]]; then
    pass "CLI --check executes without requiring a scan target"
else
    fail "CLI --check output missing expected dependency status header"
fi

# Test 32: CLI --check with satisfied module (dns).
assert_success_output \
    "CLI --check succeeds for satisfied module dependencies" \
    "All required external dependencies are satisfied." \
    "[MISSING]" \
    "$PROJECT_ROOT/reckon" --check --module dns

# Test 33: CLI --check with missing module dependencies exits with status 1.
assert_failure \
    "CLI --check returns status 1 when dependencies are missing" \
    1 \
    "[MISSING]" \
    "$PROJECT_ROOT/reckon" --check --module crawl

# Test 34: CLI --check records audit log entry when log file is configured.
CHECK_AUDIT_LOG="$TEST_ROOT/check_audit.log"
"$PROJECT_ROOT/reckon" --check --module dns --log-file "$CHECK_AUDIT_LOG" >/dev/null 2>&1 || true
if [[ -f "$CHECK_AUDIT_LOG" ]] && grep -q "Dependency check executed" "$CHECK_AUDIT_LOG"; then
    pass "CLI --check records dependency check entry in log file"
else
    fail "CLI --check failed to write audit record to log file"
fi

# Test 35: Detect missing engine component.
MISSING_ENGINE="$TEST_ROOT/missing-engine"
prepare_test_copy "$MISSING_ENGINE"

rm -- "$MISSING_ENGINE/core/engine.sh"

assert_failure \
    "Detect missing engine component" \
    1 \
    "engine.sh" \
    "$MISSING_ENGINE/reckon"

# Test 36: CLI --dry-run displays execution plan and creates no output directory.
DRY_RUN_OUT="$TEST_ROOT/dry_run_results"
assert_success_output \
    "CLI --dry-run outputs execution plan" \
    "[DRY-RUN] Execution plan simulated" \
    "Error:" \
    "$PROJECT_ROOT/reckon" --network --target 192.0.2.10 --dry-run --output "$DRY_RUN_OUT"

if [[ ! -d "$DRY_RUN_OUT" ]]; then
    pass "CLI --dry-run creates no output directory or artifacts on disk"
else
    fail "CLI --dry-run created output directory: $DRY_RUN_OUT"
fi

# Test 37: CLI execution completes scheduled tasks and generates artifacts.
SCAN_OUT="$TEST_ROOT/scan_results"
assert_success_output \
    "CLI execution completes scheduled tasks" \
    "RECONNAISSANCE COMPLETED" \
    "Error:" \
    "$PROJECT_ROOT/reckon" --module host --target 192.0.2.10 --output "$SCAN_OUT"

if [[ -f "$SCAN_OUT/192.0.2.10/host/stdout.log" && -f "$SCAN_OUT/192.0.2.10/host/output.txt" ]]; then
    pass "CLI execution generated module output files"
else
    fail "CLI execution missing expected output files in $SCAN_OUT"
fi

# Test 38: CLI execution records audit log entry when log file is configured.
SCAN_AUDIT_LOG="$TEST_ROOT/scan_audit.log"
"$PROJECT_ROOT/reckon" --module host --target 192.0.2.10 --log-file "$SCAN_AUDIT_LOG" --output "$TEST_ROOT/scan_log_out" >/dev/null 2>&1 || true
if [[ -f "$SCAN_AUDIT_LOG" ]] && grep -q "Scan execution finished" "$SCAN_AUDIT_LOG"; then
    pass "CLI execution records scan completion entry in log file"
else
    fail "CLI execution failed to write scan audit record to log file"
fi

# Test 39: Incompatible target and module selection rejected during planning.
assert_failure \
    "Reject incompatible target and module selection" \
    2 \
    "No compatible modules could be scheduled" \
    "$PROJECT_ROOT/reckon" --module dns --target 192.0.2.10

# Test 40: Detect missing results library component.
MISSING_RESULTS="$TEST_ROOT/missing-results"
prepare_test_copy "$MISSING_RESULTS"

rm -- "$MISSING_RESULTS/lib/results.sh"

assert_failure \
    "Detect missing results library component" \
    1 \
    "results.sh" \
    "$MISSING_RESULTS/reckon"

# Test 41: CLI scan generates normalized results.json in output directory.
scan_json="$SCAN_OUT/192.0.2.10/results.json"
[[ ! -f "$scan_json" ]] && scan_json="$SCAN_OUT/results.json"

if [[ -f "$scan_json" && -s "$scan_json" ]]; then
    if command -v jq >/dev/null 2>&1; then
        if jq -e . "$scan_json" >/dev/null 2>&1; then
            pass "CLI scan generated valid results.json artifact"
        else
            fail "CLI scan generated invalid results.json (jq validation failed)"
        fi
    else
        pass "CLI scan generated non-empty results.json artifact"
    fi
else
    fail "CLI scan did not generate expected results.json in $SCAN_OUT"
fi

# Test 42: Detect missing reporting library component.
MISSING_REPORTING="$TEST_ROOT/missing-reporting"
prepare_test_copy "$MISSING_REPORTING"

rm -- "$MISSING_REPORTING/lib/reporting.sh"

assert_failure \
    "Detect missing reporting library component" \
    1 \
    "reporting.sh" \
    "$MISSING_REPORTING/reckon"

# Test 43: CLI scan generates default reports (report.md and report.txt).
scan_md="$SCAN_OUT/192.0.2.10/report.md"
scan_txt="$SCAN_OUT/192.0.2.10/report.txt"
[[ ! -f "$scan_md" ]] && scan_md="$SCAN_OUT/report.md"
[[ ! -f "$scan_txt" ]] && scan_txt="$SCAN_OUT/report.txt"

if [[ -f "$scan_md" && -s "$scan_md" && \
      -f "$scan_txt" && -s "$scan_txt" ]]; then
    pass "CLI scan generated default human-readable reports (report.md, report.txt)"
else
    fail "CLI scan missing expected default human-readable reports in $SCAN_OUT"
fi

# Test 44: CLI scan with --no-report suppresses report generation.
NO_REPORT_OUT="$TEST_ROOT/no_report_scan"
assert_success \
    "CLI scan with --no-report executes successfully" \
    "$PROJECT_ROOT/reckon" --module host --target 192.0.2.10 --output "$NO_REPORT_OUT" --no-report

if [[ -f "$NO_REPORT_OUT/192.0.2.10/host/output.txt" ]]; then
    pass "CLI scan with --no-report created module output artifacts"
else
    fail "CLI scan with --no-report missing module output artifacts"
fi

if [[ ! -f "$NO_REPORT_OUT/results.json" && \
      ! -f "$NO_REPORT_OUT/report.md" && \
      ! -f "$NO_REPORT_OUT/report.txt" ]]; then
    pass "CLI scan with --no-report created no report files in output directory"
else
    fail "CLI scan with --no-report generated unwanted report files"
fi

# Test 45: CLI scan with explicit --format generates only selected formats.
CUSTOM_FMT_OUT="$TEST_ROOT/custom_format_scan"
assert_success \
    "CLI scan with --format JSON,MD executes successfully" \
    "$PROJECT_ROOT/reckon" --module host --target 192.0.2.10 --output "$CUSTOM_FMT_OUT" --format JSON,MD

custom_json="$CUSTOM_FMT_OUT/192.0.2.10/results.json"
custom_md="$CUSTOM_FMT_OUT/192.0.2.10/report.md"
[[ ! -f "$custom_json" ]] && custom_json="$CUSTOM_FMT_OUT/results.json"
[[ ! -f "$custom_md" ]] && custom_md="$CUSTOM_FMT_OUT/report.md"

if [[ -f "$custom_json" && -f "$custom_md" ]]; then
    pass "CLI scan with --format JSON,MD generated requested report files"
else
    fail "CLI scan with --format JSON,MD missing requested reports"
fi

if [[ ! -f "$CUSTOM_FMT_OUT/report.txt" && ! -f "$CUSTOM_FMT_OUT/192.0.2.10/report.txt" ]]; then
    pass "CLI scan with --format JSON,MD excluded unrequested format (report.txt)"
else
    fail "CLI scan with --format JSON,MD generated excluded report.txt"
fi

# Final summary.
printf '%s\n' "--------------------------------------"
printf 'Tests passed: %s\n' "$PASS_COUNT"
printf '%s\n' "Integration tests completed."