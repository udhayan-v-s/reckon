#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# CLI unit tests
#

set -o nounset

# Resolve the project root.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# Load the CLI component.
# shellcheck source=core/cli.sh
if ! source "$PROJECT_ROOT/core/cli.sh"; then
    printf 'Error: Unable to load CLI component.\n' >&2
    exit 1
fi

# Create an isolated temporary test directory.
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-unit-test.XXXXXX")" || {
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

    printf '%s\n' "CLI unit tests completed."
}

# Test suite header.
printf '%s\n' "RECKON - CLI Unit Tests"
printf '%s\n' "--------------------------------------"

# UT-01: CLI initialization tests.

test_cli_initialization() {

    printf '\n%s\n' "UT-01: CLI Initialization"

    # Test 1: Default scalar values.
    cli_init

    if [[ "$CLI_TARGET" == "" &&
          "$CLI_TARGETS_FILE" == "" &&
          "$CLI_PROFILE" == "" &&
          "$CLI_OUTPUT_DIR" == "results/" &&
          "$CLI_COLOR_MODE" == "auto" ]]; then
        pass "Default scalar values"
    else
        fail "Default scalar values"
    fi

    # Test 2: Default Boolean flags.
    if [[ "$CLI_NETWORK" == false &&
          "$CLI_WEB" == false &&
          "$CLI_NO_REPORT" == false &&
          "$CLI_VERBOSE" == false &&
          "$CLI_QUIET" == false &&
          "$CLI_DEBUG" == false &&
          "$CLI_NO_BANNER" == false &&
          "$CLI_CHECK" == false &&
          "$CLI_LIST_MODULES" == false &&
          "$CLI_DRY_RUN" == false &&
          "$CLI_HELP" == false &&
          "$CLI_VERSION" == false ]]; then
        pass "Default Boolean flags"
    else
        fail "Default Boolean flags"
    fi

    # Test 3: Empty arrays.
    if [[ ${#CLI_MODULES[@]} -eq 0 &&
          ${#CLI_EXCLUDE_MODULES[@]} -eq 0 &&
          ${#CLI_FORMATS[@]} -eq 0 ]]; then
        pass "Default empty arrays"
    else
        fail "Default empty arrays"
    fi
}

# UT-02: Argument parsing tests.

test_cli_argument_parsing() {

    printf '\n%s\n' "UT-02: Argument Parsing"

    # Test 1: Long and short option aliases.
    cli_init

    if cli_parse_args \
        --target example.com \
        -T targets.txt \
        -n \
        -w \
        -v \
        -q \
        -o output/ \
        -f json \
        -x dns; then

        if [[ "$CLI_TARGET" == "example.com" &&
              "$CLI_TARGETS_FILE" == "targets.txt" &&
              "$CLI_NETWORK" == true &&
              "$CLI_WEB" == true &&
              "$CLI_VERBOSE" == true &&
              "$CLI_QUIET" == true &&
              "$CLI_OUTPUT_DIR" == "output/" &&
              ${#CLI_FORMATS[@]} -eq 1 &&
              "${CLI_FORMATS[0]}" == "json" &&
              ${#CLI_EXCLUDE_MODULES[@]} -eq 1 &&
              "${CLI_EXCLUDE_MODULES[0]}" == "dns" ]]; then
            pass "Long and short option aliases"
        else
            fail "Long and short option aliases"
        fi
    else
        fail "Long and short option aliases (parser rejected valid arguments)"
    fi

    # Test 2: Target and configuration values.
    cli_init

    if cli_parse_args \
        --target example.org \
        --targets-file targets.txt \
        --profile full \
        --output reports/ \
        --log-file reckon.log \
        --config reckon.conf \
        --wordlist words.txt \
        --ports 1-1000; then

        if [[ "$CLI_TARGET" == "example.org" &&
              "$CLI_TARGETS_FILE" == "targets.txt" &&
              "$CLI_PROFILE" == "full" &&
              "$CLI_OUTPUT_DIR" == "reports/" &&
              "$CLI_LOG_FILE" == "reckon.log" &&
              "$CLI_CONFIG" == "reckon.conf" &&
              "$CLI_WORDLIST" == "words.txt" &&
              "$CLI_PORTS" == "1-1000" ]]; then
            pass "Target and configuration values"
        else
            fail "Target and configuration values"
        fi
    else
        fail "Target and configuration values (parser rejected valid arguments)"
    fi

    # Test 3: Execution options.
    cli_init

    if cli_parse_args \
        --timeout 30 \
        --threads 10 \
        --rate-limit 100 \
        --retries 3; then

        if [[ "$CLI_TIMEOUT" == "30" &&
              "$CLI_THREADS" == "10" &&
              "$CLI_RATE_LIMIT" == "100" &&
              "$CLI_RETRIES" == "3" ]]; then
            pass "Execution option values"
        else
            fail "Execution option values"
        fi
    else
        fail "Execution option values (parser rejected valid arguments)"
    fi

    # Test 4: Display and general flags.
    cli_init

    if cli_parse_args \
        --color \
        --no-banner \
        --check \
        --list-modules \
        --dry-run \
        --debug; then

        if [[ "$CLI_COLOR_MODE" == "always" &&
              "$CLI_NO_BANNER" == true &&
              "$CLI_CHECK" == true &&
              "$CLI_LIST_MODULES" == true &&
              "$CLI_DRY_RUN" == true &&
              "$CLI_DEBUG" == true ]]; then
            pass "Display and general flags"
        else
            fail "Display and general flags"
        fi
    else
        fail "Display and general flags (parser rejected valid arguments)"
    fi

    # Test 5: Informational flags.
    cli_init

    if cli_parse_args --help --version; then

        if [[ "$CLI_HELP" == true &&
              "$CLI_VERSION" == true ]]; then
            pass "Informational flags"
        else
            fail "Informational flags"
        fi
    else
        fail "Informational flags (parser rejected valid arguments)"
    fi

    # Test 6: Repeated scalar options use the last value.
    cli_init

    if cli_parse_args \
        --target first.example \
        --target second.example \
        --timeout 10 \
        --timeout 30 \
        --output first/ \
        --output second/; then

        if [[ "$CLI_TARGET" == "second.example" &&
              "$CLI_TIMEOUT" == "30" &&
              "$CLI_OUTPUT_DIR" == "second/" ]]; then
            pass "Repeated scalar options use the last value"
        else
            fail "Repeated scalar options use the last value"
        fi
    else
        fail "Repeated scalar options (parser rejected valid arguments)"
    fi

    # Test 7: Initialization resets previously parsed state.
    cli_init

    if [[ "$CLI_TARGET" == "" &&
          "$CLI_NETWORK" == false &&
          "$CLI_TIMEOUT" == "" &&
          ${#CLI_MODULES[@]} -eq 0 &&
          ${#CLI_FORMATS[@]} -eq 0 ]]; then
        pass "Initialization resets previous state"
    else
        fail "Initialization resets previous state"
    fi
}

# UT-03: CSV parsing tests.

test_cli_csv_parsing() {

    printf '\n%s\n' "UT-03: CSV Parsing"

    # Test 1: Multiple module selections.
    cli_init

    if cli_parse_args --module host,dns,port; then
        if [[ ${#CLI_MODULES[@]} -eq 3 &&
              "${CLI_MODULES[0]}" == "host" &&
              "${CLI_MODULES[1]}" == "dns" &&
              "${CLI_MODULES[2]}" == "port" ]]; then
            pass "Multiple module selections"
        else
            fail "Multiple module selections"
        fi
    else
        fail "Multiple module selections (parser rejected valid values)"
    fi

    # Test 2: Multiple excluded modules.
    cli_init

    if cli_parse_args --exclude ssh,ftp,telnet; then
        if [[ ${#CLI_EXCLUDE_MODULES[@]} -eq 3 &&
              "${CLI_EXCLUDE_MODULES[0]}" == "ssh" &&
              "${CLI_EXCLUDE_MODULES[1]}" == "ftp" &&
              "${CLI_EXCLUDE_MODULES[2]}" == "telnet" ]]; then
            pass "Multiple excluded modules"
        else
            fail "Multiple excluded modules"
        fi
    else
        fail "Multiple excluded modules (parser rejected valid values)"
    fi

    # Test 3: Multiple report formats.
    cli_init

    if cli_parse_args --format json,txt,md; then
        if [[ ${#CLI_FORMATS[@]} -eq 3 &&
              "${CLI_FORMATS[0]}" == "json" &&
              "${CLI_FORMATS[1]}" == "txt" &&
              "${CLI_FORMATS[2]}" == "md" ]]; then
            pass "Multiple report formats"
        else
            fail "Multiple report formats"
        fi
    else
        fail "Multiple report formats (parser rejected valid values)"
    fi

    # Test 4: Whitespace trimming.
    cli_init

    if cli_parse_args --module " host , dns , port "; then
        if [[ ${#CLI_MODULES[@]} -eq 3 &&
              "${CLI_MODULES[0]}" == "host" &&
              "${CLI_MODULES[1]}" == "dns" &&
              "${CLI_MODULES[2]}" == "port" ]]; then
            pass "Whitespace trimming"
        else
            fail "Whitespace trimming"
        fi
    else
        fail "Whitespace trimming (parser rejected valid values)"
    fi

    # Test 5: Duplicate removal within a CSV list.
    cli_init

    if cli_parse_args --module host,dns,host,port,dns; then
        if [[ ${#CLI_MODULES[@]} -eq 3 &&
              "${CLI_MODULES[0]}" == "host" &&
              "${CLI_MODULES[1]}" == "dns" &&
              "${CLI_MODULES[2]}" == "port" ]]; then
            pass "Duplicate removal within CSV list"
        else
            fail "Duplicate removal within CSV list"
        fi
    else
        fail "Duplicate removal within CSV list (parser rejected valid values)"
    fi

    # Test 6: Preserve first-seen ordering.
    cli_init

    if cli_parse_args --format md,json,txt,json; then
        if [[ ${#CLI_FORMATS[@]} -eq 3 &&
              "${CLI_FORMATS[0]}" == "md" &&
              "${CLI_FORMATS[1]}" == "json" &&
              "${CLI_FORMATS[2]}" == "txt" ]]; then
            pass "Preserve first-seen ordering"
        else
            fail "Preserve first-seen ordering"
        fi
    else
        fail "Preserve first-seen ordering (parser rejected valid values)"
    fi

    # Test 7: Deduplication across repeated CSV options.
    cli_init

    if cli_parse_args \
        --module host,dns \
        --module dns,port \
        --exclude ssh,ftp \
        --exclude ftp,telnet \
        --format json,txt \
        --format txt,md; then

        if [[ ${#CLI_MODULES[@]} -eq 3 &&
              "${CLI_MODULES[0]}" == "host" &&
              "${CLI_MODULES[1]}" == "dns" &&
              "${CLI_MODULES[2]}" == "port" &&
              ${#CLI_EXCLUDE_MODULES[@]} -eq 3 &&
              "${CLI_EXCLUDE_MODULES[0]}" == "ssh" &&
              "${CLI_EXCLUDE_MODULES[1]}" == "ftp" &&
              "${CLI_EXCLUDE_MODULES[2]}" == "telnet" &&
              ${#CLI_FORMATS[@]} -eq 3 &&
              "${CLI_FORMATS[0]}" == "json" &&
              "${CLI_FORMATS[1]}" == "txt" &&
              "${CLI_FORMATS[2]}" == "md" ]]; then
            pass "Deduplication across repeated CSV options"
        else
            fail "Deduplication across repeated CSV options"
        fi
    else
        fail "Deduplication across repeated CSV options (parser rejected valid values)"
    fi
}

# UT-04: Parser error handling tests.

test_cli_parser_errors() {

    printf '\n%s\n' "UT-04: Parser Error Handling"

    local output
    local status

    # Test 1: Missing option value.
    cli_init

    if output="$(cli_parse_args --target 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Missing value for --target"* ]]; then
        pass "Missing option value"
    else
        fail "Missing option value"
    fi

    # Test 2: Empty option value.
    cli_init

    if output="$(cli_parse_args --target "" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Empty value supplied for --target"* ]]; then
        pass "Empty option value"
    else
        fail "Empty option value"
    fi

    # Test 3: Another option supplied as a value.
    cli_init

    if output="$(cli_parse_args --target --network 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Missing value for --target"* ]]; then
        pass "Another option supplied as a value"
    else
        fail "Another option supplied as a value"
    fi

    # Test 4: Unknown option.
    cli_init

    if output="$(cli_parse_args --unknown-option 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Unknown option: --unknown-option"* ]]; then
        pass "Unknown option"
    else
        fail "Unknown option"
    fi

    # Test 5: Empty CSV element.
    cli_init

    if output="$(cli_parse_args --module "host,,dns" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Empty value found in CLI_MODULES list"* &&
          ${#CLI_MODULES[@]} -eq 0 ]]; then
        pass "Empty CSV element"
    else
        fail "Empty CSV element"
    fi

    # Test 6: Trailing comma.
    cli_init

    if output="$(cli_parse_args --module "host,dns," 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Empty value found in CLI_MODULES list"* &&
          ${#CLI_MODULES[@]} -eq 0 ]]; then
        pass "Trailing comma"
    else
        fail "Trailing comma"
    fi

    # Test 7: Leading comma.
    cli_init

    if output="$(cli_parse_args --module ",host,dns" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Empty value found in CLI_MODULES list"* &&
          ${#CLI_MODULES[@]} -eq 0 ]]; then
        pass "Leading comma"
    else
        fail "Leading comma"
    fi

    # Test 8: Invalid destination array.
    cli_init

    if output="$(cli_append_unique_csv INVALID_ARRAY "host,dns" 2>&1)"; then
        status=0
    else
        status=$?
    fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Invalid destination array: INVALID_ARRAY"* ]]; then
        pass "Invalid destination array"
    else
        fail "Invalid destination array"
    fi
}

# UT-05: Scan selection and module validation tests.
test_cli_scan_and_module_validation() {
    printf '\n%s\n' "UT-05: Scan Selection and Module Validation"

    local output
    local status

    # Test 1: Network and web scans require a target.
    cli_init
    CLI_NETWORK=true

    if output="$(cli_validate_scan_selection 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"A target is required"* ]]; then

        cli_init
        CLI_WEB=true

        if output="$(cli_validate_scan_selection 2>&1)"; then status=0; else status=$?; fi

        if [[ "$status" -eq 2 &&
              "$output" == *"A target is required"* ]]; then
            pass "Network and web scans require a target"
        else
            fail "Network and web scans require a target"
        fi
    else
        fail "Network and web scans require a target"
    fi

    # Test 2: A direct target satisfies scan selection.
    cli_init
    CLI_NETWORK=true
    CLI_TARGET="example.com"

    if cli_validate_scan_selection; then
        pass "Direct target satisfies scan selection"
    else
        fail "Direct target satisfies scan selection"
    fi

    # Test 3: A targets file satisfies scan selection.
    cli_init
    CLI_WEB=true
    CLI_TARGETS_FILE="targets.txt"

    if cli_validate_scan_selection; then
        pass "Targets file satisfies scan selection"
    else
        fail "Targets file satisfies scan selection"
    fi

    # Test 4: Custom modules conflict with network and web modes.
    cli_init
    CLI_MODULES=(host)
    CLI_NETWORK=true

    if output="$(cli_validate_modules 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--module cannot be combined"* ]]; then

        cli_init
        CLI_MODULES=(host)
        CLI_WEB=true

        if output="$(cli_validate_modules 2>&1)"; then status=0; else status=$?; fi

        if [[ "$status" -eq 2 &&
              "$output" == *"--module cannot be combined"* ]]; then
            pass "Custom modules conflict with network and web modes"
        else
            fail "Custom modules conflict with network and web modes"
        fi
    else
        fail "Custom modules conflict with network and web modes"
    fi

    # Test 5: Module inclusion conflicts with module exclusion.
    cli_init
    CLI_MODULES=(host)
    CLI_EXCLUDE_MODULES=(dns)

    if output="$(cli_validate_modules 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--module and --exclude cannot be used together"* ]]; then
        pass "Module inclusion conflicts with module exclusion"
    else
        fail "Module inclusion conflicts with module exclusion"
    fi

    # Test 6: Valid selected and excluded module identifiers are accepted.
    cli_init
    CLI_MODULES=(host dns http-probe)
    CLI_EXCLUDE_MODULES=()

    if cli_validate_modules; then
        CLI_MODULES=()
        CLI_EXCLUDE_MODULES=(ssh ftp resources)

        if cli_validate_modules; then
            pass "Valid selected and excluded module identifiers"
        else
            fail "Valid selected and excluded module identifiers"
        fi
    else
        fail "Valid selected and excluded module identifiers"
    fi

    # Test 7: Invalid selected module identifier is rejected.
    cli_init
    CLI_MODULES=(invalid-module)

    if output="$(cli_validate_modules 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Invalid module identifier: invalid-module"* ]]; then
        pass "Invalid selected module identifier"
    else
        fail "Invalid selected module identifier"
    fi

    # Test 8: Invalid excluded module identifier is rejected.
    cli_init
    CLI_EXCLUDE_MODULES=(invalid-module)

    if output="$(cli_validate_modules 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Invalid module identifier: invalid-module"* ]]; then
        pass "Invalid excluded module identifier"
    else
        fail "Invalid excluded module identifier"
    fi
}

# UT-06: Reporting and display validation tests.
test_cli_reporting_and_display_validation() {
    printf '\n%s\n' "UT-06: Reporting and Display Validation"

    local output
    local status

    # Test 1: All supported report formats are accepted.
    cli_init
    CLI_FORMATS=(JSON TXT MD)

    if cli_validate_reporting; then
        pass "All supported report formats"
    else
        fail "All supported report formats"
    fi

    # Test 2: Report format validation is case-insensitive.
    cli_init
    CLI_FORMATS=(json Txt mD)

    if cli_validate_reporting; then
        pass "Case-insensitive report format validation"
    else
        fail "Case-insensitive report format validation"
    fi

    # Test 3: Unsupported report format is rejected.
    cli_init
    CLI_FORMATS=(PDF)

    if output="$(cli_validate_reporting 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Unsupported report format: PDF"* ]]; then
        pass "Unsupported report format rejection"
    else
        fail "Unsupported report format rejection"
    fi

    # Test 4: Every requested report format is validated.
    cli_init
    CLI_FORMATS=(JSON PDF)

    if output="$(cli_validate_reporting 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Unsupported report format: PDF"* ]]; then
        pass "Validation of every requested report format"
    else
        fail "Validation of every requested report format"
    fi

    # Test 5: No-report conflicts with report formats.
    cli_init
    CLI_NO_REPORT=true
    CLI_FORMATS=(JSON)

    if output="$(cli_validate_reporting 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--no-report cannot be combined with --format"* ]]; then
        pass "No-report and report format conflict"
    else
        fail "No-report and report format conflict"
    fi

    # Test 6: No-report without report formats is accepted.
    cli_init
    CLI_NO_REPORT=true

    if cli_validate_reporting; then
        pass "No-report without report formats"
    else
        fail "No-report without report formats"
    fi

    # Test 7: Verbose and quiet modes conflict.
    cli_init
    CLI_VERBOSE=true
    CLI_QUIET=true

    if output="$(cli_validate_display 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--verbose and --quiet cannot be used together"* ]]; then
        pass "Verbose and quiet mode conflict"
    else
        fail "Verbose and quiet mode conflict"
    fi

    # Test 8: Verbose and quiet modes are independently accepted.
    cli_init
    CLI_VERBOSE=true

    if cli_validate_display; then
        CLI_VERBOSE=false
        CLI_QUIET=true

        if cli_validate_display; then
            pass "Independent verbose and quiet modes"
        else
            fail "Independent verbose and quiet modes"
        fi
    else
        fail "Independent verbose and quiet modes"
    fi
}

# UT-07: Numeric and file validation tests.
test_cli_numeric_and_file_validation() {
    printf '\n%s\n' "UT-07: Numeric and File Validation"

    local output
    local status
    local test_file
    local test_directory

    # Test 1: Minimum valid numeric values.
    cli_init
    CLI_TIMEOUT=1
    CLI_THREADS=1
    CLI_RATE_LIMIT=1
    CLI_RETRIES=0

    if cli_validate_numeric_options; then
        pass "Minimum valid numeric values"
    else
        fail "Minimum valid numeric values"
    fi

    # Test 2: Larger positive numeric values.
    cli_init
    CLI_TIMEOUT=30
    CLI_THREADS=10
    CLI_RATE_LIMIT=100
    CLI_RETRIES=5

    if cli_validate_numeric_options; then
        pass "Larger positive numeric values"
    else
        fail "Larger positive numeric values"
    fi

    # Test 3: Zero retries are accepted.
    cli_init
    CLI_RETRIES=0

    if cli_validate_numeric_options; then
        pass "Zero retries are accepted"
    else
        fail "Zero retries are accepted"
    fi

    # Test 4: Zero timeout is rejected.
    cli_init
    CLI_TIMEOUT=0

    if output="$(cli_validate_numeric_options 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--timeout must be at least 1"* ]]; then
        pass "Zero timeout is rejected"
    else
        fail "Zero timeout is rejected"
    fi

    # Test 5: Zero threads are rejected.
    cli_init
    CLI_THREADS=0

    if output="$(cli_validate_numeric_options 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--threads must be at least 1"* ]]; then
        pass "Zero threads are rejected"
    else
        fail "Zero threads are rejected"
    fi

    # Test 6: Zero rate limit is rejected.
    cli_init
    CLI_RATE_LIMIT=0

    if output="$(cli_validate_numeric_options 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--rate-limit must be at least 1"* ]]; then
        pass "Zero rate limit is rejected"
    else
        fail "Zero rate limit is rejected"
    fi

    # Test 7: Negative numeric values are rejected.
    cli_init
    CLI_TIMEOUT=-1

    if output="$(cli_validate_numeric_options 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--timeout must be a non-negative integer"* ]]; then
        pass "Negative numeric values are rejected"
    else
        fail "Negative numeric values are rejected"
    fi

    # Test 8: Non-integer numeric values are rejected.
    cli_init
    CLI_THREADS=2.5

    if output="$(cli_validate_numeric_options 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--threads must be a non-negative integer"* ]]; then
        pass "Non-integer numeric values are rejected"
    else
        fail "Non-integer numeric values are rejected"
    fi

    # Prepare temporary files and directories.
    test_file="$TEST_ROOT/validation-test.txt"
    test_directory="$TEST_ROOT/validation-directory"

    : > "$test_file"
    mkdir -p -- "$test_directory"

    # Test 9: Readable regular file is accepted.
    if cli_validate_file "--config" "$test_file"; then
        pass "Readable regular file is accepted"
    else
        fail "Readable regular file is accepted"
    fi

    # Test 10: Missing file is rejected.
    if output="$(cli_validate_file "--config" "$TEST_ROOT/missing.txt" 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"does not exist or is not a regular file"* ]]; then
        pass "Missing file is rejected"
    else
        fail "Missing file is rejected"
    fi

    # Test 11: Directory is rejected.
    if output="$(cli_validate_file "--config" "$test_directory" 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"does not exist or is not a regular file"* ]]; then
        pass "Directory is rejected"
    else
        fail "Directory is rejected"
    fi

    # Test 12: Unreadable regular file is rejected.
    chmod 000 "$test_file"

    if output="$(cli_validate_file "--config" "$test_file" 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"is not readable"* ]]; then
        pass "Unreadable regular file is rejected"
    else
        fail "Unreadable regular file is rejected"
    fi

    # Restore permissions for temporary-file cleanup.
    chmod 600 "$test_file"

    # Test 13: All configured CLI input files are accepted.
    cli_init
    CLI_TARGETS_FILE="$test_file"
    CLI_WORDLIST="$test_file"
    CLI_CONFIG="$test_file"

    if cli_validate_files; then
        pass "All configured CLI input files are accepted"
    else
        fail "All configured CLI input files are accepted"
    fi

    # Test 14: Missing targets file is rejected.
    cli_init
    CLI_TARGETS_FILE="$TEST_ROOT/missing-targets.txt"

    if output="$(cli_validate_files 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"specified by --targets-file"* ]]; then
        pass "Missing targets file is rejected"
    else
        fail "Missing targets file is rejected"
    fi

    # Test 15: Missing wordlist is rejected.
    cli_init
    CLI_WORDLIST="$TEST_ROOT/missing-wordlist.txt"

    if output="$(cli_validate_files 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"specified by --wordlist"* ]]; then
        pass "Missing wordlist is rejected"
    else
        fail "Missing wordlist is rejected"
    fi

    # Test 16: Missing configuration file is rejected.
    cli_init
    CLI_CONFIG="$TEST_ROOT/missing-config.txt"

    if output="$(cli_validate_files 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"specified by --config"* ]]; then
        pass "Missing configuration file is rejected"
    else
        fail "Missing configuration file is rejected"
    fi
}

# UT-08: Validation coordinator tests.
test_cli_validation_coordinator() {
    printf '\n%s\n' "UT-08: Validation Coordinator"

    local output
    local status

    # Test 1: Valid CLI configuration is accepted.
    cli_init

    if cli_validate_args; then
        pass "Valid CLI configuration"
    else
        fail "Valid CLI configuration"
    fi

    # Test 2: Scan selection validation runs before module validation.
    cli_init
    CLI_NETWORK=true
    CLI_MODULES=(invalid-module)

    if output="$(cli_validate_args 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"A target is required"* &&
          "$output" != *"Invalid module identifier"* ]]; then
        pass "Scan selection validation has first priority"
    else
        fail "Scan selection validation has first priority"
    fi

    # Test 3: Module validation runs before reporting validation.
    cli_init
    CLI_MODULES=(invalid-module)
    CLI_FORMATS=(PDF)

    if output="$(cli_validate_args 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Invalid module identifier"* &&
          "$output" != *"Unsupported report format"* ]]; then
        pass "Module validation precedes reporting validation"
    else
        fail "Module validation precedes reporting validation"
    fi

    # Test 4: Reporting validation runs before display validation.
    cli_init
    CLI_FORMATS=(PDF)
    CLI_VERBOSE=true
    CLI_QUIET=true

    if output="$(cli_validate_args 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"Unsupported report format"* &&
          "$output" != *"--verbose and --quiet"* ]]; then
        pass "Reporting validation precedes display validation"
    else
        fail "Reporting validation precedes display validation"
    fi

    # Test 5: Display validation runs before numeric validation.
    cli_init
    CLI_VERBOSE=true
    CLI_QUIET=true
    CLI_TIMEOUT=0

    if output="$(cli_validate_args 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--verbose and --quiet"* &&
          "$output" != *"--timeout must be at least 1"* ]]; then
        pass "Display validation precedes numeric validation"
    else
        fail "Display validation precedes numeric validation"
    fi

    # Test 6: Numeric validation runs before file validation.
    cli_init
    CLI_TIMEOUT=0
    CLI_CONFIG="$TEST_ROOT/missing-config.txt"

    if output="$(cli_validate_args 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"--timeout must be at least 1"* &&
          "$output" != *"specified by --config"* ]]; then
        pass "Numeric validation precedes file validation"
    else
        fail "Numeric validation precedes file validation"
    fi

    # Test 7: File validation errors are returned by the coordinator.
    cli_init
    CLI_CONFIG="$TEST_ROOT/missing-config.txt"

    if output="$(cli_validate_args 2>&1)"; then status=0; else status=$?; fi

    if [[ "$status" -eq 2 &&
          "$output" == *"specified by --config"* ]]; then
        pass "File validation error is propagated"
    else
        fail "File validation error is propagated"
    fi
}

# Run UT-01 through UT-04.
test_cli_initialization
test_cli_argument_parsing
test_cli_csv_parsing
test_cli_parser_errors
test_cli_scan_and_module_validation
test_cli_reporting_and_display_validation
test_cli_numeric_and_file_validation
test_cli_validation_coordinator

test_summary
