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

# UT-06: Configuration schema validation tests.
test_config_schema_validation() {

    printf '\n%s\n' "UT-06: Configuration Schema Validation"

    local valid_minimal valid_full
    local bad_no_version bad_version bad_unknown_root
    local bad_unknown_nested bad_section_type
    local bad_output_type bad_color_enum
    local bad_modules_type bad_modules_elem
    local bad_timeout_type
    local bad_format_enum bad_no_report_type bad_logfile_type
    local case_format

    valid_minimal="$TEST_ROOT/schema-valid-minimal.json"
    valid_full="$TEST_ROOT/schema-valid-full.json"

    bad_no_version="$TEST_ROOT/schema-bad-no-version.json"
    bad_version="$TEST_ROOT/schema-bad-version.json"
    bad_unknown_root="$TEST_ROOT/schema-bad-unknown-root.json"
    bad_unknown_nested="$TEST_ROOT/schema-bad-unknown-nested.json"
    bad_section_type="$TEST_ROOT/schema-bad-section-type.json"
    bad_output_type="$TEST_ROOT/schema-bad-output-type.json"
    bad_color_enum="$TEST_ROOT/schema-bad-color-enum.json"
    bad_modules_type="$TEST_ROOT/schema-bad-modules-type.json"
    bad_modules_elem="$TEST_ROOT/schema-bad-modules-elem.json"
    bad_timeout_type="$TEST_ROOT/schema-bad-timeout-type.json"
    bad_format_enum="$TEST_ROOT/schema-bad-format-enum.json"
    bad_no_report_type="$TEST_ROOT/schema-bad-no-report-type.json"
    bad_logfile_type="$TEST_ROOT/schema-bad-logfile-type.json"
    case_format="$TEST_ROOT/schema-case-format.json"

    printf '%s\n' '{"schema_version":1}' > "$valid_minimal"

    cat > "$valid_full" <<'JSON'
{
  "schema_version": 1,
  "general": {"output_dir": "results", "color": "auto"},
  "scanning": {"modules": [], "exclude_modules": [], "profile": "", "ports": "", "wordlist": ""},
  "execution": {"timeout": 300, "threads": 10, "rate_limit": 5, "retries": 2},
  "reporting": {"formats": ["JSON", "MD"], "no_report": false, "log_file": ""}
}
JSON

    printf '%s\n' '{}' > "$bad_no_version"
    printf '%s\n' '{"schema_version":2}' > "$bad_version"
    printf '%s\n' '{"schema_version":1,"bogus":{}}' > "$bad_unknown_root"
    printf '%s\n' '{"schema_version":1,"general":{"bogus":1}}' > "$bad_unknown_nested"
    printf '%s\n' '{"schema_version":1,"general":[]}' > "$bad_section_type"
    printf '%s\n' '{"schema_version":1,"general":{"output_dir":5}}' > "$bad_output_type"
    printf '%s\n' '{"schema_version":1,"general":{"color":"purple"}}' > "$bad_color_enum"
    printf '%s\n' '{"schema_version":1,"scanning":{"modules":"x"}}' > "$bad_modules_type"
    printf '%s\n' '{"schema_version":1,"scanning":{"modules":[1]}}' > "$bad_modules_elem"
    printf '%s\n' '{"schema_version":1,"execution":{"timeout":1.5}}' > "$bad_timeout_type"
    printf '%s\n' '{"schema_version":1,"reporting":{"formats":["PDF"]}}' > "$bad_format_enum"
    printf '%s\n' '{"schema_version":1,"reporting":{"no_report":"yes"}}' > "$bad_no_report_type"
    printf '%s\n' '{"schema_version":1,"reporting":{"log_file":5}}' > "$bad_logfile_type"
    printf '%s\n' '{"schema_version":1,"reporting":{"formats":["json","Md"]}}' > "$case_format"

    # Test 1: Valid minimal configuration is accepted.
    config_init
    CONFIG_FILE="$valid_minimal"

    if config_load; then
        if [[ "$CONFIG_LOADED" == true && "$CONFIG_ERROR" == "" ]]; then
            pass "Schema: valid minimal configuration accepted"
        else
            fail "Schema: valid minimal configuration accepted (incorrect state)"
        fi
    else
        fail "Schema: valid minimal configuration accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 2: Valid full configuration is accepted.
    config_init
    CONFIG_FILE="$valid_full"

    if config_load; then
        if [[ "$CONFIG_LOADED" == true && "$CONFIG_ERROR" == "" ]]; then
            pass "Schema: valid full configuration accepted"
        else
            fail "Schema: valid full configuration accepted (incorrect state)"
        fi
    else
        fail "Schema: valid full configuration accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 3: Missing schema_version is rejected.
    config_init
    CONFIG_FILE="$bad_no_version"

    if config_load; then
        fail "Schema: missing schema_version rejected"
    elif [[ "$CONFIG_LOADED" == false && "$CONFIG_ERROR" == *"schema_version: missing"* ]]; then
        pass "Schema: missing schema_version rejected"
    else
        fail "Schema: missing schema_version rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 4: Unsupported schema version is rejected.
    config_init
    CONFIG_FILE="$bad_version"

    if config_load; then
        fail "Schema: unsupported schema_version rejected"
    elif [[ "$CONFIG_ERROR" == *"schema_version: expected 1"* ]]; then
        pass "Schema: unsupported schema_version rejected"
    else
        fail "Schema: unsupported schema_version rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 5: Unknown top-level key is rejected.
    config_init
    CONFIG_FILE="$bad_unknown_root"

    if config_load; then
        fail "Schema: unknown top-level key rejected"
    elif [[ "$CONFIG_ERROR" == *"bogus: unknown key"* ]]; then
        pass "Schema: unknown top-level key rejected"
    else
        fail "Schema: unknown top-level key rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 6: Unknown nested key is rejected.
    config_init
    CONFIG_FILE="$bad_unknown_nested"

    if config_load; then
        fail "Schema: unknown nested key rejected"
    elif [[ "$CONFIG_ERROR" == *"general.bogus: unknown key"* ]]; then
        pass "Schema: unknown nested key rejected"
    else
        fail "Schema: unknown nested key rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 7: Section with wrong type is rejected.
    config_init
    CONFIG_FILE="$bad_section_type"

    if config_load; then
        fail "Schema: section wrong type rejected"
    elif [[ "$CONFIG_ERROR" == *"general: expected object"* ]]; then
        pass "Schema: section wrong type rejected"
    else
        fail "Schema: section wrong type rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 8: output_dir wrong type is rejected.
    config_init
    CONFIG_FILE="$bad_output_type"

    if config_load; then
        fail "Schema: general.output_dir wrong type rejected"
    elif [[ "$CONFIG_ERROR" == *"general.output_dir: expected string"* ]]; then
        pass "Schema: general.output_dir wrong type rejected"
    else
        fail "Schema: general.output_dir wrong type rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 9: Invalid color enum is rejected.
    config_init
    CONFIG_FILE="$bad_color_enum"

    if config_load; then
        fail "Schema: invalid general.color rejected"
    elif [[ "$CONFIG_ERROR" == *"general.color: expected one of"* ]]; then
        pass "Schema: invalid general.color rejected"
    else
        fail "Schema: invalid general.color rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 10: modules wrong type is rejected.
    config_init
    CONFIG_FILE="$bad_modules_type"

    if config_load; then
        fail "Schema: scanning.modules wrong type rejected"
    elif [[ "$CONFIG_ERROR" == *"scanning.modules: expected array"* ]]; then
        pass "Schema: scanning.modules wrong type rejected"
    else
        fail "Schema: scanning.modules wrong type rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 11: modules with non-string element is rejected.
    config_init
    CONFIG_FILE="$bad_modules_elem"

    if config_load; then
        fail "Schema: scanning.modules non-string element rejected"
    elif [[ "$CONFIG_ERROR" == *"scanning.modules: array elements must be strings"* ]]; then
        pass "Schema: scanning.modules non-string element rejected"
    else
        fail "Schema: scanning.modules non-string element rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 12: Non-integer timeout is rejected.
    config_init
    CONFIG_FILE="$bad_timeout_type"

    if config_load; then
        fail "Schema: non-integer execution.timeout rejected"
    elif [[ "$CONFIG_ERROR" == *"execution.timeout: expected integer"* ]]; then
        pass "Schema: non-integer execution.timeout rejected"
    else
        fail "Schema: non-integer execution.timeout rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 13: Unsupported report format is rejected.
    config_init
    CONFIG_FILE="$bad_format_enum"

    if config_load; then
        fail "Schema: unsupported report format rejected"
    elif [[ "$CONFIG_ERROR" == *"reporting.formats: unsupported format"* ]]; then
        pass "Schema: unsupported report format rejected"
    else
        fail "Schema: unsupported report format rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 14: Non-boolean no_report is rejected.
    config_init
    CONFIG_FILE="$bad_no_report_type"

    if config_load; then
        fail "Schema: non-boolean reporting.no_report rejected"
    elif [[ "$CONFIG_ERROR" == *"reporting.no_report: expected boolean"* ]]; then
        pass "Schema: non-boolean reporting.no_report rejected"
    else
        fail "Schema: non-boolean reporting.no_report rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 15: Non-string log_file is rejected.
    config_init
    CONFIG_FILE="$bad_logfile_type"

    if config_load; then
        fail "Schema: non-string reporting.log_file rejected"
    elif [[ "$CONFIG_ERROR" == *"reporting.log_file: expected string"* ]]; then
        pass "Schema: non-string reporting.log_file rejected"
    else
        fail "Schema: non-string reporting.log_file rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 16: Case-insensitive report formats are accepted by schema.
    config_init
    CONFIG_FILE="$case_format"

    if config_load; then
        if [[ "$CONFIG_LOADED" == true && "$CONFIG_ERROR" == "" ]]; then
            pass "Schema: case-insensitive report formats accepted"
        else
            fail "Schema: case-insensitive report formats accepted (incorrect state)"
        fi
    else
        fail "Schema: case-insensitive report formats accepted (load failed: $CONFIG_ERROR)"
    fi

    CONFIG_FILE=""
    CONFIG_ERROR=""
}

# Run UT-01 through UT-06.
test_config_initialization
test_config_dependencies
test_config_file_validation
test_config_loading
test_config_optional_loading
test_config_schema_validation

test_summary
