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

# Load the CLI component (provides _cli_valid_modules, a shared
# dependency of configuration value validation).
# shellcheck source=core/cli.sh
if ! source "$PROJECT_ROOT/core/cli.sh"; then
    printf 'Error: Unable to load CLI component.\n' >&2
    exit 1
fi

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

    # Test 3: Effective state is reset to empty.
    if [[ "$CONFIG_EFFECTIVE_OUTPUT_DIR" == "" &&
          "$CONFIG_EFFECTIVE_COLOR" == "" &&
          "$CONFIG_EFFECTIVE_PROFILE" == "" &&
          "$CONFIG_EFFECTIVE_TIMEOUT" == "" &&
          "$CONFIG_EFFECTIVE_THREADS" == "" &&
          "$CONFIG_EFFECTIVE_RATE_LIMIT" == "" &&
          "$CONFIG_EFFECTIVE_RETRIES" == "" &&
          "$CONFIG_EFFECTIVE_NO_REPORT" == "" &&
          "$CONFIG_EFFECTIVE_LOG_FILE" == "" &&
          "$CONFIG_EFFECTIVE_TARGET" == "" &&
          "$CONFIG_EFFECTIVE_TARGETS_FILE" == "" &&
          "$CONFIG_EFFECTIVE_NETWORK" == false &&
          "$CONFIG_EFFECTIVE_WEB" == false &&
          ${#CONFIG_EFFECTIVE_MODULES[@]} -eq 0 &&
          ${#CONFIG_EFFECTIVE_EXCLUDE_MODULES[@]} -eq 0 &&
          ${#CONFIG_EFFECTIVE_FORMATS[@]} -eq 0 ]]; then
        pass "Effective state reset to empty"
    else
        fail "Effective state reset to empty"
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

# UT-07: Configuration value validation tests.
test_config_values() {

    printf '\n%s\n' "UT-07: Configuration Value Validation"

    local valid_full valid_wordlist no_wordlist bad_wordlist
    local bad_timeout bad_timeout_neg bad_threads bad_rate_limit
    local good_retries bad_retries
    local good_modules bad_modules bad_exclude
    local norm_formats conflict_no_report_no_formats conflict_no_report_with_formats
    local no_conflict

    valid_full="$TEST_ROOT/values-valid-full.json"
    valid_wordlist="$TEST_ROOT/values-valid-wordlist.json"
    no_wordlist="$TEST_ROOT/values-no-wordlist.json"
    bad_wordlist="$TEST_ROOT/values-bad-wordlist.json"
    bad_timeout="$TEST_ROOT/values-bad-timeout.json"
    bad_timeout_neg="$TEST_ROOT/values-bad-timeout-neg.json"
    bad_threads="$TEST_ROOT/values-bad-threads.json"
    bad_rate_limit="$TEST_ROOT/values-bad-rate-limit.json"
    good_retries="$TEST_ROOT/values-good-retries.json"
    bad_retries="$TEST_ROOT/values-bad-retries.json"
    good_modules="$TEST_ROOT/values-good-modules.json"
    bad_modules="$TEST_ROOT/values-bad-modules.json"
    bad_exclude="$TEST_ROOT/values-bad-exclude.json"
    norm_formats="$TEST_ROOT/values-norm-formats.json"
    conflict_no_report_no_formats="$TEST_ROOT/values-conflict-no-report-empty.json"
    conflict_no_report_with_formats="$TEST_ROOT/values-conflict-no-report-formats.json"
    no_conflict="$TEST_ROOT/values-no-conflict.json"

    # A wordlist file that exists and is readable.
    printf '%s\n' 'common' 'admin' > "$TEST_ROOT/words.txt"

    cat > "$valid_full" <<JSON
{
  "schema_version": 1,
  "execution": {"timeout": 300, "threads": 10, "rate_limit": 5, "retries": 2},
  "scanning": {"modules": [], "exclude_modules": [], "wordlist": ""},
  "reporting": {"formats": ["JSON"], "no_report": false}
}
JSON

    cat > "$valid_wordlist" <<JSON
{
  "schema_version": 1,
  "scanning": {"wordlist": "$TEST_ROOT/words.txt"}
}
JSON

    cat > "$no_wordlist" <<'JSON'
{"schema_version": 1, "scanning": {"wordlist": ""}}
JSON

    cat > "$bad_wordlist" <<'JSON'
{"schema_version": 1, "scanning": {"wordlist": "/does/not/exist.txt"}}
JSON

    cat > "$bad_timeout" <<'JSON'
{"schema_version": 1, "execution": {"timeout": 0}}
JSON

    cat > "$bad_timeout_neg" <<'JSON'
{"schema_version": 1, "execution": {"timeout": -5}}
JSON

    cat > "$bad_threads" <<'JSON'
{"schema_version": 1, "execution": {"threads": 0}}
JSON

    cat > "$bad_rate_limit" <<'JSON'
{"schema_version": 1, "execution": {"rate_limit": 0}}
JSON

    cat > "$good_retries" <<'JSON'
{"schema_version": 1, "execution": {"retries": 0}}
JSON

    cat > "$bad_retries" <<'JSON'
{"schema_version": 1, "execution": {"retries": -1}}
JSON

    cat > "$good_modules" <<'JSON'
{"schema_version": 1, "scanning": {"modules": ["host", "dns", "http-probe"]}}
JSON

    cat > "$bad_modules" <<'JSON'
{"schema_version": 1, "scanning": {"modules": ["host", "bogus"]}}
JSON

    cat > "$bad_exclude" <<'JSON'
{"schema_version": 1, "scanning": {"exclude_modules": ["bogus"]}}
JSON

    cat > "$norm_formats" <<'JSON'
{"schema_version": 1, "reporting": {"formats": ["json", "Md"]}}
JSON

    cat > "$conflict_no_report_no_formats" <<'JSON'
{"schema_version": 1, "reporting": {"no_report": true, "formats": []}}
JSON

    cat > "$conflict_no_report_with_formats" <<'JSON'
{"schema_version": 1, "reporting": {"no_report": true, "formats": ["JSON"]}}
JSON

    cat > "$no_conflict" <<'JSON'
{"schema_version": 1, "reporting": {"no_report": false, "formats": ["JSON"]}}
JSON

    # Test 1: Full valid config is accepted.
    config_init
    CONFIG_FILE="$valid_full"

    if config_load; then
        pass "Values: full valid config accepted"
    else
        fail "Values: full valid config accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 2: timeout 0 is rejected.
    config_init
    CONFIG_FILE="$bad_timeout"

    if config_load; then
        fail "Values: timeout 0 rejected"
    elif [[ "$CONFIG_ERROR" == *"execution.timeout: must be at least 1"* ]]; then
        pass "Values: timeout 0 rejected"
    else
        fail "Values: timeout 0 rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 3: negative timeout is rejected.
    config_init
    CONFIG_FILE="$bad_timeout_neg"

    if config_load; then
        fail "Values: negative timeout rejected"
    elif [[ "$CONFIG_ERROR" == *"execution.timeout: must be at least 1"* ]]; then
        pass "Values: negative timeout rejected"
    else
        fail "Values: negative timeout rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 4: threads 0 is rejected.
    config_init
    CONFIG_FILE="$bad_threads"

    if config_load; then
        fail "Values: threads 0 rejected"
    elif [[ "$CONFIG_ERROR" == *"execution.threads: must be at least 1"* ]]; then
        pass "Values: threads 0 rejected"
    else
        fail "Values: threads 0 rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 5: rate_limit 0 is rejected.
    config_init
    CONFIG_FILE="$bad_rate_limit"

    if config_load; then
        fail "Values: rate_limit 0 rejected"
    elif [[ "$CONFIG_ERROR" == *"execution.rate_limit: must be at least 1"* ]]; then
        pass "Values: rate_limit 0 rejected"
    else
        fail "Values: rate_limit 0 rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 6: retries 0 is accepted.
    config_init
    CONFIG_FILE="$good_retries"

    if config_load; then
        pass "Values: retries 0 accepted"
    else
        fail "Values: retries 0 accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 7: negative retries is rejected.
    config_init
    CONFIG_FILE="$bad_retries"

    if config_load; then
        fail "Values: negative retries rejected"
    elif [[ "$CONFIG_ERROR" == *"execution.retries: must be at least 0"* ]]; then
        pass "Values: negative retries rejected"
    else
        fail "Values: negative retries rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 8: missing wordlist file is rejected.
    config_init
    CONFIG_FILE="$bad_wordlist"

    if config_load; then
        fail "Values: missing wordlist rejected"
    elif [[ "$CONFIG_ERROR" == *"scanning.wordlist: file does not exist"* ]]; then
        pass "Values: missing wordlist rejected"
    else
        fail "Values: missing wordlist rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 9: empty wordlist is accepted.
    config_init
    CONFIG_FILE="$no_wordlist"

    if config_load; then
        pass "Values: empty wordlist accepted"
    else
        fail "Values: empty wordlist accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 10: readable wordlist is accepted.
    config_init
    CONFIG_FILE="$valid_wordlist"

    if config_load; then
        pass "Values: readable wordlist accepted"
    else
        fail "Values: readable wordlist accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 11: valid modules are accepted.
    config_init
    CONFIG_FILE="$good_modules"

    if config_load; then
        pass "Values: valid modules accepted"
    else
        fail "Values: valid modules accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 12: invalid module is rejected.
    config_init
    CONFIG_FILE="$bad_modules"

    if config_load; then
        fail "Values: invalid module rejected"
    elif [[ "$CONFIG_ERROR" == *"scanning.modules: invalid module identifier: bogus"* ]]; then
        pass "Values: invalid module rejected"
    else
        fail "Values: invalid module rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 13: invalid excluded module is rejected.
    config_init
    CONFIG_FILE="$bad_exclude"

    if config_load; then
        fail "Values: invalid excluded module rejected"
    elif [[ "$CONFIG_ERROR" == *"scanning.exclude_modules: invalid module identifier: bogus"* ]]; then
        pass "Values: invalid excluded module rejected"
    else
        fail "Values: invalid excluded module rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 14: formats are normalized to uppercase in stored config.
    config_init
    CONFIG_FILE="$norm_formats"

    if config_load; then
        if [[ "$CONFIG_JSON" == *'"JSON"'* && "$CONFIG_JSON" == *'"MD"'* && \
              "$CONFIG_JSON" != *'"json"'* && "$CONFIG_JSON" != *'"Md"'* ]]; then
            pass "Values: formats normalized to uppercase"
        else
            fail "Values: formats normalized to uppercase (stored: $CONFIG_JSON)"
        fi
    else
        fail "Values: formats normalized to uppercase (load failed: $CONFIG_ERROR)"
    fi

    # Test 15: no_report with non-empty formats is rejected.
    config_init
    CONFIG_FILE="$conflict_no_report_with_formats"

    if config_load; then
        fail "Values: no_report+formats conflict rejected"
    elif [[ "$CONFIG_ERROR" == *"reporting.no_report: cannot be combined"* ]]; then
        pass "Values: no_report+formats conflict rejected"
    else
        fail "Values: no_report+formats conflict rejected (incorrect error: $CONFIG_ERROR)"
    fi

    # Test 16: no_report with empty formats is accepted.
    config_init
    CONFIG_FILE="$conflict_no_report_no_formats"

    if config_load; then
        pass "Values: no_report with empty formats accepted"
    else
        fail "Values: no_report with empty formats accepted (load failed: $CONFIG_ERROR)"
    fi

    # Test 17: no_report false with formats is accepted.
    config_init
    CONFIG_FILE="$no_conflict"

    if config_load; then
        pass "Values: no_report false with formats accepted"
    else
        fail "Values: no_report false with formats accepted (load failed: $CONFIG_ERROR)"
    fi

    CONFIG_FILE=""
    CONFIG_ERROR=""
}

# UT-08: Configuration application tests.
test_config_apply() {

    printf '\n%s\n' "UT-08: Configuration Application"

    local no_file defaults_only overrides

    no_file="$TEST_ROOT/apply-no-file.txt"
    defaults_only="$TEST_ROOT/apply-defaults.json"
    overrides="$TEST_ROOT/apply-overrides.json"

    : > "$no_file"

    printf '%s\n' '{"schema_version":1}' > "$defaults_only"

    cat > "$overrides" <<JSON
{
  "schema_version": 1,
  "general": {"output_dir": "custom-out", "color": "always"},
  "scanning": {"modules": ["host", "dns"], "exclude_modules": ["ftp"], "profile": "full", "ports": "1-1000", "wordlist": ""},
  "execution": {"timeout": 60, "threads": 4, "rate_limit": 2, "retries": 1},
  "reporting": {"formats": ["JSON", "MD"], "no_report": false, "log_file": "/tmp/reckon.log"}
}
JSON

    # Test 1: No config file — defaults applied.
    config_init
    CONFIG_FILE=""

    if config_load; then
        if [[ "$CONFIG_EFFECTIVE_OUTPUT_DIR" == "results" &&
              "$CONFIG_EFFECTIVE_COLOR" == "auto" &&
              "$CONFIG_EFFECTIVE_TIMEOUT" == "300" &&
              "$CONFIG_EFFECTIVE_THREADS" == "10" &&
              "$CONFIG_EFFECTIVE_RATE_LIMIT" == "5" &&
              "$CONFIG_EFFECTIVE_RETRIES" == "2" &&
              "$CONFIG_EFFECTIVE_NO_REPORT" == "false" &&
              ${#CONFIG_EFFECTIVE_MODULES[@]} -eq 0 &&
              ${#CONFIG_EFFECTIVE_FORMATS[@]} -eq 0 ]]; then
            pass "No config file applies schema defaults"
        else
            fail "No config file applies schema defaults (incorrect state)"
        fi
    else
        fail "No config file applies schema defaults (load failed: $CONFIG_ERROR)"
    fi

    # Test 2: Empty config file (only schema_version) — defaults applied.
    config_init
    CONFIG_FILE="$defaults_only"

    if config_load; then
        if [[ "$CONFIG_EFFECTIVE_OUTPUT_DIR" == "results" &&
              "$CONFIG_EFFECTIVE_TIMEOUT" == "300" &&
              "$CONFIG_EFFECTIVE_RETRIES" == "2" ]]; then
            pass "Schema-only config applies defaults"
        else
            fail "Schema-only config applies defaults (incorrect state)"
        fi
    else
        fail "Schema-only config applies defaults (load failed: $CONFIG_ERROR)"
    fi

    # Test 3: Full config — all effective values reflect file.
    config_init
    CONFIG_FILE="$overrides"

    if config_load; then
        if [[ "$CONFIG_EFFECTIVE_OUTPUT_DIR" == "custom-out" &&
              "$CONFIG_EFFECTIVE_COLOR" == "always" &&
              "$CONFIG_EFFECTIVE_PROFILE" == "full" &&
              "$CONFIG_EFFECTIVE_PORTS" == "1-1000" &&
              "$CONFIG_EFFECTIVE_TIMEOUT" == "60" &&
              "$CONFIG_EFFECTIVE_THREADS" == "4" &&
              "$CONFIG_EFFECTIVE_RATE_LIMIT" == "2" &&
              "$CONFIG_EFFECTIVE_RETRIES" == "1" &&
              "$CONFIG_EFFECTIVE_NO_REPORT" == "false" &&
              "$CONFIG_EFFECTIVE_LOG_FILE" == "/tmp/reckon.log" &&
              ${#CONFIG_EFFECTIVE_MODULES[@]} -eq 2 &&
              "${CONFIG_EFFECTIVE_MODULES[0]}" == "host" &&
              "${CONFIG_EFFECTIVE_MODULES[1]}" == "dns" &&
              ${#CONFIG_EFFECTIVE_EXCLUDE_MODULES[@]} -eq 1 &&
              "${CONFIG_EFFECTIVE_EXCLUDE_MODULES[0]}" == "ftp" &&
              ${#CONFIG_EFFECTIVE_FORMATS[@]} -eq 2 &&
              "${CONFIG_EFFECTIVE_FORMATS[0]}" == "JSON" &&
              "${CONFIG_EFFECTIVE_FORMATS[1]}" == "MD" ]]; then
            pass "Full config populates all effective values"
        else
            fail "Full config populates all effective values (incorrect state: out=$CONFIG_EFFECTIVE_OUTPUT_DIR timeout=$CONFIG_EFFECTIVE_TIMEOUT modules=${CONFIG_EFFECTIVE_MODULES[*]})"
        fi
    else
        fail "Full config populates all effective values (load failed: $CONFIG_ERROR)"
    fi

    CONFIG_FILE=""
    CONFIG_ERROR=""
}

# UT-09: CLI/config/default precedence tests.
test_config_apply_cli() {

    printf '\n%s\n' "UT-09: CLI/Config/Default Precedence"

    # A config file that sets non-default values.
    local cfg="$TEST_ROOT/apply-cli-config.json"
    cat > "$cfg" <<'JSON'
{
  "schema_version": 1,
  "general": {"output_dir": "from-config", "color": "always"},
  "scanning": {"modules": ["port"], "exclude_modules": ["ftp"], "profile": "full", "ports": "1-1000", "wordlist": ""},
  "execution": {"timeout": 60, "threads": 4, "rate_limit": 2, "retries": 2},
  "reporting": {"formats": ["MD"], "no_report": false, "log_file": "/tmp/from-config.log"}
}
JSON

    # Test 1: No CLI supplied — effective values from config.
    config_init
    cli_init
    CONFIG_FILE="$cfg"
    if config_load; then :; else fail "Test setup: config_load failed: $CONFIG_ERROR"; fi
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_TIMEOUT" == "60" &&
          "$CONFIG_EFFECTIVE_OUTPUT_DIR" == "from-config" &&
          "$CONFIG_EFFECTIVE_COLOR" == "always" ]]; then
        pass "No CLI: config values preserved"
    else
        fail "No CLI: config values preserved (timeout=$CONFIG_EFFECTIVE_TIMEOUT output_dir=$CONFIG_EFFECTIVE_OUTPUT_DIR color=$CONFIG_EFFECTIVE_COLOR)"
    fi

    # Test 2: CLI --timeout 300 explicitly overrides config timeout 60.
    config_init
    cli_init
    cli_parse_args --timeout 300 || fail "Test setup: parse --timeout"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_TIMEOUT" == "300" ]]; then
        pass "CLI timeout explicitly overrides config"
    else
        fail "CLI timeout explicitly overrides config (got: $CONFIG_EFFECTIVE_TIMEOUT)"
    fi

    # Test 3: CLI --retries 0 explicitly overrides config retries 2 (explicit tracking catches zero).
    config_init
    cli_init
    cli_parse_args --retries 0 || fail "Test setup: parse --retries 0"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_RETRIES" == "0" ]]; then
        pass "CLI retries 0 explicitly overrides config (zero is real value)"
    else
        fail "CLI retries 0 explicitly overrides config (got: $CONFIG_EFFECTIVE_RETRIES)"
    fi

    # Test 4: CLI --output custom/ overrides config output_dir.
    config_init
    cli_init
    cli_parse_args --output custom/ || fail "Test setup: parse --output"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_OUTPUT_DIR" == "custom/" ]]; then
        pass "CLI output_dir overrides config"
    else
        fail "CLI output_dir overrides config (got: $CONFIG_EFFECTIVE_OUTPUT_DIR)"
    fi

    # Test 5: CLI --color overrides config color.
    config_init
    cli_init
    cli_parse_args --color || fail "Test setup: parse --color"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_COLOR" == "always" ]]; then
        pass "CLI color overrides config"
    else
        fail "CLI color overrides config (got: $CONFIG_EFFECTIVE_COLOR)"
    fi

    # Test 6: CLI --module host,dns replaces config modules [port] (array replacement, not merge).
    config_init
    cli_init
    cli_parse_args --module host,dns || fail "Test setup: parse --module"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ ${#CONFIG_EFFECTIVE_MODULES[@]} -eq 2 &&
          "${CONFIG_EFFECTIVE_MODULES[0]}" == "host" &&
          "${CONFIG_EFFECTIVE_MODULES[1]}" == "dns" ]]; then
        pass "CLI modules array replaces config modules (no merge)"
    else
        fail "CLI modules array replaces config modules (got: ${CONFIG_EFFECTIVE_MODULES[*]})"
    fi

    # Test 7: CLI --exclude replaces config exclude_modules.
    config_init
    cli_init
    cli_parse_args --exclude ssh,telnet || fail "Test setup: parse --exclude"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ ${#CONFIG_EFFECTIVE_EXCLUDE_MODULES[@]} -eq 2 &&
          "${CONFIG_EFFECTIVE_EXCLUDE_MODULES[0]}" == "ssh" &&
          "${CONFIG_EFFECTIVE_EXCLUDE_MODULES[1]}" == "telnet" ]]; then
        pass "CLI exclude_modules array replaces config"
    else
        fail "CLI exclude_modules array replaces config (got: ${CONFIG_EFFECTIVE_EXCLUDE_MODULES[*]})"
    fi

    # Test 8: CLI --format JSON replaces config formats [MD].
    config_init
    cli_init
    cli_parse_args --format JSON || fail "Test setup: parse --format"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ ${#CONFIG_EFFECTIVE_FORMATS[@]} -eq 1 &&
          "${CONFIG_EFFECTIVE_FORMATS[0]}" == "JSON" ]]; then
        pass "CLI formats array replaces config formats"
    else
        fail "CLI formats array replaces config formats (got: ${CONFIG_EFFECTIVE_FORMATS[*]})"
    fi

    # Test 9: CLI --no-report overrides config no_report false.
    config_init
    cli_init
    cli_parse_args --no-report || fail "Test setup: parse --no-report"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_NO_REPORT" == "true" ]]; then
        pass "CLI no_report overrides config"
    else
        fail "CLI no_report overrides config (got: $CONFIG_EFFECTIVE_NO_REPORT)"
    fi

    # Test 10: CLI --profile overrides config profile.
    config_init
    cli_init
    cli_parse_args --profile quick || fail "Test setup: parse --profile"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_PROFILE" == "quick" ]]; then
        pass "CLI profile overrides config"
    else
        fail "CLI profile overrides config (got: $CONFIG_EFFECTIVE_PROFILE)"
    fi

    # Test 11: CLI --target sets effective target.
    config_init
    cli_init
    cli_parse_args --target example.com || fail "Test setup: parse --target"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_TARGET" == "example.com" ]]; then
        pass "CLI target sets effective target"
    else
        fail "CLI target sets effective target (got: $CONFIG_EFFECTIVE_TARGET)"
    fi

    # Test 12: CLI --network sets effective network.
    config_init
    cli_init
    cli_parse_args --network || fail "Test setup: parse --network"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_NETWORK" == "true" ]]; then
        pass "CLI --network sets effective network"
    else
        fail "CLI --network sets effective network (got: $CONFIG_EFFECTIVE_NETWORK)"
    fi

    # Test 13: CLI --ports overrides config ports.
    config_init
    cli_init
    cli_parse_args --ports 22,80,443 || fail "Test setup: parse --ports"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_PORTS" == "22,80,443" ]]; then
        pass "CLI ports overrides config"
    else
        fail "CLI ports overrides config (got: $CONFIG_EFFECTIVE_PORTS)"
    fi

    # Test 14: CLI --log-file overrides config log_file.
    config_init
    cli_init
    cli_parse_args --log-file /tmp/cli.log || fail "Test setup: parse --log-file"
    CONFIG_FILE="$cfg"
    config_load || fail "Test setup: config_load: $CONFIG_ERROR"
    config_apply_cli

    if [[ "$CONFIG_EFFECTIVE_LOG_FILE" == "/tmp/cli.log" ]]; then
        pass "CLI log_file overrides config"
    else
        fail "CLI log_file overrides config (got: $CONFIG_EFFECTIVE_LOG_FILE)"
    fi
}

# Run UT-01 through UT-09.
test_config_initialization
test_config_dependencies
test_config_file_validation
test_config_loading
test_config_optional_loading
test_config_schema_validation
test_config_values
test_config_apply
test_config_apply_cli

test_summary
