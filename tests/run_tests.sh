#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Unified Test Runner & Suite Orchestrator (tests/run_tests.sh)
#
# Dispatches unit tests, integration pipelines, security audits, and linting
# with granular batch filtering to enable lightweight, targeted execution:
#
#   ./tests/run_tests.sh --unit-core
#   ./tests/run_tests.sh --unit-lib
#   ./tests/run_tests.sh --unit-net
#   ./tests/run_tests.sh --unit-web
#   ./tests/run_tests.sh --integration
#   ./tests/run_tests.sh --security
#   ./tests/run_tests.sh --lint
#   ./tests/run_tests.sh tests/unit/test_cli.sh
#

set -o nounset

# Script and Project Root Directories
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# Temporary working directory for runner state and outputs
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reckon-runner.XXXXXX")" || {
    printf 'Error: Failed to create runner temporary directory.\n' >&2
    exit 1
}
readonly TMP_DIR

# Terminal color configuration
USE_COLOR=true
if [[ ! -t 1 ]] || [[ "${NO_COLOR:-}" != "" ]] || [[ "${TERM:-}" == "dumb" ]]; then
    USE_COLOR=false
fi

setup_colors() {
    if [[ "$USE_COLOR" == true ]]; then
        C_RESET="$(printf '\033[0m')"
        C_BOLD="$(printf '\033[1m')"
        C_GREEN="$(printf '\033[32m')"
        C_RED="$(printf '\033[31m')"
        C_YELLOW="$(printf '\033[33m')"
        C_BLUE="$(printf '\033[34m')"
        C_CYAN="$(printf '\033[36m')"
        C_GRAY="$(printf '\033[90m')"
    else
        C_RESET=""
        C_BOLD=""
        C_GREEN=""
        C_RED=""
        C_YELLOW=""
        C_BLUE=""
        C_CYAN=""
        C_GRAY=""
    fi
}
setup_colors

# Active child process tracker for signal handling
CURRENT_CHILD_PID=""

# shellcheck disable=SC2329
cleanup_runner() {
    local exit_code=$?
    if [[ -n "$CURRENT_CHILD_PID" ]] && kill -0 "$CURRENT_CHILD_PID" 2>/dev/null; then
        kill -TERM "$CURRENT_CHILD_PID" 2>/dev/null || true
        wait "$CURRENT_CHILD_PID" 2>/dev/null || true
    fi
    rm -rf -- "$TMP_DIR"
    exit "$exit_code"
}

# shellcheck disable=SC2329
handle_interrupt() {
    printf '\n%s[ABORTED]%s Test execution interrupted by user.\n' "$C_RED$C_BOLD" "$C_RESET" >&2
    if [[ -n "$CURRENT_CHILD_PID" ]] && kill -0 "$CURRENT_CHILD_PID" 2>/dev/null; then
        kill -KILL "$CURRENT_CHILD_PID" 2>/dev/null || true
    fi
    rm -rf -- "$TMP_DIR"
    exit 130
}

# shellcheck disable=SC2329
handle_terminate() {
    printf '\n%s[TERMINATED]%s Test runner terminated.\n' "$C_RED$C_BOLD" "$C_RESET" >&2
    if [[ -n "$CURRENT_CHILD_PID" ]] && kill -0 "$CURRENT_CHILD_PID" 2>/dev/null; then
        kill -KILL "$CURRENT_CHILD_PID" 2>/dev/null || true
    fi
    rm -rf -- "$TMP_DIR"
    exit 143
}

trap cleanup_runner EXIT
trap handle_interrupt INT
trap handle_terminate TERM

# Display Usage Information
print_usage() {
    cat << EOF
${C_BOLD}RECKON - Unified Test Runner${C_RESET}

${C_YELLOW}Usage:${C_RESET}
  ./tests/run_tests.sh [OPTIONS] [SUITE...]

${C_YELLOW}Granular Split Execution Batches (Recommended):${C_RESET}
  --unit-core         Run core CLI, config, target and engine tests (4 suites)
  --unit-lib          Run shared utility library tests (8 suites)
  --unit-net          Run network reconnaissance module tests (13 suites)
  --unit-web          Run web enumeration module tests (15 suites)
  --unit              Run all 40 unit test suites in sequential batches
  --integration       Run all end-to-end integration pipeline tests (8 suites)
  --security          Run repository security audit and hardening suite (1 suite)
  --lint              Run static code quality and ShellCheck linting harness
  --all               Run all 49 test suites and static analysis checks

${C_YELLOW}Execution & Output Modifiers:${C_RESET}
  -v, --verbose       Stream full test output in real time
  -q, --quiet         Only print failures and final execution summary
  -x, --fail-fast     Abort immediately upon the first failed suite
  -l, --list          List all discovered suites for selected batch without running
      --no-color      Disable ANSI color highlighting
  -h, --help          Display this help message and exit

${C_YELLOW}Examples:${C_RESET}
  ./tests/run_tests.sh --unit-core
  ./tests/run_tests.sh --unit-lib
  ./tests/run_tests.sh --unit-net
  ./tests/run_tests.sh --unit-web
  ./tests/run_tests.sh --integration
  ./tests/run_tests.sh --security
  ./tests/run_tests.sh --lint
  ./tests/run_tests.sh tests/unit/test_cli.sh tests/unit/test_targets.sh
EOF
}

# Configuration flags
VERBOSE_MODE=false
QUIET_MODE=false
FAIL_FAST=false
LIST_ONLY=false
RUN_LINT=false
SELECTED_BATCHES=""

declare -a EXPLICIT_SUITES=()

if (( $# == 0 )); then
    print_usage
    exit 0
fi

# Parse CLI options
while (( $# > 0 )); do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE_MODE=true
            shift
            ;;
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        -x|--fail-fast)
            FAIL_FAST=true
            shift
            ;;
        -l|--list)
            LIST_ONLY=true
            shift
            ;;
        --no-color)
            USE_COLOR=false
            setup_colors
            shift
            ;;
        --unit-core)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}unit_core"
            shift
            ;;
        --unit-lib)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}unit_lib"
            shift
            ;;
        --unit-net)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}unit_net"
            shift
            ;;
        --unit-web)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}unit_web"
            shift
            ;;
        --unit)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}unit_core,unit_lib,unit_net,unit_web"
            shift
            ;;
        --integration)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}integration"
            shift
            ;;
        --security)
            SELECTED_BATCHES="${SELECTED_BATCHES:+${SELECTED_BATCHES},}security"
            shift
            ;;
        --lint)
            RUN_LINT=true
            shift
            ;;
        --all)
            SELECTED_BATCHES="unit_core,unit_lib,unit_net,unit_web,integration,security"
            RUN_LINT=true
            shift
            ;;
        -*)
            printf '%sError: Unknown option: %s%s\n' "$C_RED" "$1" "$C_RESET" >&2
            printf 'Run tests/run_tests.sh --help for available options.\n' >&2
            exit 2
            ;;
        *)
            EXPLICIT_SUITES+=("$1")
            shift
            ;;
    esac
done

# Queue of test suites to run
declare -a SUITE_QUEUE=()

queue_file() {
    local file_candidate="$1"
    if [[ -f "$file_candidate" && -r "$file_candidate" ]]; then
        local existing
        for existing in "${SUITE_QUEUE[@]}"; do
            if [[ "$existing" == "$file_candidate" ]]; then
                return 0
            fi
        done
        SUITE_QUEUE+=("$file_candidate")
    fi
}

# Resolve explicit files
if (( ${#EXPLICIT_SUITES[@]} > 0 )); then
    for target in "${EXPLICIT_SUITES[@]}"; do
        if [[ -f "$target" ]]; then
            queue_file "$target"
        elif [[ -f "$PROJECT_ROOT/$target" ]]; then
            queue_file "$PROJECT_ROOT/$target"
        elif [[ -f "$PROJECT_ROOT/tests/$target" ]]; then
            queue_file "$PROJECT_ROOT/tests/$target"
        elif [[ -f "$PROJECT_ROOT/tests/unit/$target" ]]; then
            queue_file "$PROJECT_ROOT/tests/unit/$target"
        elif [[ -f "$PROJECT_ROOT/tests/integration/$target" ]]; then
            queue_file "$PROJECT_ROOT/tests/integration/$target"
        else
            printf '%sWarning: Test suite not found: %s%s\n' "$C_YELLOW" "$target" "$C_RESET" >&2
        fi
    done
fi

# Resolve selected batches
if [[ -n "$SELECTED_BATCHES" ]]; then
    IFS=',' read -r -a BATCHES <<< "$SELECTED_BATCHES"
    for batch in "${BATCHES[@]}"; do
        case "$batch" in
            unit_core)
                queue_file "$PROJECT_ROOT/tests/unit/test_cli.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_config.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_targets.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_engine.sh"
                ;;
            unit_lib)
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_common.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_deps.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_exec.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_fs.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_log.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_term.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_results.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_lib_reporting.sh"
                ;;
            unit_net)
                queue_file "$PROJECT_ROOT/tests/unit/test_module_common.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_services_common.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_host.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_port.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_service.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_os.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_dns.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_ftp.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_ssh.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_telnet.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_http.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_https.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_smb.sh"
                ;;
            unit_web)
                queue_file "$PROJECT_ROOT/tests/unit/test_web_common.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_subdomain.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_http_probe.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_tls.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_waf.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_technology.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_directory.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_file.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_vhost.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_crawl.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_endpoint.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_resources.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_cms.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_historical_urls.sh"
                queue_file "$PROJECT_ROOT/tests/unit/test_mod_http_analysis.sh"
                ;;
            integration)
                queue_file "$PROJECT_ROOT/tests/integration/test_entrypoint.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_network_pipeline.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_service_pipeline.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_web_discovery.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_web_pipeline.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_reporting_pipeline.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_signal_handling.sh"
                queue_file "$PROJECT_ROOT/tests/integration/test_error_resilience.sh"
                ;;
            security)
                queue_file "$PROJECT_ROOT/tests/security_audit.sh"
                ;;
        esac
    done
fi

# If --list was requested, print selected suites and exit
if [[ "$LIST_ONLY" == true ]]; then
    printf '%sDiscovered Test Suites (%d):%s\n' "$C_BOLD$C_CYAN" "${#SUITE_QUEUE[@]}" "$C_RESET"
    if (( ${#SUITE_QUEUE[@]} > 0 )); then
        for suite in "${SUITE_QUEUE[@]}"; do
            rel_suite="${suite#"$PROJECT_ROOT/"}"
            printf '  - %s\n' "$rel_suite"
        done
    fi
    if [[ "$RUN_LINT" == true ]]; then
        printf '  - tests/lint.sh (static analysis & shellcheck)\n'
    fi
    exit 0
fi

# Validation: At least one suite or linting requested
if (( ${#SUITE_QUEUE[@]} == 0 )) && [[ "$RUN_LINT" == false ]]; then
    printf '%sError: No test suites or batches selected.%s\n' "$C_RED" "$C_RESET" >&2
    printf 'Run tests/run_tests.sh --help for available options.\n' >&2
    exit 1
fi

# Runner Statistics
SUITES_TOTAL=0
SUITES_PASSED=0
SUITES_FAILED=0
TOTAL_ASSERTIONS_PASSED=0
TOTAL_ASSERTIONS_FAILED=0

# Timing helper (returns seconds as integer or decimal if nanoseconds supported)
get_timestamp_ms() {
    local now_ms
    now_ms="$(date +%s%3N 2>/dev/null || true)"
    if [[ "$now_ms" =~ ^[0-9]+$ ]]; then
        printf '%s' "$now_ms"
    else
        printf '%d000' "$(date +%s)"
    fi
}

format_duration() {
    local elapsed_ms="$1"
    local sec=$(( elapsed_ms / 1000 ))
    local remainder_ms=$(( elapsed_ms % 1000 ))
    local dec=$(( remainder_ms / 100 ))
    printf '%d.%ds' "$sec" "$dec"
}

GLOBAL_START_MS="$(get_timestamp_ms)"

printf '%s=============================================================%s\n' "$C_BLUE$C_BOLD" "$C_RESET"
printf '%s  RECKON - Unified Test Suite Runner%s\n' "$C_BOLD" "$C_RESET"
printf '%s=============================================================%s\n' "$C_BLUE$C_BOLD" "$C_RESET"
if (( ${#SUITE_QUEUE[@]} > 0 )); then
    printf 'Test Suites Scheduled: %s%d%s\n' "$C_CYAN$C_BOLD" "${#SUITE_QUEUE[@]}" "$C_RESET"
fi
if [[ "$RUN_LINT" == true ]]; then
    printf 'Lint Verification:     %sEnabled%s\n' "$C_CYAN" "$C_RESET"
fi
printf '%s-------------------------------------------------------------%s\n' "$C_GRAY" "$C_RESET"

# Execute a single test suite
run_suite() {
    local suite_path="${1:-}"
    if [[ -z "$suite_path" ]]; then
        return 0
    fi
    local rel_suite="${suite_path#"$PROJECT_ROOT/"}"
    local suite_name
    suite_name="$(basename "$suite_path")"
    local suite_log="$TMP_DIR/suite_${suite_name}.log"

    (( SUITES_TOTAL += 1 ))

    local suite_start_ms
    suite_start_ms="$(get_timestamp_ms)"

    if [[ "$QUIET_MODE" == false ]]; then
        printf '  %s[RUN]%s   %s...' "$C_CYAN" "$C_RESET" "$rel_suite"
    fi

    local suite_exit=0
    if [[ "$VERBOSE_MODE" == true ]]; then
        printf '\n'
        # Run directly and tee to log
        bash "$suite_path" 2>&1 | tee "$suite_log"
        suite_exit="${PIPESTATUS[0]}"
    else
        bash "$suite_path" > "$suite_log" 2>&1 || suite_exit=$?
    fi

    local suite_end_ms
    suite_end_ms="$(get_timestamp_ms)"
    local suite_duration_ms=$(( suite_end_ms - suite_start_ms ))
    local formatted_time
    formatted_time="$(format_duration "$suite_duration_ms")"

    # Extract assertion statistics from output log
    local assertions_pass=0
    local assertions_fail=0
    local pass_line fail_line
    pass_line="$(grep -E "Tests passed:[[:space:]]*[0-9]+" "$suite_log" | tail -n 1 || true)"
    fail_line="$(grep -E "Tests failed:[[:space:]]*[0-9]+" "$suite_log" | tail -n 1 || true)"

    if [[ -n "$pass_line" ]]; then
        assertions_pass="$(printf '%s' "$pass_line" | grep -o -E "[0-9]+" | tail -n 1)"
    fi
    if [[ -n "$fail_line" ]]; then
        assertions_fail="$(printf '%s' "$fail_line" | grep -o -E "[0-9]+" | tail -n 1)"
    fi

    TOTAL_ASSERTIONS_PASSED=$(( TOTAL_ASSERTIONS_PASSED + assertions_pass ))
    TOTAL_ASSERTIONS_FAILED=$(( TOTAL_ASSERTIONS_FAILED + assertions_fail ))

    if (( suite_exit == 0 )); then
        (( SUITES_PASSED += 1 ))
        if [[ "$QUIET_MODE" == false ]]; then
            if [[ "$VERBOSE_MODE" == true ]]; then
                printf '  %s[PASS]%s  %s (%d passed, %s)\n' \
                    "$C_GREEN$C_BOLD" "$C_RESET" "$rel_suite" "$assertions_pass" "$formatted_time"
            else
                # Carriage return overwrite or clean newline
                printf '\r  %s[PASS]%s  %-40s (%d passed, %s)\n' \
                    "$C_GREEN$C_BOLD" "$C_RESET" "$rel_suite" "$assertions_pass" "$formatted_time"
            fi
        fi
    else
        (( SUITES_FAILED += 1 ))
        if [[ "$VERBOSE_MODE" == false ]]; then
            printf '\r  %s[FAIL]%s  %-40s (exit status %d, %s)\n' \
                "$C_RED$C_BOLD" "$C_RESET" "$rel_suite" "$suite_exit" "$formatted_time"
        else
            printf '  %s[FAIL]%s  %s (exit status %d, %s)\n' \
                "$C_RED$C_BOLD" "$C_RESET" "$rel_suite" "$suite_exit" "$formatted_time"
        fi

        # Print failure excerpt if not in verbose mode
        if [[ "$VERBOSE_MODE" == false ]]; then
            printf '%s--- [Output Excerpt: %s] ---%s\n' "$C_RED" "$rel_suite" "$C_RESET" >&2
            tail -n 25 "$suite_log" >&2
            printf '%s---------------------------------------------------%s\n' "$C_RED" "$C_RESET" >&2
        fi

        if [[ "$FAIL_FAST" == true ]]; then
            printf '%s[FAIL-FAST]%s Aborting execution on first failure.\n' "$C_RED$C_BOLD" "$C_RESET" >&2
            return 1
        fi
    fi

    return 0
}

# Run all queued test suites
if (( ${#SUITE_QUEUE[@]} > 0 )); then
    for suite in "${SUITE_QUEUE[@]}"; do
        if ! run_suite "$suite"; then
            break
        fi
    done
fi

# Run Linting Harness if requested
LINT_EXIT=0
if [[ "$RUN_LINT" == true && ( "$SUITES_FAILED" == 0 || "$FAIL_FAST" == false ) ]]; then
    printf '%s-------------------------------------------------------------%s\n' "$C_GRAY" "$C_RESET"
    printf '  %s[LINT]%s   Executing static analysis (tests/lint.sh)...\n' "$C_CYAN" "$C_RESET"
    
    local_lint_log="$TMP_DIR/lint_output.log"
    if [[ "$VERBOSE_MODE" == true ]]; then
        "$PROJECT_ROOT/tests/lint.sh" --all 2>&1 | tee "$local_lint_log" || LINT_EXIT=$?
    elif [[ "$QUIET_MODE" == true ]]; then
        "$PROJECT_ROOT/tests/lint.sh" --all --quiet > "$local_lint_log" 2>&1 || LINT_EXIT=$?
    else
        "$PROJECT_ROOT/tests/lint.sh" --all > "$local_lint_log" 2>&1 || LINT_EXIT=$?
    fi

    if (( LINT_EXIT == 0 )); then
        printf '  %s[PASS]%s  tests/lint.sh (all syntax and ShellCheck checks passed)\n' \
            "$C_GREEN$C_BOLD" "$C_RESET"
    else
        printf '  %s[FAIL]%s  tests/lint.sh (static analysis errors detected)\n' \
            "$C_RED$C_BOLD" "$C_RESET" >&2
        if [[ "$VERBOSE_MODE" == false ]]; then
            cat "$local_lint_log" >&2
        fi
    fi
fi

# Calculate Global Execution Duration
GLOBAL_END_MS="$(get_timestamp_ms)"
GLOBAL_ELAPSED_MS=$(( GLOBAL_END_MS - GLOBAL_START_MS ))
TOTAL_FORMATTED_TIME="$(format_duration "$GLOBAL_ELAPSED_MS")"

# Summary Display
fail_suite_color="$C_GREEN"
if (( SUITES_FAILED > 0 )); then
    fail_suite_color="$C_RED"
fi

fail_assert_color="$C_GREEN"
if (( TOTAL_ASSERTIONS_FAILED > 0 )); then
    fail_assert_color="$C_RED"
fi

lint_color="$C_GREEN"
lint_status_str="PASSED"
if (( LINT_EXIT != 0 )); then
    lint_color="$C_RED"
    lint_status_str="FAILED"
fi

printf '%s=============================================================%s\n' "$C_BLUE$C_BOLD" "$C_RESET"
printf '%s  RECKON Execution Summary%s\n' "$C_BOLD" "$C_RESET"
printf '%s=============================================================%s\n' "$C_BLUE$C_BOLD" "$C_RESET"
printf 'Suites Executed:       %d\n' "$SUITES_TOTAL"
printf 'Suites Passed:         %s%d%s\n' "$C_GREEN" "$SUITES_PASSED" "$C_RESET"
printf 'Suites Failed:         %s%d%s\n' "$fail_suite_color" "$SUITES_FAILED" "$C_RESET"
printf 'Assertions Passed:     %s%d%s\n' "$C_GREEN" "$TOTAL_ASSERTIONS_PASSED" "$C_RESET"
printf 'Assertions Failed:     %s%d%s\n' "$fail_assert_color" "$TOTAL_ASSERTIONS_FAILED" "$C_RESET"
if [[ "$RUN_LINT" == true ]]; then
    printf 'Lint Verification:     %s%s%s\n' "$lint_color" "$lint_status_str" "$C_RESET"
fi
printf 'Total Elapsed Time:    %s\n' "$TOTAL_FORMATTED_TIME"
printf '%s-------------------------------------------------------------%s\n' "$C_GRAY" "$C_RESET"

if (( SUITES_FAILED == 0 && LINT_EXIT == 0 )); then
    printf '%sRESULT: ALL TEST SUITES PASSED%s\n' "$C_GREEN$C_BOLD" "$C_RESET"
    exit 0
else
    printf '%sRESULT: TEST RUN FAILED%s\n' "$C_RED$C_BOLD" "$C_RESET"
    exit 1
fi
