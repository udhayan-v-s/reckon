#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Code Quality, Syntax & ShellCheck Linting Harness (tests/lint.sh)
#
# Validates all project shell scripts using:
# 1. 'bash -n' syntax verification (checks for parser and syntax errors)
# 2. 'shellcheck -x' static analysis (enforces POSIX/Bash best practices)
#
# Supports granular split batch execution to avoid heavy monolithic runs:
#   ./tests/lint.sh --core
#   ./tests/lint.sh --lib
#   ./tests/lint.sh --modules-net
#   ./tests/lint.sh --modules-web
#   ./tests/lint.sh --tests-unit
#   ./tests/lint.sh --tests-int
#   ./tests/lint.sh --all
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# ShellCheck availability check
HAS_SHELLCHECK=false
if command -v shellcheck >/dev/null 2>&1; then
    HAS_SHELLCHECK=true
fi

# Configuration flags
DO_SYNTAX=true
DO_SHELLCHECK=true
QUIET_MODE=false
SELECTED_SCOPE=""

FILES_CHECKED=0
SYNTAX_ERRORS=0
SHELLCHECK_ERRORS=0

print_usage() {
    cat << 'EOF'
RECKON - Linting and Code Quality Harness

Usage: tests/lint.sh [OPTIONS] [FILE...]

Scope Selection (choose one or more, or specify explicit files):
  -c, --core             Lint core CLI entrypoint and framework files
  -l, --lib              Lint shared utility libraries (lib/*.sh)
  -m, --modules          Lint all network and web modules
      --modules-net      Lint network reconnaissance modules only
      --modules-web      Lint web enumeration modules only
  -t, --tests            Lint all test suites (unit, integration, harness, security)
      --tests-unit       Lint unit test suites only
      --tests-int        Lint integration test suites only
      --tests-harness    Lint test runners and harnesses (lint.sh, run_tests.sh)
  -s, --security         Lint security audit test suite only
  -a, --all              Lint all repository shell scripts

Analysis Options:
      --syntax-only      Run only 'bash -n' syntax verification
      --shellcheck-only  Run only 'shellcheck -x' static analysis
  -q, --quiet            Only display files with errors or warnings
  -h, --help             Display this help message and exit

Examples:
  ./tests/lint.sh --core
  ./tests/lint.sh --lib
  ./tests/lint.sh --modules-net
  ./tests/lint.sh --all
  ./tests/lint.sh lib/results.sh
EOF
}

# Resolve candidate files based on selected scopes
declare -a TARGET_FILES=()

add_file() {
    local candidate="$1"
    if [[ -f "$candidate" && -r "$candidate" ]]; then
        # Deduplicate
        local existing
        for existing in "${TARGET_FILES[@]}"; do
            if [[ "$existing" == "$candidate" ]]; then
                return 0
            fi
        done
        TARGET_FILES+=("$candidate")
    fi
}

# Parse command line options
if (( $# == 0 )); then
    print_usage
    exit 0
fi

declare -a EXPLICIT_FILES=()

while (( $# > 0 )); do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        --syntax-only)
            DO_SYNTAX=true
            DO_SHELLCHECK=false
            shift
            ;;
        --shellcheck-only)
            DO_SYNTAX=false
            DO_SHELLCHECK=true
            shift
            ;;
        -c|--core)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}core"
            shift
            ;;
        -l|--lib)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}lib"
            shift
            ;;
        -m|--modules)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}modules_net,modules_web"
            shift
            ;;
        --modules-net)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}modules_net"
            shift
            ;;
        --modules-web)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}modules_web"
            shift
            ;;
        -t|--tests)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}tests_unit,tests_int,tests_harness,security"
            shift
            ;;
        --tests-unit)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}tests_unit"
            shift
            ;;
        --tests-int)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}tests_int"
            shift
            ;;
        --tests-harness)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}tests_harness"
            shift
            ;;
        -s|--security)
            SELECTED_SCOPE="${SELECTED_SCOPE:+${SELECTED_SCOPE},}security"
            shift
            ;;
        -a|--all)
            SELECTED_SCOPE="core,lib,modules_net,modules_web,tests_unit,tests_int,tests_harness,security"
            shift
            ;;
        -*)
            printf 'Error: Unknown option: %s\n' "$1" >&2
            printf 'Use --help for usage information.\n' >&2
            exit 2
            ;;
        *)
            EXPLICIT_FILES+=("$1")
            shift
            ;;
    esac
done

# If explicit files were provided, use them
if (( ${#EXPLICIT_FILES[@]} > 0 )); then
    for f in "${EXPLICIT_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            add_file "$f"
        elif [[ -f "$PROJECT_ROOT/$f" ]]; then
            add_file "$PROJECT_ROOT/$f"
        else
            printf 'Warning: Specified file does not exist: %s\n' "$f" >&2
        fi
    done
fi

# Populate scopes
if [[ -n "$SELECTED_SCOPE" ]]; then
    IFS=',' read -r -a SCOPES <<< "$SELECTED_SCOPE"
    for scope in "${SCOPES[@]}"; do
    case "$scope" in
        core)
            add_file "$PROJECT_ROOT/reckon"
            for f in "$PROJECT_ROOT"/core/*.sh; do add_file "$f"; done
            ;;
        lib)
            for f in "$PROJECT_ROOT"/lib/*.sh; do add_file "$f"; done
            ;;
        modules_net)
            for f in "$PROJECT_ROOT"/modules/network/*.sh; do add_file "$f"; done
            for f in "$PROJECT_ROOT"/modules/network/services/*.sh; do add_file "$f"; done
            ;;
        modules_web)
            for f in "$PROJECT_ROOT"/modules/web/*.sh; do add_file "$f"; done
            ;;
        tests_unit)
            for f in "$PROJECT_ROOT"/tests/unit/*.sh; do add_file "$f"; done
            ;;
        tests_int)
            for f in "$PROJECT_ROOT"/tests/integration/*.sh; do add_file "$f"; done
            ;;
        tests_harness)
            add_file "$PROJECT_ROOT/tests/lint.sh"
            add_file "$PROJECT_ROOT/tests/run_tests.sh"
            ;;
        security)
            add_file "$PROJECT_ROOT/tests/security_audit.sh"
            ;;
    esac
done
fi

if (( ${#TARGET_FILES[@]} == 0 )); then
    printf 'Error: No files selected for linting.\n' >&2
    printf 'Use --help for usage instructions.\n' >&2
    exit 1
fi

if [[ "$DO_SHELLCHECK" == true && "$HAS_SHELLCHECK" == false ]]; then
    printf 'Warning: ShellCheck utility not found in PATH. Skipping static analysis.\n' >&2
    DO_SHELLCHECK=false
fi

printf '%s\n' "RECKON - Code Quality & Linting Harness"
printf '%s\n' "Target files selected: ${#TARGET_FILES[@]}"
printf '%s\n' "-------------------------------------------------------------"

# Lint each target file
cd "$PROJECT_ROOT" || exit 1

for file_path in "${TARGET_FILES[@]}"; do
    rel_path="${file_path#"$PROJECT_ROOT/"}"
    (( FILES_CHECKED += 1 ))

    file_has_error=false

    # 1. Syntax check with bash -n
    if [[ "$DO_SYNTAX" == true ]]; then
        syntax_output="$(bash -n "$file_path" 2>&1 || true)"
        if [[ -n "$syntax_output" ]]; then
            file_has_error=true
            (( SYNTAX_ERRORS += 1 ))
            printf '[SYNTAX ERROR] %s\n' "$rel_path" >&2
            printf '%s\n' "$syntax_output" >&2
        fi
    fi

    # 2. Static analysis with shellcheck -x
    if [[ "$DO_SHELLCHECK" == true ]]; then
        shellcheck_output="$(shellcheck -x "$file_path" 2>&1 || true)"
        if [[ -n "$shellcheck_output" ]]; then
            file_has_error=true
            (( SHELLCHECK_ERRORS += 1 ))
            printf '[SHELLCHECK ERROR] %s\n' "$rel_path" >&2
            printf '%s\n' "$shellcheck_output" >&2
        fi
    fi

    if [[ "$file_has_error" == false && "$QUIET_MODE" == false ]]; then
        printf '[PASS] %s\n' "$rel_path"
    fi
done

printf '%s\n' "-------------------------------------------------------------"
printf 'Files linted:           %d\n' "$FILES_CHECKED"
printf 'Syntax errors:          %d\n' "$SYNTAX_ERRORS"
printf 'ShellCheck violations:  %d\n' "$SHELLCHECK_ERRORS"

if (( SYNTAX_ERRORS > 0 || SHELLCHECK_ERRORS > 0 )); then
    printf '%s\n' "Linting check FAILED." >&2
    exit 1
fi

printf '%s\n' "All linting checks passed successfully."
exit 0
