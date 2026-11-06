#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Terminal presentation and color library unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/term.sh
if ! source "$PROJECT_ROOT/lib/term.sh"; then
    printf 'Error: Unable to load terminal library component.\n' >&2
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

pass() { printf '[PASS] %s\n' "$1"; ((PASS_COUNT += 1)); }
fail() { printf '[FAIL] %s\n' "$1" >&2; ((FAIL_COUNT += 1)); }

test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Terminal library unit tests completed."
}

printf '%s\n' "RECKON - Terminal Library Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Terminal Initialization & Mode Selection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Terminal Initialization & Mode Selection"

# Test 1: Explicit "always" mode enables color
term_init "always"
if [[ "$TERM_COLOR_ENABLED" == true && "$TERM_COLOR_MODE" == "always" ]]; then
    pass "Mode 'always' enables color unconditionally"
else
    fail "Mode 'always' did not enable color"
fi

# Test 2: Explicit "never" mode disables color
term_init "never"
if [[ "$TERM_COLOR_ENABLED" == false && "$TERM_COLOR_MODE" == "never" ]]; then
    pass "Mode 'never' disables color unconditionally"
else
    fail "Mode 'never' did not disable color"
fi

# Test 3: Unrecognized mode returns error and disables color
if ! term_init "unrecognized_mode"; then
    if [[ "$TERM_COLOR_ENABLED" == false ]]; then
        pass "Unrecognized mode returns error and disables color"
    else
        fail "Unrecognized mode returned error but color remained enabled"
    fi
else
    fail "Unrecognized mode did not return an error status"
fi

# Test 4: Default argument initializes as "auto"
term_init
if [[ "$TERM_COLOR_MODE" == "auto" ]]; then
    pass "Default argument defaults to mode 'auto'"
else
    fail "Default argument did not set mode 'auto'"
fi

# Test 5: "auto" mode disables color when TERM is "dumb"
if (
    TERM="dumb"
    term_init "auto"
    [[ "$TERM_COLOR_ENABLED" == false ]]
); then
    pass "Mode 'auto' disables color when TERM is 'dumb'"
else
    fail "Mode 'auto' enabled color when TERM is 'dumb'"
fi

# Test 6: "auto" mode in non-interactive subshell/pipe disables color
if (
    # Piping into cat ensures stdout is not a TTY
    term_init "auto"
    [[ "$TERM_COLOR_ENABLED" == false ]]
) | cat >/dev/null; then
    pass "Mode 'auto' disables color when stdout is not a TTY"
else
    fail "Mode 'auto' enabled color in non-TTY environment"
fi

# -----------------------------------------------------------------------------
# UT-02: Color Status Inspection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Color Status Inspection"

# Test 7: term_is_color_enabled returns 0 when true
term_init "always"
if term_is_color_enabled; then
    pass "term_is_color_enabled returns 0 when color is enabled"
else
    fail "term_is_color_enabled did not return 0 when color was enabled"
fi

# Test 8: term_is_color_enabled returns 1 when false
term_init "never"
if ! term_is_color_enabled; then
    pass "term_is_color_enabled returns 1 when color is disabled"
else
    fail "term_is_color_enabled did not return 1 when color was disabled"
fi

# -----------------------------------------------------------------------------
# UT-03: Formatted Output When Enabled
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Formatted Output When Enabled"
term_init "always"

# Test 9: Generic term_color embeds ANSI code and reset
out="$(term_color "$TERM_CLR_RED" "test")"
expected=$'\033[31mtest\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_color wraps text with escape code and reset"
else
    fail "term_color output '$out' did not match '$expected'"
fi

# Test 10: term_red helper
out="$(term_red "error")"
expected=$'\033[31merror\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_red generates red ANSI escape sequence"
else
    fail "term_red output '$out' did not match '$expected'"
fi

# Test 11: term_green helper
out="$(term_green "success")"
expected=$'\033[32msuccess\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_green generates green ANSI escape sequence"
else
    fail "term_green output '$out' did not match '$expected'"
fi

# Test 12: term_yellow helper
out="$(term_yellow "warning")"
expected=$'\033[33mwarning\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_yellow generates yellow ANSI escape sequence"
else
    fail "term_yellow output '$out' did not match '$expected'"
fi

# Test 13: term_blue helper
out="$(term_blue "info")"
expected=$'\033[34minfo\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_blue generates blue ANSI escape sequence"
else
    fail "term_blue output '$out' did not match '$expected'"
fi

# Test 14: term_cyan helper
out="$(term_cyan "heading")"
expected=$'\033[36mheading\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_cyan generates cyan ANSI escape sequence"
else
    fail "term_cyan output '$out' did not match '$expected'"
fi

# Test 15: term_bold helper
out="$(term_bold "important")"
expected=$'\033[1mimportant\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_bold generates bold ANSI escape sequence"
else
    fail "term_bold output '$out' did not match '$expected'"
fi

# Test 16: term_dim helper
out="$(term_dim "faint")"
expected=$'\033[2mfaint\033[0m'
if [[ "$out" == "$expected" ]]; then
    pass "term_dim generates dim ANSI escape sequence"
else
    fail "term_dim output '$out' did not match '$expected'"
fi

# -----------------------------------------------------------------------------
# UT-04: Passthrough Behavior When Disabled
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Passthrough Behavior When Disabled"
term_init "never"

# Test 17: term_color passthrough
out="$(term_color "$TERM_CLR_RED" "plain")"
if [[ "$out" == "plain" ]]; then
    pass "term_color outputs unmodified text when disabled"
else
    fail "term_color added escape sequences when disabled: '$out'"
fi

# Test 18: term_red passthrough
out="$(term_red "error text")"
if [[ "$out" == "error text" ]]; then
    pass "term_red outputs unmodified text when disabled"
else
    fail "term_red added escape sequences when disabled: '$out'"
fi

# Test 19: term_green passthrough
out="$(term_green "success text")"
if [[ "$out" == "success text" ]]; then
    pass "term_green outputs unmodified text when disabled"
else
    fail "term_green added escape sequences when disabled: '$out'"
fi

# Test 20: term_bold passthrough
out="$(term_bold "bold text")"
if [[ "$out" == "bold text" ]]; then
    pass "term_bold outputs unmodified text when disabled"
else
    fail "term_bold added escape sequences when disabled: '$out'"
fi

# -----------------------------------------------------------------------------
# UT-05: ANSI Escape Stripping
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: ANSI Escape Stripping"

# Test 21: Plain text unchanged
in="Plain message without colors"
out="$(term_strip_ansi "$in")"
if [[ "$out" == "$in" ]]; then
    pass "term_strip_ansi leaves unadorned text unmodified"
else
    fail "term_strip_ansi altered unadorned text: '$out'"
fi

# Test 22: Single ANSI sequence stripped
in=$'\033[31mRed text\033[0m'
out="$(term_strip_ansi "$in")"
if [[ "$out" == "Red text" ]]; then
    pass "term_strip_ansi strips simple color and reset sequences"
else
    fail "term_strip_ansi failed on simple color: '$out'"
fi

# Test 23: Multiple chained and nested ANSI sequences stripped
in=$'\033[1m\033[32mBold Green\033[0m and \033[33mYellow\033[0m'
out="$(term_strip_ansi "$in")"
if [[ "$out" == "Bold Green and Yellow" ]]; then
    pass "term_strip_ansi strips multiple mixed escape sequences"
else
    fail "term_strip_ansi failed on multiple mixed sequences: '$out'"
fi

# Test 24: Compound parameter sequences (e.g., 1;32m) stripped
in=$'\033[1;32mHighlight\033[0m'
out="$(term_strip_ansi "$in")"
if [[ "$out" == "Highlight" ]]; then
    pass "term_strip_ansi strips compound parameter ANSI sequences"
else
    fail "term_strip_ansi failed on compound sequence: '$out'"
fi

# Test 25: Terminal control CSI sequences (e.g., cursor, line clear) stripped
in=$'\033[2K\033[1GMessage\033[0m'
out="$(term_strip_ansi "$in")"
if [[ "$out" == "Message" ]]; then
    pass "term_strip_ansi strips general CSI terminal control codes"
else
    fail "term_strip_ansi failed on general CSI codes: '$out'"
fi

# Test 26: Empty string returns empty string
out="$(term_strip_ansi "")"
if [[ -z "$out" ]]; then
    pass "term_strip_ansi handles empty input string cleanly"
else
    fail "term_strip_ansi returned non-empty string for empty input"
fi

test_summary
