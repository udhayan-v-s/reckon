#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Terminal presentation and color library
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# ANSI escape sequence constants.
readonly TERM_CLR_RESET=$'\033[0m'
readonly TERM_CLR_BOLD=$'\033[1m'
readonly TERM_CLR_DIM=$'\033[2m'
readonly TERM_CLR_RED=$'\033[31m'
readonly TERM_CLR_GREEN=$'\033[32m'
readonly TERM_CLR_YELLOW=$'\033[33m'
readonly TERM_CLR_BLUE=$'\033[34m'
readonly TERM_CLR_MAGENTA=$'\033[35m'
readonly TERM_CLR_CYAN=$'\033[36m'
readonly TERM_CLR_WHITE=$'\033[37m'

# Terminal color state.
TERM_COLOR_ENABLED=false
TERM_COLOR_MODE="auto"

# Initialize terminal presentation and color settings.
#
# Arguments:
#   $1 - color mode: "auto" (default), "always", or "never"
#
# Returns:
#   0 on valid mode, 1 on unrecognized mode
term_init() {
    local mode="${1:-auto}"

    case "$mode" in
        always)
            TERM_COLOR_MODE="always"
            TERM_COLOR_ENABLED=true
            return 0
            ;;
        never)
            TERM_COLOR_MODE="never"
            TERM_COLOR_ENABLED=false
            return 0
            ;;
        auto)
            TERM_COLOR_MODE="auto"
            # Enable colors only when stdout is a terminal and TERM is not "dumb".
            if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then
                TERM_COLOR_ENABLED=true
            else
                TERM_COLOR_ENABLED=false
            fi
            return 0
            ;;
        *)
            TERM_COLOR_MODE="never"
            TERM_COLOR_ENABLED=false
            return 1
            ;;
    esac
}

# Check whether terminal color is currently enabled.
#
# Returns:
#   0 if enabled, 1 if disabled
term_is_color_enabled() {
    [[ "$TERM_COLOR_ENABLED" == true ]]
}

# Apply an ANSI color/style code to text with an automatic reset.
#
# Arguments:
#   $1 - ANSI escape sequence code
#   $2 - text string to format
#
# Output:
#   Formatted string if color is enabled, or unmodified text if disabled
term_color() {
    local code="${1:-}"
    local text="${2:-}"

    if term_is_color_enabled; then
        printf '%s%s%s' "$code" "$text" "$TERM_CLR_RESET"
    else
        printf '%s' "$text"
    fi
}

# Semantic color helpers.
term_red()     { term_color "$TERM_CLR_RED" "${1:-}"; }
term_green()   { term_color "$TERM_CLR_GREEN" "${1:-}"; }
term_yellow()  { term_color "$TERM_CLR_YELLOW" "${1:-}"; }
term_blue()    { term_color "$TERM_CLR_BLUE" "${1:-}"; }
term_magenta() { term_color "$TERM_CLR_MAGENTA" "${1:-}"; }
term_cyan()    { term_color "$TERM_CLR_CYAN" "${1:-}"; }
term_white()   { term_color "$TERM_CLR_WHITE" "${1:-}"; }
term_bold()    { term_color "$TERM_CLR_BOLD" "${1:-}"; }
term_dim()     { term_color "$TERM_CLR_DIM" "${1:-}"; }

# Strip all ANSI CSI escape sequences from a string.
#
# Arguments:
#   $1 - input string containing optional ANSI sequences
#
# Output:
#   Clean string with all ANSI sequences removed
term_strip_ansi() {
    local str="${1:-}"
    local esc=$'\033'
    local extglob_was_set=false

    if shopt -q extglob; then
        extglob_was_set=true
    else
        shopt -s extglob
    fi

    # Remove all ANSI Control Sequence Introducer (CSI) sequences.
    # Pattern: ESC [ <optional numeric/semicolon/question parameters> <command letter>
    str="${str//$esc\[*([0-9;?])[a-zA-Z]/}"

    if [[ "$extglob_was_set" == false ]]; then
        shopt -u extglob
    fi

    printf '%s' "$str"
}
