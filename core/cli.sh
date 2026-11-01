#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# CLI state initialization
#

# CLI state is consumed by other application components.
# shellcheck disable=SC2034

# Initialize command-line interface state.
cli_init() {

    # Target options.
    CLI_TARGET=""
    CLI_TARGETS_FILE=""

    # Scan selection options.
    CLI_NETWORK=false
    CLI_WEB=false
    CLI_MODULES=()
    CLI_EXCLUDE_MODULES=()
    CLI_PROFILE=""

    # Output and reporting options.
    CLI_OUTPUT_DIR="results/"
    CLI_FORMATS=()
    CLI_NO_REPORT=false
    CLI_LOG_FILE=""

    # Execution options.
    CLI_TIMEOUT=""
    CLI_THREADS=""
    CLI_RATE_LIMIT=""
    CLI_RETRIES=""
    CLI_PORTS=""
    CLI_WORDLIST=""
    CLI_CONFIG=""

    # Display options.
    CLI_VERBOSE=false
    CLI_QUIET=false
    CLI_DEBUG=false
    CLI_COLOR_MODE="auto"

    # General options.
    CLI_NO_BANNER=false
    CLI_CHECK=false
    CLI_LIST_MODULES=false
    CLI_DRY_RUN=false

    # Informational options.
    CLI_HELP=false
    CLI_VERSION=false

}


# Parse command-line arguments.
cli_parse_args() {

    # Process arguments until none remain.
    while (($# > 0)); do

        case "$1" in

            
            # Target option.
            --target|-t)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_TARGET="$2"
                shift 2
                ;;

            # Targets file option.
            --targets-file|-T)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_TARGETS_FILE="$2"
                shift 2
                ;;

            # Custom module selection.
            --module)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                if ! cli_append_unique_csv CLI_MODULES "$2"; then
                    return 2
                fi

                shift 2
                ;;

            # Module exclusion.
            --exclude|-x)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                if ! cli_append_unique_csv CLI_EXCLUDE_MODULES "$2"; then
                    return 2
                fi

                shift 2
                ;;

            # Scan profile selection.
            --profile)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_PROFILE="$2"
                shift 2
                ;;

            # Network scan selection.
            --network|-n)
                CLI_NETWORK=true
                shift
                ;;

            # Web scan selection.
            --web|-w)
                CLI_WEB=true
                shift
                ;;

            # Verbose output.
            --verbose|-v)
                CLI_VERBOSE=true
                shift
                ;;

            # Quiet output.
            --quiet|-q)
                CLI_QUIET=true
                shift
                ;;

            # Output directory.
            --output|-o)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_OUTPUT_DIR="$2"
                shift 2
                ;;

            # Report format selection.
            --format|-f)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                if ! cli_append_unique_csv CLI_FORMATS "$2"; then
                    return 2
                fi

                shift 2
                ;;

            # Disable report generation.
            --no-report)

                CLI_NO_REPORT=true
                shift
                ;;

            # Log file.
            --log-file)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_LOG_FILE="$2"
                shift 2
                ;;

            # Help.
            --help|-h)
                CLI_HELP=true
                shift
                ;;

            # Version.
            --version|-V)
                CLI_VERSION=true
                shift
                ;;

            # Reject unknown options.
            *)
                printf 'Error: Unknown option: %s\n' "$1" >&2
                return 2
                ;;

        esac

    done

}


# Validate that an option has a usable value.
cli_require_value() {

    local option="$1"
    local argument_count="$2"
    local value="${3-}"

    # Check whether a value was supplied.
    if (( argument_count < 2 )); then
        printf 'Error: Missing value for %s.\n' "$option" >&2
        return 2
    fi

    # Reject empty values.
    if [[ -z "$value" ]]; then
        printf 'Error: Empty value supplied for %s.\n' "$option" >&2
        return 2
    fi

    # Reject another option being used as a value.
    if [[ "$value" == -* ]]; then
        printf 'Error: Missing value for %s (received another option: %s).\n' \
            "$option" "$value" >&2
        return 2
    fi

    return 0
}

# Append unique values from a comma-separated list to a CLI array.
cli_append_unique_csv() {

    local array_name="$1"
    local csv_value="$2"
    local remaining="$csv_value"
    local item
    local existing
    local found
    local is_last=false

    local -a parsed_values=()

    # Restrict the destination to known CLI arrays.
    case "$array_name" in
        CLI_MODULES|CLI_EXCLUDE_MODULES|CLI_FORMATS)
            ;;
        *)
            printf 'Error: Invalid destination array: %s\n' "$array_name" >&2
            return 2
            ;;
    esac

    # Create a local reference to the destination array.
    local -n destination_array="$array_name"

    # Parse and validate all values before modifying the destination.
    while :; do

        if [[ "$remaining" == *,* ]]; then
            item="${remaining%%,*}"
            remaining="${remaining#*,}"
        else
            item="$remaining"
            is_last=true
        fi

        # Trim leading and trailing whitespace.
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"

        # Reject empty entries.
        if [[ -z "$item" ]]; then
            printf 'Error: Empty value found in %s list.\n' "$array_name" >&2
            return 2
        fi

        found=false

        # Check for duplicates in the current parsed values.
        for existing in "${parsed_values[@]}"; do
            if [[ "$existing" == "$item" ]]; then
                found=true
                break
            fi
        done

        # Check for duplicates already present in the destination.
        if [[ "$found" == false ]]; then
            for existing in "${destination_array[@]}"; do
                if [[ "$existing" == "$item" ]]; then
                    found=true
                    break
                fi
            done
        fi

        # Preserve only the first occurrence.
        if [[ "$found" == false ]]; then
            parsed_values+=("$item")
        fi

        # Stop after processing the final entry.
        if [[ "$is_last" == true ]]; then
            break
        fi

    done

    # Append validated, unique values to the destination array.
    for item in "${parsed_values[@]}"; do
        destination_array+=("$item")
    done

    return 0
}

# Display command-line help.
cli_show_help() {

    cat <<EOF
RECKON - Network and Web Reconnaissance Toolkit

Usage:
    reckon [OPTIONS]

General options:
    -h, --help              Display this help message.
    -V, --version           Display application version.

Target options:
    -t, --target TARGET     Specify a single scan target.

Scan selection:
    -n, --network           Select network reconnaissance.
    -w, --web               Select web reconnaissance.

Display options:
    -v, --verbose           Enable verbose output.
    -q, --quiet             Suppress non-essential output.

Examples:
    reckon --help
    reckon --version
    reckon --target example.com
    reckon --target 192.0.2.10 --network
    reckon --target https://example.com --web
    reckon --target example.com --network --web

For more information, see the project README.

EOF

}

# Display application version.
cli_show_version() {

    printf '%s %s\n' "$APP_NAME" "$APP_VERSION"

}