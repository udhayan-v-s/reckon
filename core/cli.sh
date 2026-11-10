#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# CLI state initialization
#

# CLI state is consumed by other application components.
# shellcheck disable=SC2034

# Initialize command-line interface state.
cli_init() {

    # Explicit-supply tracking. Consumed by config_apply_cli.
    # shellcheck disable=SC2034
    declare -gA CLI_EXPLICIT
    CLI_EXPLICIT=()

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

            # Force terminal colors.
            --color)

                CLI_COLOR_MODE="always"
                CLI_EXPLICIT[color]=true
                shift
                ;;

            # Disable terminal colors.
            --no-color)

                CLI_COLOR_MODE="never"
                CLI_EXPLICIT[color]=true
                shift
                ;;

            # Suppress the startup banner.
            --no-banner)

                CLI_NO_BANNER=true
                shift
                ;;

            # Request an environment and dependency check.
            --check|--check-deps|-c)

                CLI_CHECK=true
                shift
                ;;

            # Request a listing of available modules.
            --list-modules)

                CLI_LIST_MODULES=true
                shift
                ;;

            # Request a simulated scan execution.
            --dry-run)

                CLI_DRY_RUN=true
                shift
                ;;

            # Target option.
            --target|-t)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_TARGET="$2"
                CLI_EXPLICIT[target]=true
                shift 2
                ;;

            # Targets file option.
            --targets-file|-T)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_TARGETS_FILE="$2"
                CLI_EXPLICIT[targets_file]=true
                shift 2
                ;;

            # Custom module selection.
            --module|--modules|-M)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                if ! cli_append_unique_csv CLI_MODULES "$2"; then
                    return 2
                fi
                CLI_EXPLICIT[modules]=true

                shift 2
                ;;

            # Module exclusion.
            --exclude|--exclude-modules|-x)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                if ! cli_append_unique_csv CLI_EXCLUDE_MODULES "$2"; then
                    return 2
                fi
                CLI_EXPLICIT[exclude_modules]=true

                shift 2
                ;;

            # Scan profile selection.
            --profile)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_PROFILE="$2"
                CLI_EXPLICIT[profile]=true
                shift 2
                ;;

            # Scan mode selection.
            --mode|-m)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                case "${2,,}" in
                    network|net)
                        CLI_NETWORK=true
                        CLI_EXPLICIT[network]=true
                        ;;
                    web)
                        CLI_WEB=true
                        CLI_EXPLICIT[web]=true
                        ;;
                    all|both|full)
                        CLI_NETWORK=true
                        CLI_WEB=true
                        CLI_EXPLICIT[network]=true
                        CLI_EXPLICIT[web]=true
                        ;;
                    *)
                        printf 'Error: Invalid scan mode: %s (expected: network, web, all)\n' "$2" >&2
                        return 2
                        ;;
                esac
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

            # Target port selection.
            --ports)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_PORTS="$2"
                CLI_EXPLICIT[ports]=true
                shift 2
                ;;

            # Enumeration wordlist.
            --wordlist)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_WORDLIST="$2"
                CLI_EXPLICIT[wordlist]=true
                shift 2
                ;;

            # Configuration file.
            --config)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_CONFIG="$2"
                shift 2
                ;;

            # Execution thread count.
            --threads)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_THREADS="$2"
                CLI_EXPLICIT[threads]=true
                shift 2
                ;;

            # Execution timeout.
            --timeout)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_TIMEOUT="$2"
                CLI_EXPLICIT[timeout]=true
                shift 2
                ;;   

            # Execution rate limit.
            --rate-limit)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_RATE_LIMIT="$2"
                CLI_EXPLICIT[rate_limit]=true
                shift 2
                ;;

            # Execution retry count.
            --retries)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_RETRIES="$2"
                CLI_EXPLICIT[retries]=true
                shift 2
                ;;

            # Output directory.
            --output|-o)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_OUTPUT_DIR="$2"
                CLI_EXPLICIT[output_dir]=true
                shift 2
                ;;

            # Report format selection.
            --format|--report|-f)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                if ! cli_append_unique_csv CLI_FORMATS "$2"; then
                    return 2
                fi
                CLI_EXPLICIT[formats]=true

                shift 2
                ;;

            # Disable report generation.
            --no-report)

                CLI_NO_REPORT=true
                CLI_EXPLICIT[no_report]=true
                shift
                ;;

            # Log file.
            --log-file)

                if ! cli_require_value "$1" "$#" "${2-}"; then
                    return 2
                fi

                CLI_LOG_FILE="$2"
                CLI_EXPLICIT[log_file]=true
                shift 2
                ;;

            # Enable debug mode.
            --debug)

                CLI_DEBUG=true
                shift
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

# Validate target requirements for scan selection.
cli_validate_scan_selection() {

    # Check whether a scan mode was selected.
    if [[ "$CLI_NETWORK" == true || "$CLI_WEB" == true ]]; then

        # Require at least one target source.
        if [[ -z "$CLI_TARGET" && -z "$CLI_TARGETS_FILE" ]]; then
            printf 'Error: A target is required when network or web scanning is selected.\n' >&2
            printf 'Use --target or --targets-file to specify a scan target.\n' >&2
            return 2
        fi

    fi

    return 0
}

# Emit the canonical list of valid reconnaissance module identifiers.
# One identifier per line. Used by both CLI validation and configuration
# validation so the list is defined in exactly one place.
_cli_valid_modules() {
    cat <<'EOF'
host
dns
port
service
os
ssh
ftp
http
https
smb
telnet
http-probe
subdomain
crawl
technology
cms
waf
directory
file
vhost
endpoint
http-analysis
tls
resources
historical-urls
EOF
}

# Validate module selection and module identifiers.
cli_validate_modules() {

    local module
    local valid_module
    local is_valid

    local -a valid_modules=()
    local module_id

    while IFS= read -r module_id; do
        valid_modules+=("$module_id")
    done < <(_cli_valid_modules)

    # Reject custom module selection with network or web scan modes.
    if [[ ${#CLI_MODULES[@]} -gt 0 ]]; then

        if [[ "$CLI_NETWORK" == true || "$CLI_WEB" == true ]]; then
            printf 'Error: --module cannot be combined with --network or --web.\n' >&2
            return 2
        fi

    fi

    # Reject simultaneous module inclusion and exclusion.
    if [[ ${#CLI_MODULES[@]} -gt 0 && ${#CLI_EXCLUDE_MODULES[@]} -gt 0 ]]; then
        printf 'Error: --module and --exclude cannot be used together.\n' >&2
        return 2
    fi

    # Validate selected and excluded module identifiers.
    for module in "${CLI_MODULES[@]}" "${CLI_EXCLUDE_MODULES[@]}"; do

        is_valid=false

        for valid_module in "${valid_modules[@]}"; do
            if [[ "$module" == "$valid_module" ]]; then
                is_valid=true
                break
            fi
        done

        if [[ "$is_valid" == false ]]; then
            printf 'Error: Invalid module identifier: %s\n' "$module" >&2
            printf 'Use --list-modules to view available modules.\n' >&2
            return 2
        fi

    done

    return 0
}

# Validate report formats and reporting options.
cli_validate_reporting() {

    local format
    local normalized_format
    local valid_format
    local is_valid

    local -a valid_formats=(
        JSON
        TXT
        MD
        HTML
        CSV
        ALL
    )

    # Reject report formats when report generation is disabled.
    if [[ "$CLI_NO_REPORT" == true && ${#CLI_FORMATS[@]} -gt 0 ]]; then
        printf 'Error: --no-report cannot be combined with --format.\n' >&2
        return 2
    fi

    # Validate every requested report format.
    for format in "${CLI_FORMATS[@]}"; do

        normalized_format="${format^^}"
        is_valid=false

        for valid_format in "${valid_formats[@]}"; do

            if [[ "$normalized_format" == "$valid_format" ]]; then
                is_valid=true
                break
            fi

        done

        if [[ "$is_valid" == false ]]; then
            printf 'Error: Unsupported report format: %s\n' "$format" >&2
            printf 'Supported formats: JSON, HTML, MD, TXT, CSV, ALL.\n' >&2
            return 2
        fi

    done

    return 0
}

# Validate display options.
cli_validate_display() {

    # Reject conflicting verbose and quiet modes.
    if [[ "$CLI_VERBOSE" == true && "$CLI_QUIET" == true ]]; then
        printf 'Error: --verbose and --quiet cannot be used together.\n' >&2
        return 2
    fi

    return 0
}

# Validate numeric execution options.
cli_validate_numeric_options() {

    local index
    local option
    local value
    local minimum

    local -a option_names=(
        --timeout
        --threads
        --rate-limit
        --retries
    )

    local -a option_values=(
        "$CLI_TIMEOUT"
        "$CLI_THREADS"
        "$CLI_RATE_LIMIT"
        "$CLI_RETRIES"
    )

    local -a minimum_values=(
        1
        1
        1
        0
    )

    # Validate each supplied numeric option.
    for index in "${!option_names[@]}"; do

        option="${option_names[$index]}"
        value="${option_values[$index]}"
        minimum="${minimum_values[$index]}"

        # Skip options that were not supplied.
        if [[ -z "$value" ]]; then
            continue
        fi

        # Require decimal digits only.
        if [[ ! "$value" =~ ^[0-9]+$ ]]; then
            printf 'Error: %s must be a non-negative integer.\n' "$option" >&2
            return 2
        fi

        # Positive-integer options must contain at least one non-zero digit.
        if [[ "$minimum" == 1 && ! "$value" =~ [1-9] ]]; then
            printf 'Error: %s must be at least 1.\n' "$option" >&2
            return 2
        fi

    done

    return 0
}

# Validate an input file.
cli_validate_file() {

    local option="$1"
    local file_path="$2"

    # Check whether the file exists and is a regular file.
    if [[ ! -f "$file_path" ]]; then
        printf 'Error: File specified by %s does not exist or is not a regular file: %s\n' \
            "$option" "$file_path" >&2
        return 2
    fi

    # Check whether the file is readable.
    if [[ ! -r "$file_path" ]]; then
        printf 'Error: File specified by %s is not readable: %s\n' \
            "$option" "$file_path" >&2
        return 2
    fi

    return 0
}

# Validate CLI input files.
cli_validate_files() {

    # Validate the targets file when supplied.
    if [[ -n "$CLI_TARGETS_FILE" ]]; then
        if ! cli_validate_file "--targets-file" "$CLI_TARGETS_FILE"; then
            return 2
        fi
    fi

    # Validate the enumeration wordlist when supplied.
    if [[ -n "$CLI_WORDLIST" ]]; then
        if ! cli_validate_file "--wordlist" "$CLI_WORDLIST"; then
            return 2
        fi
    fi

    # Validate the configuration file when supplied.
    if [[ -n "$CLI_CONFIG" ]]; then
        if ! cli_validate_file "--config" "$CLI_CONFIG"; then
            return 2
        fi
    fi

    return 0
}

# Run all CLI argument validation checks.
cli_validate_args() {

    cli_validate_scan_selection || return $?
    cli_validate_modules || return $?
    cli_validate_reporting || return $?
    cli_validate_display || return $?
    cli_validate_numeric_options || return $?
    cli_validate_files || return $?

    return 0
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

# Display the ASCII art application banner.
cli_show_banner() {

    if [[ "${CLI_NO_BANNER:-false}" == true || "${CLI_QUIET:-false}" == true ]]; then
        return 0
    fi

    if declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
        printf '\033[1;36m'
        cat << 'EOF'
  ____  _____ ____ _  __ ___  _   _ 
 |  _ \| ____/ ___| |/ // _ \| \ | |
 | |_) |  _|| |   | ' /| | | |  \| |
 |  _ <| |__| |___| . \| |_| | |\  |
 |_| \_\_____\____|_|\_\\___/|_| \_|
EOF
        printf '\033[0m\033[1;37m  %s\033[0m \033[2m- %s\033[0m\n\n' "${APP_NAME:-RECKON}" "${APP_DESCRIPTION:-A modular Bash-based network and web reconnaissance toolkit.}"
    else
        cat << 'EOF'
  ____  _____ ____ _  __ ___  _   _ 
 |  _ \| ____/ ___| |/ // _ \| \ | |
 | |_) |  _|| |   | ' /| | | |  \| |
 |  _ <| |__| |___| . \| |_| | |\  |
 |_| \_\_____\____|_|\_\\___/|_| \_|
EOF
        printf '  %s - %s\n\n' "${APP_NAME:-RECKON}" "${APP_DESCRIPTION:-A modular Bash-based network and web reconnaissance toolkit.}"
    fi

}

# Display command-line help.

cli_show_help() {

    cat <<EOF
RECKON - Network and Web Reconnaissance Toolkit

Usage:
    reckon [OPTIONS]

General options:
    -h, --help                  Display this help message.
    -V, --version               Display application version.
        --no-banner             Suppress the startup banner.
    -c, --check, --check-deps   Check the environment and dependencies.
        --list-modules          List available reconnaissance modules.
        --dry-run               Simulate scan execution without running tools.

Target options:
    -t, --target TARGET         Specify a single scan target.
    -T, --targets-file FILE     Specify a file containing scan targets.

Scan selection:
    -n, --network               Select network reconnaissance.
    -w, --web                   Select web reconnaissance.
    -m, --mode MODE             Select scan mode (network, web, all).
        --module, --modules MOD Select specific reconnaissance modules.
    -x, --exclude MODS          Exclude specified reconnaissance modules.
        --profile PROFILE       Select a scan profile.

Output and reporting:
    -o, --output DIR            Specify the output directory.
    -f, --format, --report FMTS Specify report formats (JSON, HTML, MD, TXT, CSV, ALL).
        --no-report             Disable report generation.
        --log-file FILE         Specify the log file.

Execution options:
        --timeout SECONDS       Set the execution timeout.
        --threads NUMBER        Set the execution thread count.
        --rate-limit NUMBER     Set the execution rate limit.
        --retries NUMBER        Set the retry count.
        --ports PORTS           Specify target ports.
        --wordlist FILE         Specify an enumeration wordlist.
        --config FILE           Specify a configuration file.

Display options:
    -v, --verbose               Enable verbose output.
    -q, --quiet                 Suppress non-essential output.
        --debug                 Enable debug mode.
        --color                 Force colored output.
        --no-color              Disable colored output.

Examples:
    reckon --help
    reckon --version
    reckon --check-deps
    reckon --target example.com
    reckon --target 192.0.2.10 --network
    reckon --target https://example.com --web
    reckon --target example.com --mode all
    reckon --target example.com --modules host,dns
    reckon --target example.com --network --dry-run
    reckon --target example.com --web --report all
    reckon --target example.com --network --debug --no-color

For more information, see the project README.

EOF

}

# Display application version.
cli_show_version() {

    printf '%s %s\n' "$APP_NAME" "$APP_VERSION"

}