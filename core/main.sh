#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Main application bootstrap
#

set -o nounset

# Load command-line interface functions.
# shellcheck source=core/cli.sh
if ! source "$PROJECT_ROOT/core/cli.sh"; then
    printf 'Error: Failed to load the command-line interface.\n' >&2
    exit 1
fi

# Load configuration management functions.
# shellcheck source=core/config.sh
if ! source "$PROJECT_ROOT/core/config.sh"; then
    printf 'Error: Failed to load configuration management.\n' >&2
    exit 1
fi

# Load target processing functions.
# shellcheck source=core/targets.sh
if ! source "$PROJECT_ROOT/core/targets.sh"; then
    printf 'Error: Failed to load target processing.\n' >&2
    exit 1
fi

# Load shared libraries.
# shellcheck source=lib/term.sh
if ! source "$PROJECT_ROOT/lib/term.sh"; then
    printf 'Error: Failed to load terminal presentation library.\n' >&2
    exit 1
fi

# shellcheck source=lib/log.sh
if ! source "$PROJECT_ROOT/lib/log.sh"; then
    printf 'Error: Failed to load logging framework library.\n' >&2
    exit 1
fi

# shellcheck source=lib/fs.sh
if ! source "$PROJECT_ROOT/lib/fs.sh"; then
    printf 'Error: Failed to load filesystem library.\n' >&2
    exit 1
fi

# shellcheck source=lib/common.sh
if ! source "$PROJECT_ROOT/lib/common.sh"; then
    printf 'Error: Failed to load common utilities library.\n' >&2
    exit 1
fi

# shellcheck source=lib/exec.sh
if ! source "$PROJECT_ROOT/lib/exec.sh"; then
    printf 'Error: Failed to load execution wrapper library.\n' >&2
    exit 1
fi

# Main application function.
reckon_main() {

    local parse_status
    local validation_status
    local config_status
    local warning

    # Initialize CLI state.
    cli_init

    # Parse command-line arguments.
    if cli_parse_args "$@"; then
        :
    else
        parse_status=$?
        exit "$parse_status"
    fi

    # Display help when requested.
    if [[ "$CLI_HELP" == true ]]; then
        cli_show_help
        return 0
    fi

    # Display version when requested.
    if [[ "$CLI_VERSION" == true ]]; then
        cli_show_version
        return 0
    fi

    # Validate command-line arguments.
    if cli_validate_args; then
        :
    else
        validation_status=$?
        exit "$validation_status"
    fi

    # Initialize configuration state.
    config_init

    # Set the configuration file selected through the CLI.
    CONFIG_FILE="$CLI_CONFIG"

    # Load the configuration file.
    if config_load; then
        :
    else
        config_status=$?
        printf 'Error: %s\n' "$CONFIG_ERROR" >&2
        exit "$config_status"
    fi

    # Overlay CLI-supplied options onto the effective configuration.
    if config_apply_cli; then
        :
    else
        config_status=$?
        printf 'Error: %s\n' "$CONFIG_ERROR" >&2
        exit "$config_status"
    fi

    # Initialize terminal presentation and logging framework.
    term_init "$CONFIG_EFFECTIVE_COLOR"
    log_init "$CLI_VERBOSE" "$CLI_QUIET" "$CLI_DEBUG" "$CONFIG_EFFECTIVE_LOG_FILE"

    # Prepare targets.
    if target_prepare; then
        :
    else
        printf 'Error: %s\n' "$TARGET_ERROR" >&2
        exit 2
    fi

    # Print any target warnings collected during preparation.
    if (( ${#TARGET_WARNINGS[@]} > 0 )); then
        for warning in "${TARGET_WARNINGS[@]}"; do
            printf 'Warning: %s\n' "$warning" >&2
        done
    fi

    # Temporary application identity display.
    printf '%s\n' "$APP_NAME"
    printf 'Version: %s\n' "$APP_VERSION"
    printf '%s\n' "$APP_DESCRIPTION"

    # Record initialization record to log file if configured.
    if [[ -n "$CONFIG_EFFECTIVE_LOG_FILE" ]]; then
        _log_write_file "INFO" "RECKON initialized (version: $APP_VERSION)"
    fi

}

# Start the application.
reckon_main "$@"