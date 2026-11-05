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

# Main application function.
reckon_main() {

    local parse_status
    local validation_status
    local config_status

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

    # Temporary application identity display.
    printf '%s\n' "$APP_NAME"
    printf 'Version: %s\n' "$APP_VERSION"
    printf '%s\n' "$APP_DESCRIPTION"

}

# Start the application.
reckon_main "$@"