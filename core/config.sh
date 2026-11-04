#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Configuration management
#

# Initialize configuration state.
config_init() {

    CONFIG_FILE=""
    CONFIG_JSON=""
    CONFIG_LOADED=false
    CONFIG_ERROR=""

    return 0
}

# Check dependencies required for configuration loading.
config_check_dependencies() {

    # A configuration file is optional.
    # No config file means jq is not required.
    if [[ -z "$CONFIG_FILE" ]]; then
        return 0
    fi

    # Check whether jq is available.
    if ! command -v jq >/dev/null 2>&1; then
        CONFIG_ERROR="jq is required to load the configuration file."
        return 1
    fi

    return 0
}

# Validate the configuration file.
config_validate_file() {

    # Configuration is optional.
    if [[ -z "$CONFIG_FILE" ]]; then
        return 0
    fi

    # Check whether the file exists.
    if [[ ! -f "$CONFIG_FILE" ]]; then
        CONFIG_ERROR="Configuration file does not exist: $CONFIG_FILE"
        return 1
    fi

    # Check whether the file is readable.
    if [[ ! -r "$CONFIG_FILE" ]]; then
        CONFIG_ERROR="Configuration file is not readable: $CONFIG_FILE"
        return 1
    fi

    return 0
}

# Load the configuration file into memory.
config_load() {

    local parsed_config

    # Reset the previous loading state.
    CONFIG_JSON=""
    CONFIG_LOADED=false
    CONFIG_ERROR=""

    # Configuration is optional.
    if [[ -z "$CONFIG_FILE" ]]; then
        return 0
    fi

    # Validate the configuration file.
    if ! config_validate_file; then
        return 1
    fi

    # Check required dependencies.
    if ! config_check_dependencies; then
        return 1
    fi

    # Parse exactly one JSON document.
    if ! parsed_config=$(jq -c -s '
        if length == 1 then
            .[0]
        else
            error("Expected exactly one JSON document")
        end
    ' "$CONFIG_FILE" 2>/dev/null); then
        CONFIG_ERROR="Invalid JSON configuration file: $CONFIG_FILE"
        return 1
    fi

    # Store the parsed configuration.
    CONFIG_JSON="$parsed_config"
    CONFIG_LOADED=true

    return 0
}