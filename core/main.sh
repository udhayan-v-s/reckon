#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Main application bootstrap
#

set -o nounset

# Main application function.
reckon_main() {

    # Temporary application identity display.
    printf '%s\n' "$APP_NAME"
    printf 'Version: %s\n' "$APP_VERSION"
    printf '%s\n' "$APP_DESCRIPTION"

}

# Start the application.
reckon_main "$@"