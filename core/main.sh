#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Main application component
#

set -o nounset

readonly APP_NAME="RECKON"
readonly APP_VERSION="0.1.0"

# Temporary application identity display.
printf '%s\n' "$APP_NAME"
printf 'Version: %s\n' "$APP_VERSION"
printf '%s\n' "Bash-based network and web reconnaissance toolkit."
