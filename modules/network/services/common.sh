#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Service Module Common Framework (modules/network/services/common.sh)
#
# Provides a shared framework and specialized utility functions for all
# service-specific reconnaissance modules (ssh, telnet, ftp, smb, http, https).
#
# Key Capabilities:
#   - Upstream port and service discovery correlation (open_ports.txt & services.txt)
#   - Intelligent port resolution across non-standard, default, and CLI-specified ports
#   - Automatic skipping of inactive services when port scanning proved ports closed
#   - Uniform service header rendering and findings report formatting
#   - Lightweight raw socket banner grabbing
#   - Secure artifact permission enforcement
#

set -o nounset

SERVICES_COMMON_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SERVICES_COMMON_DIR

# Source base network module common library.
# shellcheck source=modules/network/common.sh
if ! source "$SERVICES_COMMON_DIR/../common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh.\n' >&2
    exit 1
fi

# Exported service module state variables.
# shellcheck disable=SC2034
SVC_TARGET=""
SVC_TARGET_TYPE=""
SVC_TASK_DIR=""
SVC_PORT_DIR=""
SVC_SERVICE_DIR=""
SVC_OPEN_PORTS_FILE=""
SVC_SERVICES_FILE=""
SVC_RESOLVED_PORTS=()
SVC_PORT_SOURCE=""
SVC_SKIP_SCAN=false
SVC_SKIP_REASON=""
SVC_MOD_ERROR=""

# Initialize service module execution context.
#
# Arguments:
#   $1 - target string
#   $2 - target type
#   $3 - task output directory
#
# Returns:
#   0 on success, 1 on argument or target incompatibility error
svc_mod_init() {
    SVC_MOD_ERROR=""
    SVC_RESOLVED_PORTS=()
    SVC_PORT_SOURCE=""
    SVC_SKIP_SCAN=false
    SVC_SKIP_REASON=""

    # Initialize underlying network module framework.
    if ! net_mod_init "$@"; then
        SVC_MOD_ERROR="${NET_MOD_ERROR:-Failed to initialize network module context.}"
        return 1
    fi

    # Enforce discrete single-host target compatibility.
    if ! net_mod_is_single_host; then
        SVC_MOD_ERROR="Target '$NET_TARGET' ($NET_TARGET_TYPE) is not a single discrete host."
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: $SVC_MOD_ERROR"
        net_mod_write_raw "       Service-specific audits require single host targets (ipv4, hostname, domain)."
        net_mod_write_footer "FAILED" "Incompatible target type for service reconnaissance."
        return 1
    fi

    SVC_TARGET="$NET_TARGET"
    SVC_TARGET_TYPE="$NET_TARGET_TYPE"
    SVC_TASK_DIR="$NET_TASK_DIR"

    # Derive sibling directories for port scanning and service detection tasks.
    local parent_target_dir
    parent_target_dir="$(dirname "$NET_TASK_DIR")"
    SVC_PORT_DIR="${parent_target_dir}/port"
    SVC_SERVICE_DIR="${parent_target_dir}/service"
    SVC_OPEN_PORTS_FILE="${SVC_PORT_DIR}/open_ports.txt"
    SVC_SERVICES_FILE="${SVC_SERVICE_DIR}/services.txt"

    return 0
}

# Resolve target ports for a specific network service.
#
# Checks upstream reconnaissance artifacts in prioritized sequence:
#   1. Explicit CLI configuration (CONFIG_EFFECTIVE_PORTS)
#   2. Upstream service detection artifact (services.txt) matching service regex
#   3. Upstream open ports artifact (open_ports.txt) matching canonical default ports
#   4. Fallback to canonical default ports (if no upstream artifacts exist)
#
# If upstream port scanning ran and verified that neither matching nor default
# ports are open, SVC_SKIP_SCAN is set to true and 1 is returned.
#
# Arguments:
#   $1 - service identifier (e.g. "ssh", "ftp", "http")
#   $2 - canonical default ports CSV (e.g. "22", "445,139", "80")
#   $3 - optional service name regex for matching services.txt (defaults to $1)
#
# Returns:
#   0 if ports were resolved and active
#   1 if upstream scan verified service is not listening (skip recommended)
#   2 on invalid arguments
svc_mod_resolve_ports() {
    local svc_name="${1:-}"
    local default_ports_csv="${2:-}"
    local svc_regex="${3:-}"

    if [[ -z "$svc_name" || -z "$default_ports_csv" ]]; then
        SVC_MOD_ERROR="Service name and default ports must be provided."
        return 2
    fi

    if [[ -z "$svc_regex" ]]; then
        svc_regex="$svc_name"
    fi

    SVC_RESOLVED_PORTS=()
    SVC_PORT_SOURCE=""
    SVC_SKIP_SCAN=false
    SVC_SKIP_REASON=""

    local -a raw_ports=()

    # 1. Check explicit CLI port configuration override.
    local cli_ports="${CONFIG_EFFECTIVE_PORTS:-}"
    cli_ports="${cli_ports//[[:space:]]/}"
    if [[ -n "$cli_ports" && "$cli_ports" != "top-100" && "$cli_ports" != "top-1000" && "$cli_ports" != "full" && "$cli_ports" != "all" ]]; then
        local p
        while IFS= read -r p || [[ -n "$p" ]]; do
            [[ -n "$p" ]] && raw_ports+=("$p")
        done < <(tr ',' '\n' <<< "$cli_ports")
        SVC_PORT_SOURCE="CLI configuration override"
    fi

    # 2. Check upstream services.txt artifact if no explicit ports were configured.
    if (( ${#raw_ports[@]} == 0 )) && [[ -f "$SVC_SERVICES_FILE" ]]; then
        while IFS=$'\t' read -r port_proto state svc _ || [[ -n "$port_proto" ]]; do
            if [[ "$svc" =~ $svc_regex ]] && [[ "$state" == "open"* ]]; then
                local p_num="${port_proto%%/*}"
                if [[ "$p_num" =~ ^[0-9]+$ ]]; then
                    raw_ports+=("$p_num")
                fi
            fi
        done < "$SVC_SERVICES_FILE"

        if (( ${#raw_ports[@]} > 0 )); then
            SVC_PORT_SOURCE="Service detection (services.txt)"
        fi
    fi

    # 3. Check upstream open_ports.txt artifact for canonical default ports.
    if (( ${#raw_ports[@]} == 0 )) && [[ -f "$SVC_OPEN_PORTS_FILE" ]]; then
        local -a open_ports_arr=()
        local op_line
        while IFS= read -r op_line || [[ -n "$op_line" ]]; do
            op_line="${op_line//[[:space:]]/}"
            if [[ "$op_line" =~ ^[0-9]+$ ]]; then
                open_ports_arr+=("$op_line")
            fi
        done < "$SVC_OPEN_PORTS_FILE"

        local -a default_ports_arr=()
        while IFS= read -r op_line || [[ -n "$op_line" ]]; do
            [[ -n "$op_line" ]] && default_ports_arr+=("$op_line")
        done < <(tr ',' '\n' <<< "$default_ports_csv")

        local def_p
        local act_p
        for def_p in "${default_ports_arr[@]}"; do
            for act_p in "${open_ports_arr[@]}"; do
                if [[ "$def_p" == "$act_p" ]]; then
                    raw_ports+=("$def_p")
                fi
            done
        done

        if (( ${#raw_ports[@]} > 0 )); then
            SVC_PORT_SOURCE="Port scan verification (open_ports.txt)"
        else
            # Upstream port scanning completed, but verified no ports for this service are open.
            SVC_SKIP_SCAN=true
            SVC_SKIP_REASON="Port scan verified service '${svc_name}' (default port: ${default_ports_csv}) is not open."
            return 1
        fi
    fi

    # 4. Fallback: Neither upstream artifact exists (standalone module execution).
    if (( ${#raw_ports[@]} == 0 )); then
        local def_p
        while IFS= read -r def_p || [[ -n "$def_p" ]]; do
            [[ -n "$def_p" ]] && raw_ports+=("$def_p")
        done < <(tr ',' '\n' <<< "$default_ports_csv")
        SVC_PORT_SOURCE="Canonical default port(s)"
    fi

    # Deduplicate resolved ports while preserving order.
    local -a unique_ports=()
    local item
    for item in "${raw_ports[@]}"; do
        [[ -z "$item" ]] && continue
        local seen=false
        local u
        for u in "${unique_ports[@]}"; do
            if [[ "$u" == "$item" ]]; then
                seen=true
                break
            fi
        done
        if [[ "$seen" == false ]]; then
            unique_ports+=("$item")
        fi
    done

    SVC_RESOLVED_PORTS=("${unique_ports[@]}")
    return 0
}

# Determine whether the service should be skipped based on upstream discovery.
#
# Returns:
#   0 if service was verified closed/inactive, 1 otherwise
svc_mod_should_skip() {
    [[ "$SVC_SKIP_SCAN" == true ]]
}

# Check if a given port is in the resolved port set.
#
# Arguments:
#   $1 - port number
#
# Returns:
#   0 if present, 1 otherwise
svc_mod_is_port_resolved() {
    local query_port="${1:-}"
    [[ -z "$query_port" ]] && return 1

    local p
    for p in "${SVC_RESOLVED_PORTS[@]}"; do
        if [[ "$p" == "$query_port" ]]; then
            return 0
        fi
    done
    return 1
}

# Handle a skipped service audit cleanly when upstream scans show service is closed.
#
# Arguments:
#   $1 - module identifier (e.g. "ssh", "ftp")
#   $2 - module display title (e.g. "SSH Enumeration")
#
# Returns:
#   0 (always completes with status COMPLETED and exit code 0)
svc_mod_handle_skipped() {
    local mod_id="${1:-service}"
    local mod_title="${2:-Service Enumeration}"

    net_mod_write_header "$mod_id" "$mod_title"

    net_mod_write_section "Target Information"
    net_mod_write_kv "Target" "$SVC_TARGET"
    net_mod_write_kv "Target Type" "$SVC_TARGET_TYPE"

    net_mod_write_section "Service Audit Status"
    net_mod_write_raw "Notice: ${SVC_SKIP_REASON:-Service is not listening on target systems.}"
    net_mod_write_raw "        Skipping active interrogation to optimize scan execution."

    net_mod_write_footer "COMPLETED" "Service not active on target."
    net_mod_finish 0
    return 0
}

# Write standard service target information header section.
#
# Arguments:
#   $1 - service identifier
#   $2 - service display title
#   $3 - audit engines description
svc_mod_write_service_header() {
    local mod_id="${1:-service}"
    local mod_title="${2:-Service Enumeration}"
    local engines="${3:-Native / Nmap}"

    net_mod_write_header "$mod_id" "$mod_title"

    local IFS=','
    local ports_str="${SVC_RESOLVED_PORTS[*]:-None}"

    net_mod_write_section "Target Information"
    net_mod_write_kv "Target" "$SVC_TARGET"
    net_mod_write_kv "Target Type" "$SVC_TARGET_TYPE"
    net_mod_write_kv "Target Ports" "$ports_str"
    net_mod_write_kv "Port Resolution" "${SVC_PORT_SOURCE:-Unknown}"
    net_mod_write_kv "Audit Engine(s)" "$engines"
}

# Grab raw banner from a target host and port.
#
# Arguments:
#   $1 - host or IP
#   $2 - port number
#   $3 - timeout in seconds (default: 2)
#   $4 - optional payload string to send upon connection
#
# Outputs:
#   Sanitized ASCII banner on stdout
#
# Returns:
#   0 if banner received, 1 on connection failure or empty response
svc_mod_banner_grab() {
    local host="${1:-}"
    local port="${2:-}"
    local timeout="${3:-2}"
    local payload="${4:-}"

    if [[ -z "$host" || -z "$port" ]]; then
        return 1
    fi

    local banner=""
    local nc_bin="${RECKON_MOCK_NC_BIN:-nc}"

    # 1. Attempt banner acquisition via netcat if available.
    if net_mod_has_tool "$nc_bin"; then
        if [[ -n "$payload" ]]; then
            banner=$(printf "%s\r\n" "$payload" | "$nc_bin" -w "$timeout" "$host" "$port" 2>/dev/null | head -n 20 || true)
        else
            banner=$("$nc_bin" -w "$timeout" "$host" "$port" < /dev/null 2>/dev/null | head -n 20 || true)
        fi
    fi

    # 2. Fallback to /dev/tcp via subshell timeout if nc yielded nothing.
    if [[ -z "$banner" ]]; then
        banner=$(
            exec 3<>/dev/tcp/"$host"/"$port" 2>/dev/null || exit 1
            if [[ -n "$payload" ]]; then
                printf "%s\r\n" "$payload" >&3 2>/dev/null || true
            fi
            read -r -t "$timeout" line <&3 2>/dev/null || true
            printf '%s\n' "${line:-}"
            exec 3<&-
            exec 3>&-
        ) || true
    fi

    # Strip non-printable control characters except standard whitespace.
    banner=$(tr -cd '\11\12\15\40-\176' <<< "$banner" | tr -d '\r')

    if [[ -n "$banner" ]]; then
        printf '%s\n' "$banner"
        return 0
    fi

    return 1
}

# Finalize service module task and enforce secure permissions on all task files.
#
# Arguments:
#   $1 - exit code (default: 0)
#
# Returns:
#   Propagates the specified exit code
svc_mod_finish() {
    local exit_code="${1:-0}"

    # Enforce 0640 permissions on all files created in the task directory.
    if [[ -d "$SVC_TASK_DIR" ]]; then
        find "$SVC_TASK_DIR" -type f -exec chmod 0640 {} + 2>/dev/null || true
    fi

    net_mod_finish "$exit_code"
    return "$exit_code"
}
