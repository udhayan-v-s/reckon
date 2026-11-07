#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Host Discovery Module (modules/network/host.sh)
#
# Identifies active, responsive systems on target networks using
# ICMP ping sweeps and TCP/ARP host discovery probes.
#
# Supported target types:
#   ipv4, ipv4_cidr, ipv4_range, hostname, domain
#
# External tools utilized:
#   - fping (high-speed ICMP sweeps)
#   - nmap (multi-probe discovery: ICMP + TCP SYN/ACK)
#

set -o nounset

HOST_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/common.sh
if ! source "$HOST_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
HOST_FPING_BIN="${RECKON_MOCK_FPING_BIN:-fping}"
HOST_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-nmap}"

# Array to collect deduplicated live hosts.
LIVE_HOSTS=()

_host_add_live() {
    local candidate="${1:-}"
    [[ -z "$candidate" ]] && return 0
    local existing
    for existing in "${LIVE_HOSTS[@]}"; do
        if [[ "$existing" == "$candidate" ]]; then
            return 0
        fi
    done
    LIVE_HOSTS+=("$candidate")
}

# Parse an IPv4 range string (e.g. "192.168.1.1-192.168.1.50" or "10.0.0.1-50")
# into starting and ending IP addresses.
#
# Output:
#   Prints start_ip and end_ip separated by space
_host_parse_range() {
    local range="$1"
    local start_ip="${range%%-*}"
    local end_part="${range##*-}"
    local end_ip="$end_part"

    if [[ "$end_part" =~ ^[0-9]+$ ]]; then
        local base="${start_ip%.*}"
        end_ip="${base}.${end_part}"
    fi

    printf '%s %s\n' "$start_ip" "$end_ip"
}

# Main module execution function.
host_main() {
    # Initialize execution context using module common library.
    if ! net_mod_init "$@"; then
        return 1
    fi

    net_mod_write_header "host" "Host Discovery"

    local fping_available=false
    local nmap_available=false
    local tools_used=()

    if net_mod_has_tool "$HOST_FPING_BIN"; then
        fping_available=true
    fi
    if net_mod_has_tool "$HOST_NMAP_BIN"; then
        nmap_available=true
    fi

    local scope_desc="Single Host"
    if net_mod_is_cidr; then
        scope_desc="CIDR Network Block"
    elif net_mod_is_range; then
        scope_desc="IPv4 Address Range"
    fi

    net_mod_write_section "Target Information"
    net_mod_write_kv "Target" "$NET_TARGET"
    net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
    net_mod_write_kv "Scan Scope" "$scope_desc"

    # If neither tool is available, attempt basic ping fallback for single hosts.
    if [[ "$fping_available" == false && "$nmap_available" == false ]]; then
        if net_mod_is_single_host && net_mod_has_tool "ping"; then
            net_mod_write_kv "Discovery Engine" "System ping (fallback)"
            if ping -c 1 -W 2 "$NET_TARGET" >/dev/null 2>&1; then
                _host_add_live "$NET_TARGET"
            fi
        else
            net_mod_write_section "Execution Notice"
            net_mod_write_raw "Error: Neither 'fping' nor 'nmap' is available in PATH."
            net_mod_write_footer "FAILED" "Missing required discovery tools (fping, nmap)."
            return 1
        fi
    fi

    # 1. Execute fping sweep if available.
    if [[ "$fping_available" == true ]]; then
        tools_used+=("fping")
        local fping_out="${NET_TASK_DIR}/fping_raw.txt"
        local -a fping_cmd=("$HOST_FPING_BIN" "-a" "-q")

        if net_mod_is_cidr; then
            fping_cmd+=("-g" "$NET_TARGET")
        elif net_mod_is_range; then
            local r_start r_end
            read -r r_start r_end < <(_host_parse_range "$NET_TARGET")
            fping_cmd+=("-g" "$r_start" "$r_end")
        else
            fping_cmd+=("$NET_TARGET")
        fi

        # Execute fping command.
        "${fping_cmd[@]}" > "$fping_out" 2>/dev/null || true

        # Parse discovered live hosts from fping output.
        if [[ -f "$fping_out" ]]; then
            local line
            while IFS= read -r line || [[ -n "$line" ]]; do
                line="${line//[[:space:]]/}"
                if [[ -n "$line" ]]; then
                    _host_add_live "$line"
                fi
            done < "$fping_out"
        fi
    fi

    # 2. Execute nmap multi-probe discovery if available.
    if [[ "$nmap_available" == true ]]; then
        tools_used+=("nmap")
        local gnmap_file="${NET_TASK_DIR}/nmap_host.gnmap"
        local nmap_out="${NET_TASK_DIR}/nmap_host.nmap"
        local -a nmap_cmd=(
            "$HOST_NMAP_BIN"
            "-sn"
            "-n"
            "--max-retries" "1"
            "-oG" "$gnmap_file"
            "-oN" "$nmap_out"
            "$NET_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        # Parse grepable nmap output for live hosts (Status: Up).
        if [[ -f "$gnmap_file" ]]; then
            local gline
            while IFS= read -r gline || [[ -n "$gline" ]]; do
                if [[ "$gline" == "Host: "* && "$gline" == *"Status: Up"* ]]; then
                    local rest="${gline#Host: }"
                    local ip="${rest%%[[:space:]]*}"
                    if [[ -n "$ip" ]]; then
                        _host_add_live "$ip"
                    fi
                fi
            done < "$gnmap_file"
        fi
    fi

    # Record discovery engines used.
    local engines_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        engines_str="${tools_used[*]}"
    fi
    net_mod_write_kv "Discovery Engines" "$engines_str"

    # Write discovered hosts artifact (one host per line).
    local live_hosts_file="${NET_TASK_DIR}/hosts_live.txt"
    : > "$live_hosts_file"

    net_mod_write_section "Discovered Live Hosts"
    net_mod_write_kv "Total Live Hosts" "${#LIVE_HOSTS[@]}"

    if (( ${#LIVE_HOSTS[@]} > 0 )); then
        net_mod_write_raw "  Discovered Hosts         :"
        local h
        for h in "${LIVE_HOSTS[@]}"; do
            printf '%s\n' "$h" >> "$live_hosts_file"
            net_mod_write_raw "    - $h"
        done
        chmod 0640 "$live_hosts_file" 2>/dev/null || true
        net_mod_write_footer "COMPLETED" "Discovered ${#LIVE_HOSTS[@]} active live host(s)."
    else
        net_mod_write_kv "Discovered Hosts" "None (no responsive systems detected)"
        net_mod_write_footer "COMPLETED" "No live hosts detected."
    fi

    net_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    host_main "$@"
fi
