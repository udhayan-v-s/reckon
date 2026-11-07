#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Port Scanning Module (modules/network/port.sh)
#
# Orchestrates Nmap TCP port discovery across single discrete targets
# (IPv4 addresses, hostnames, and domain names), captures raw artifacts,
# extracts open ports, and produces structured findings reports.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - open_ports.txt (newline-delimited open port numbers)
#   - nmap_port.gnmap (grepable Nmap output)
#   - nmap_port.nmap (standard Nmap output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (network exploration tool and security / port scanner)
#

set -o nounset

PORT_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/common.sh
if ! source "$PORT_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
PORT_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"

# Main module execution function.
port_main() {
    # Initialize execution context using module common library.
    if ! net_mod_init "$@"; then
        return 1
    fi

    local nmap_bin="${PORT_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    net_mod_write_header "port" "Port Scanning"

    # Validate target type compatibility (ipv4, hostname, domain).
    if ! net_mod_is_single_host; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Target '$NET_TARGET' ($NET_TARGET_TYPE) is not a single discrete host."
        net_mod_write_raw "       Port scanning requires single host targets (ipv4, hostname, domain)."
        net_mod_write_footer "FAILED" "Incompatible target type for port scanning."
        return 1
    fi

    # Verify primary scanning tool availability.
    if ! net_mod_has_tool "$nmap_bin"; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Port scanning utility 'nmap' is not available in PATH."
        net_mod_write_footer "FAILED" "Missing required port scanning tool (nmap)."
        return 1
    fi

    # Determine scanning technique based on privilege level or mock override.
    local scan_type="-sT"
    local scan_type_desc="TCP Connect (-sT)"

    if [[ -n "${RECKON_MOCK_SCAN_TYPE:-}" ]]; then
        scan_type="$RECKON_MOCK_SCAN_TYPE"
        scan_type_desc="Mock Scan ($scan_type)"
    elif [[ "$(id -u 2>/dev/null || echo 1000)" -eq 0 ]]; then
        scan_type="-sS"
        scan_type_desc="TCP SYN Stealth (-sS)"
    fi

    # Determine port specification arguments and human-readable scope description.
    local -a port_args=()
    local port_desc=""
    local ports_cfg="${CONFIG_EFFECTIVE_PORTS:-}"
    ports_cfg="${ports_cfg//[[:space:]]/}"

    if [[ -z "$ports_cfg" ]]; then
        case "${CONFIG_EFFECTIVE_PROFILE:-}" in
            fast|quick)
                port_args=("--top-ports" "100")
                port_desc="Top 100 Ports (fast profile)"
                ;;
            full|all)
                port_args=("-p-")
                port_desc="All 65535 Ports (full profile)"
                ;;
            *)
                port_args=("--top-ports" "1000")
                port_desc="Top 1000 Ports (default)"
                ;;
        esac
    else
        case "$ports_cfg" in
            top-100|top100|100)
                port_args=("--top-ports" "100")
                port_desc="Top 100 Ports"
                ;;
            top-1000|top1000|1000)
                port_args=("--top-ports" "1000")
                port_desc="Top 1000 Ports"
                ;;
            full|all|1-65535|-p-)
                port_args=("-p-")
                port_desc="All 65535 Ports (Full Scan)"
                ;;
            *)
                port_args=("-p" "$ports_cfg")
                port_desc="Custom Ports ($ports_cfg)"
                ;;
        esac
    fi

    # Construct Nmap execution command.
    local gnmap_file="${NET_TASK_DIR}/nmap_port.gnmap"
    local nmap_file="${NET_TASK_DIR}/nmap_port.nmap"

    local -a nmap_cmd=(
        "$nmap_bin"
        "$scan_type"
        "-Pn"
        "-n"
        "--system-dns"
        "-T4"
        "--max-retries" "${CONFIG_EFFECTIVE_RETRIES:-1}"
    )

    nmap_cmd+=("${port_args[@]}")

    if [[ -n "${CONFIG_EFFECTIVE_RATE_LIMIT:-}" && "$CONFIG_EFFECTIVE_RATE_LIMIT" =~ ^[0-9]+$ ]]; then
        nmap_cmd+=("--min-rate" "$CONFIG_EFFECTIVE_RATE_LIMIT")
    fi

    if [[ -n "${CONFIG_EFFECTIVE_TIMEOUT:-}" && "$CONFIG_EFFECTIVE_TIMEOUT" =~ ^[0-9]+$ ]]; then
        nmap_cmd+=("--host-timeout" "${CONFIG_EFFECTIVE_TIMEOUT}s")
    fi

    nmap_cmd+=(
        "-oG" "$gnmap_file"
        "-oN" "$nmap_file"
        "$NET_TARGET"
    )

    # Execute Nmap scan.
    local nmap_exit=0
    "${nmap_cmd[@]}" >/dev/null 2>&1 || nmap_exit=$?

    # Handle catastrophic Nmap failure where no output was produced.
    if (( nmap_exit != 0 )) && [[ ! -s "$gnmap_file" && ! -s "$nmap_file" ]]; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Nmap scan execution failed with exit code $nmap_exit."
        net_mod_write_footer "FAILED" "Nmap port scan failed."
        return "$nmap_exit"
    fi

    # Initialize open ports artifact file.
    local open_ports_file="${NET_TASK_DIR}/open_ports.txt"
    : > "$open_ports_file"

    local -a open_ports=()
    local -a open_proto=()
    local -a open_state=()
    local -a open_service=()

    # Parse grepable output file if present.
    if [[ -f "$gnmap_file" ]]; then
        while IFS='|' read -r p_num p_proto p_state p_svc || [[ -n "$p_num" ]]; do
            [[ -z "$p_num" ]] && continue
            open_ports+=("$p_num")
            open_proto+=("$p_proto")
            open_state+=("$p_state")
            open_service+=("$p_svc")
        done < <(awk -F'Ports: ' '/Ports: /{
            split($2, tab_split, "\t");
            ports_str = tab_split[1];
            n = split(ports_str, items, ", ");
            for (i = 1; i <= n; i++) {
                split(items[i], fields, "/");
                port = fields[1];
                state = fields[2];
                proto = fields[3];
                svc = fields[5];
                if (state ~ /^open/) {
                    printf "%s|%s|%s|%s\n", port, proto, state, (svc != "" ? svc : "unknown");
                }
            }
        }' "$gnmap_file" 2>/dev/null)
    fi

    # Fallback: Parse standard Nmap output if grepable format yielded no ports.
    if (( ${#open_ports[@]} == 0 )) && [[ -f "$nmap_file" ]]; then
        while IFS='|' read -r p_num p_proto p_state p_svc || [[ -n "$p_num" ]]; do
            [[ -z "$p_num" ]] && continue
            open_ports+=("$p_num")
            open_proto+=("$p_proto")
            open_state+=("$p_state")
            open_service+=("$p_svc")
        done < <(awk '/^[0-9]+\/(tcp|udp)[ \t]+open/{
            split($1, p, "/");
            svc = ($3 != "" ? $3 : "unknown");
            printf "%s|%s|open|%s\n", p[1], p[2], svc;
        }' "$nmap_file" 2>/dev/null)
    fi

    # Write discovered open port numbers to downstream artifact.
    if (( ${#open_ports[@]} > 0 )); then
        local p
        for p in "${open_ports[@]}"; do
            printf '%s\n' "$p" >> "$open_ports_file"
        done
    fi

    # Ensure secure permissions on all generated artifacts.
    chmod 0640 "$open_ports_file" 2>/dev/null || true
    [[ -f "$gnmap_file" ]] && chmod 0640 "$gnmap_file" 2>/dev/null || true
    [[ -f "$nmap_file" ]] && chmod 0640 "$nmap_file" 2>/dev/null || true

    # Document structured findings in output report.
    net_mod_write_section "Target Information"
    net_mod_write_kv "Target" "$NET_TARGET"
    net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
    net_mod_write_kv "Scan Engine" "nmap"
    net_mod_write_kv "Scan Technique" "$scan_type_desc"
    net_mod_write_kv "Port Scope" "$port_desc"

    net_mod_write_section "Discovered Open Ports"
    net_mod_write_kv "Total Open Ports" "${#open_ports[@]}"

    if (( ${#open_ports[@]} > 0 )); then
        local IFS=', '
        local ports_csv="${open_ports[*]}"
        net_mod_write_kv "Open Port List" "$ports_csv"
        net_mod_write_raw ""
        net_mod_write_raw "  PORT       STATE      SERVICE"
        net_mod_write_raw "  ---------  ---------  --------------------"
        local i
        for (( i = 0; i < ${#open_ports[@]}; i++ )); do
            local p_label="${open_ports[i]}/${open_proto[i]}"
            local p_st="${open_state[i]}"
            local p_sv="${open_service[i]}"
            local row
            printf -v row '  %-9s  %-9s  %s' "$p_label" "$p_st" "$p_sv"
            net_mod_write_raw "$row"
        done
        net_mod_write_footer "COMPLETED" "Identified ${#open_ports[@]} open port(s)."
    else
        net_mod_write_kv "Open Port List" "None (no open ports detected)"
        net_mod_write_footer "COMPLETED" "No open ports detected."
    fi

    net_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    port_main "$@"
fi
