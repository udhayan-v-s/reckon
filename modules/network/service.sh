#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Service Detection Module (modules/network/service.sh)
#
# Interrogates open network ports on target systems to identify running
# application services, daemon implementations, protocols, and exact version numbers.
# Utilizes prior port scanning artifacts (open_ports.txt) when available to focus
# version probes directly on active listening sockets.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - services.txt (tab-delimited port, proto, state, service, version)
#   - nmap_service.gnmap (grepable Nmap output)
#   - nmap_service.nmap (standard Nmap output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (service version detection engine)
#

set -o nounset

SERVICE_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/common.sh
if ! source "$SERVICE_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
SERVICE_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"

# Main module execution function.
service_main() {
    # Initialize execution context using module common library.
    if ! net_mod_init "$@"; then
        return 1
    fi

    local nmap_bin="${SERVICE_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    net_mod_write_header "service" "Service Detection"

    # Validate target type compatibility (ipv4, hostname, domain).
    if ! net_mod_is_single_host; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Target '$NET_TARGET' ($NET_TARGET_TYPE) is not a single discrete host."
        net_mod_write_raw "       Service detection requires single host targets (ipv4, hostname, domain)."
        net_mod_write_footer "FAILED" "Incompatible target type for service detection."
        return 1
    fi

    # Verify primary scanning tool availability.
    if ! net_mod_has_tool "$nmap_bin"; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Service detection utility 'nmap' is not available in PATH."
        net_mod_write_footer "FAILED" "Missing required service detection tool (nmap)."
        return 1
    fi

    # Check for upstream open ports artifact from prior port scanning task.
    local upstream_ports_file
    upstream_ports_file="$(dirname "$NET_TASK_DIR")/port/open_ports.txt"
    local -a known_ports=()
    local upstream_checked=false

    if [[ -f "$upstream_ports_file" ]]; then
        upstream_checked=true
        local p_line
        while IFS= read -r p_line || [[ -n "$p_line" ]]; do
            p_line="${p_line//[[:space:]]/}"
            if [[ "$p_line" =~ ^[0-9]+$ ]]; then
                known_ports+=("$p_line")
            fi
        done < "$upstream_ports_file"
    fi

    local services_file="${NET_TASK_DIR}/services.txt"
    : > "$services_file"

    # If port module ran and verified zero open ports, skip active probing.
    if [[ "$upstream_checked" == true && ${#known_ports[@]} -eq 0 ]]; then
        net_mod_write_section "Target Information"
        net_mod_write_kv "Target" "$NET_TARGET"
        net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
        net_mod_write_kv "Scan Engine" "nmap"
        net_mod_write_kv "Port Scope" "Known Open Ports (0 ports)"

        net_mod_write_section "Service Detection Notice"
        net_mod_write_raw "Notice: Port scanning detected 0 open ports on target."
        net_mod_write_raw "        Skipping active service version interrogation."

        chmod 0640 "$services_file" 2>/dev/null || true
        net_mod_write_footer "COMPLETED" "No open ports available for service detection."
        net_mod_finish 0
        return 0
    fi

    # Determine scanning technique based on privilege level or mock override.
    local scan_type="-sT"
    local scan_type_desc="TCP Connect Service Scan (-sT -sV)"

    if [[ -n "${RECKON_MOCK_SCAN_TYPE:-}" ]]; then
        scan_type="$RECKON_MOCK_SCAN_TYPE"
        scan_type_desc="Mock Service Scan ($scan_type -sV)"
    elif [[ "$(id -u 2>/dev/null || echo 1000)" -eq 0 ]]; then
        scan_type="-sS"
        scan_type_desc="TCP SYN Service Scan (-sS -sV)"
    fi

    # Determine port specification arguments and description.
    local -a port_args=()
    local port_desc=""

    if (( ${#known_ports[@]} > 0 )); then
        local IFS=','
        local ports_str="${known_ports[*]}"
        port_args=("-p" "$ports_str")
        port_desc="Known Open Ports (${#known_ports[@]} ports: $ports_str)"
    else
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
    fi

    # Construct Nmap version execution command.
    local gnmap_file="${NET_TASK_DIR}/nmap_service.gnmap"
    local nmap_file="${NET_TASK_DIR}/nmap_service.nmap"

    local -a nmap_cmd=(
        "$nmap_bin"
        "-sV"
        "$scan_type"
        "-Pn"
        "-n"
        "--system-dns"
        "-T4"
        "--version-intensity" "${CONFIG_EFFECTIVE_VERSION_INTENSITY:-7}"
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

    # Execute Nmap service scan.
    local nmap_exit=0
    "${nmap_cmd[@]}" >/dev/null 2>&1 || nmap_exit=$?

    # Handle catastrophic Nmap failure where no output was produced.
    if (( nmap_exit != 0 )) && [[ ! -s "$gnmap_file" && ! -s "$nmap_file" ]]; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Nmap service scan execution failed with exit code $nmap_exit."
        net_mod_write_footer "FAILED" "Nmap service detection failed."
        return "$nmap_exit"
    fi

    # Parse discovered services from output files.
    local -a svc_ports=()
    local -a svc_proto=()
    local -a svc_state=()
    local -a svc_name=()
    local -a svc_version=()

    # 1. Parse grepable output file if present.
    if [[ -f "$gnmap_file" ]]; then
        while IFS=$'\t' read -r p_num p_proto p_state p_svc p_ver || [[ -n "$p_num" ]]; do
            [[ -z "$p_num" ]] && continue
            svc_ports+=("$p_num")
            svc_proto+=("$p_proto")
            svc_state+=("$p_state")
            svc_name+=("$p_svc")
            svc_version+=("$p_ver")
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
                ver = fields[7];
                if (state ~ /^open/) {
                    printf "%s\t%s\t%s\t%s\t%s\n", port, proto, state, (svc != "" ? svc : "unknown"), (ver != "" ? ver : "unknown");
                }
            }
        }' "$gnmap_file" 2>/dev/null)
    fi

    # 2. Fallback: Parse standard Nmap output if grepable format yielded no services.
    if (( ${#svc_ports[@]} == 0 )) && [[ -f "$nmap_file" ]]; then
        while IFS=$'\t' read -r p_num p_proto p_state p_svc p_ver || [[ -n "$p_num" ]]; do
            [[ -z "$p_num" ]] && continue
            svc_ports+=("$p_num")
            svc_proto+=("$p_proto")
            svc_state+=("$p_state")
            svc_name+=("$p_svc")
            svc_version+=("$p_ver")
        done < <(awk '/^[0-9]+\/(tcp|udp)[ \t]+open/{
            split($1, p, "/");
            port = p[1];
            proto = p[2];
            state = $2;
            svc = $3;
            ver = "";
            for (i = 4; i <= NF; i++) {
                ver = (ver == "" ? $i : ver " " $i);
            }
            printf "%s\t%s\t%s\t%s\t%s\n", port, proto, state, svc, (ver != "" ? ver : "unknown");
        }' "$nmap_file" 2>/dev/null)
    fi

    # Write normalized findings to services.txt downstream artifact.
    if (( ${#svc_ports[@]} > 0 )); then
        local i
        for (( i = 0; i < ${#svc_ports[@]}; i++ )); do
            printf '%s/%s\t%s\t%s\t%s\n' \
                "${svc_ports[i]}" "${svc_proto[i]}" "${svc_state[i]}" \
                "${svc_name[i]}" "${svc_version[i]}" >> "$services_file"
        done
    fi

    # Ensure secure permissions on all generated artifacts.
    chmod 0640 "$services_file" 2>/dev/null || true
    [[ -f "$gnmap_file" ]] && chmod 0640 "$gnmap_file" 2>/dev/null || true
    [[ -f "$nmap_file" ]] && chmod 0640 "$nmap_file" 2>/dev/null || true

    # Document structured findings in output report.
    net_mod_write_section "Target Information"
    net_mod_write_kv "Target" "$NET_TARGET"
    net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
    net_mod_write_kv "Scan Engine" "nmap"
    net_mod_write_kv "Detection Technique" "$scan_type_desc"
    net_mod_write_kv "Port Scope" "$port_desc"

    net_mod_write_section "Identified Services"
    net_mod_write_kv "Total Services" "${#svc_ports[@]}"

    if (( ${#svc_ports[@]} > 0 )); then
        local -a svc_unique=()
        for (( i = 0; i < ${#svc_ports[@]}; i++ )); do
            local s="${svc_name[i]}"
            local found=false
            local u
            for u in "${svc_unique[@]}"; do
                if [[ "$u" == "$s" ]]; then found=true; break; fi
            done
            if [[ "$found" == false ]]; then svc_unique+=("$s"); fi
        done

        local IFS=','
        local svc_summary="${svc_unique[*]}"
        svc_summary="${svc_summary//,/, }"
        net_mod_write_kv "Service Names" "$svc_summary"
        net_mod_write_raw ""
        net_mod_write_raw "  PORT       STATE      SERVICE     VERSION / PRODUCT DETAILS"
        net_mod_write_raw "  ---------  ---------  ----------  ----------------------------------------"
        for (( i = 0; i < ${#svc_ports[@]}; i++ )); do
            local p_label="${svc_ports[i]}/${svc_proto[i]}"
            local p_st="${svc_state[i]}"
            local p_sv="${svc_name[i]}"
            local p_vr="${svc_version[i]}"
            local row
            printf -v row '  %-9s  %-9s  %-10s  %s' "$p_label" "$p_st" "$p_sv" "$p_vr"
            net_mod_write_raw "$row"
        done
        net_mod_write_footer "COMPLETED" "Identified ${#svc_ports[@]} active service(s)."
    else
        net_mod_write_kv "Service Names" "None (no active services identified)"
        net_mod_write_footer "COMPLETED" "No active services identified."
    fi

    net_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    service_main "$@"
fi
