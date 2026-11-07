#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Operating System Fingerprinting Module (modules/network/os.sh)
#
# Analyzes network stack responses and banner heuristics across target systems
# to identify operating system family, kernel releases, hardware architecture,
# and device classifications. Utilizes upstream open ports (open_ports.txt) to
# focus fingerprinting probes directly on responsive services.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - os_info.txt (key-value OS summary)
#   - nmap_os.gnmap (grepable Nmap output)
#   - nmap_os.nmap (standard Nmap output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (OS fingerprinting and heuristic analysis engine)
#

set -o nounset

OS_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/common.sh
if ! source "$OS_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
OS_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"

# Main module execution function.
os_main() {
    # Initialize execution context using module common library.
    if ! net_mod_init "$@"; then
        return 1
    fi

    local nmap_bin="${OS_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    net_mod_write_header "os" "OS Detection"

    # Validate target type compatibility (ipv4, hostname, domain).
    if ! net_mod_is_single_host; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Target '$NET_TARGET' ($NET_TARGET_TYPE) is not a single discrete host."
        net_mod_write_raw "       OS detection requires single host targets (ipv4, hostname, domain)."
        net_mod_write_footer "FAILED" "Incompatible target type for OS detection."
        return 1
    fi

    # Verify primary scanning tool availability.
    if ! net_mod_has_tool "$nmap_bin"; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: OS detection utility 'nmap' is not available in PATH."
        net_mod_write_footer "FAILED" "Missing required OS detection tool (nmap)."
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

    local os_info_file="${NET_TASK_DIR}/os_info.txt"
    : > "$os_info_file"

    # If port module ran and verified zero open ports, skip active probing.
    if [[ "$upstream_checked" == true && ${#known_ports[@]} -eq 0 ]]; then
        net_mod_write_section "Target Information"
        net_mod_write_kv "Target" "$NET_TARGET"
        net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
        net_mod_write_kv "Scan Engine" "nmap"

        net_mod_write_section "OS Detection Notice"
        net_mod_write_raw "Notice: Port scanning detected 0 open ports on target."
        net_mod_write_raw "        Skipping active operating system fingerprinting."

        chmod 0640 "$os_info_file" 2>/dev/null || true
        net_mod_write_footer "COMPLETED" "No open ports available for OS fingerprinting."
        net_mod_finish 0
        return 0
    fi

    # Determine fingerprinting technique based on privilege level.
    # Root: TCP/IP Stack Fingerprinting (-O)
    # Unprivileged: Service Banner & Version Heuristics (-sV)
    local is_privileged=false
    if [[ "${RECKON_MOCK_OS_ROOT:-false}" == "true" || "$(id -u 2>/dev/null || echo 1000)" -eq 0 ]]; then
        is_privileged=true
    fi

    local -a os_probe_args=()
    local method_desc=""

    if [[ -n "${RECKON_MOCK_OS_SCAN_ARGS:-}" ]]; then
        # shellcheck disable=SC2206
        os_probe_args=($RECKON_MOCK_OS_SCAN_ARGS)
        method_desc="Mock Fingerprinting ($RECKON_MOCK_OS_SCAN_ARGS)"
    elif [[ "$is_privileged" == true ]]; then
        os_probe_args=("-O" "--osscan-guess" "--max-os-tries" "1")
        method_desc="TCP/IP Stack Fingerprinting (-O)"
    else
        os_probe_args=("-sV" "--version-intensity" "5")
        method_desc="Banner & Service Heuristics (-sV)"
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

        if [[ -n "$ports_cfg" ]]; then
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
                    port_desc="All 65535 Ports"
                    ;;
                *)
                    port_args=("-p" "$ports_cfg")
                    port_desc="Custom Ports ($ports_cfg)"
                    ;;
            esac
        else
            port_args=("--top-ports" "100")
            port_desc="Top 100 Ports (default OS scope)"
        fi
    fi

    # Construct Nmap OS execution command.
    local gnmap_file="${NET_TASK_DIR}/nmap_os.gnmap"
    local nmap_file="${NET_TASK_DIR}/nmap_os.nmap"

    local -a nmap_cmd=(
        "$nmap_bin"
        "-Pn"
        "-n"
        "--system-dns"
        "-T4"
        "--max-retries" "${CONFIG_EFFECTIVE_RETRIES:-1}"
    )

    nmap_cmd+=("${os_probe_args[@]}")
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

    # Execute Nmap OS scan.
    local nmap_exit=0
    "${nmap_cmd[@]}" >/dev/null 2>&1 || nmap_exit=$?

    # Handle catastrophic Nmap failure where no output was produced.
    if (( nmap_exit != 0 )) && [[ ! -s "$gnmap_file" && ! -s "$nmap_file" ]]; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Nmap OS scan execution failed with exit code $nmap_exit."
        net_mod_write_footer "FAILED" "Nmap OS detection failed."
        return "$nmap_exit"
    fi

    # Parse OS identification details from scan outputs.
    local os_details=""
    local os_running=""
    local os_cpe=""
    local os_device=""
    local os_accuracy=""

    # 1. Parse standard nmap text report.
    if [[ -f "$nmap_file" ]]; then
        local raw_content
        raw_content="$(< "$nmap_file")"

        while IFS= read -r line || [[ -n "$line" ]]; do
            case "$line" in
                "OS details: "*)
                    os_details="${line#OS details: }"
                    ;;
                "Running: "*)
                    os_running="${line#Running: }"
                    ;;
                "OS CPE: "*)
                    os_cpe="${line#OS CPE: }"
                    ;;
                "Device type: "*)
                    os_device="${line#Device type: }"
                    ;;
                "Aggressive OS guesses: "*)
                    local guesses="${line#Aggressive OS guesses: }"
                    local first_guess="${guesses%%,*}"
                    if [[ -z "$os_details" ]]; then
                        os_details="${first_guess% (*}"
                    fi
                    if [[ "$first_guess" =~ \(([0-9]+%)\) ]]; then
                        os_accuracy="${BASH_REMATCH[1]}"
                    fi
                    ;;
                *"Service Info: OS: "*|*"Service Info: OSs: "*)
                    local info_os="${line#*Service Info: OS*: }"
                    info_os="${info_os%%;*}"
                    [[ -z "$os_details" ]] && os_details="$info_os"
                    if [[ "$line" == *"CPE: "* ]]; then
                        local cpe_val="${line#*CPE: }"
                        cpe_val="${cpe_val%%;*}"
                        [[ -z "$os_cpe" ]] && os_cpe="$cpe_val"
                    fi
                    ;;
            esac
        done < "$nmap_file"

        # Secondary banner heuristic fallback if still unresolved
        if [[ -z "$os_details" ]]; then
            if [[ "$raw_content" == *"Ubuntu"* ]]; then
                os_details="Linux (Ubuntu)"
                [[ -z "$os_running" ]] && os_running="Linux"
                [[ -z "$os_cpe" ]] && os_cpe="cpe:/o:canonical:ubuntu_linux"
            elif [[ "$raw_content" == *"Debian"* ]]; then
                os_details="Linux (Debian)"
                [[ -z "$os_running" ]] && os_running="Linux"
                [[ -z "$os_cpe" ]] && os_cpe="cpe:/o:debian:debian_linux"
            elif [[ "$raw_content" == *"Windows"* || "$raw_content" == *"Microsoft"* ]]; then
                os_details="Microsoft Windows"
                [[ -z "$os_running" ]] && os_running="Microsoft Windows"
                [[ -z "$os_cpe" ]] && os_cpe="cpe:/o:microsoft:windows"
            elif [[ "$raw_content" == *"FreeBSD"* ]]; then
                os_details="FreeBSD"
                [[ -z "$os_running" ]] && os_running="FreeBSD"
                [[ -z "$os_cpe" ]] && os_cpe="cpe:/o:freebsd:freebsd"
            fi
        fi
    fi

    # 2. Check grepable gnmap output if os_details remains empty.
    if [[ -z "$os_details" && -f "$gnmap_file" ]]; then
        while IFS=$'\t' read -r -a fields; do
            local f
            for f in "${fields[@]}"; do
                if [[ "$f" == "OS: "* ]]; then
                    local g_os="${f#OS: }"
                    if [[ -n "$g_os" && "$g_os" != "Unknown" && "$g_os" != "unknown" ]]; then
                        os_details="$g_os"
                        break 2
                    fi
                fi
            done
        done < "$gnmap_file"
    fi

    # Populate os_info.txt artifact.
    {
        printf 'OS: %s\n' "${os_details:-Unknown}"
        printf 'Running: %s\n' "${os_running:-Unknown}"
        printf 'Device: %s\n' "${os_device:-Unknown}"
        printf 'CPE: %s\n' "${os_cpe:-Unknown}"
        if [[ -n "$os_accuracy" ]]; then
            printf 'Accuracy: %s\n' "$os_accuracy"
        fi
        printf 'Method: %s\n' "$method_desc"
    } > "$os_info_file"

    # Ensure secure permissions on all generated artifacts.
    chmod 0640 "$os_info_file" 2>/dev/null || true
    [[ -f "$gnmap_file" ]] && chmod 0640 "$gnmap_file" 2>/dev/null || true
    [[ -f "$nmap_file" ]] && chmod 0640 "$nmap_file" 2>/dev/null || true

    # Document structured findings in output report.
    net_mod_write_section "Target Information"
    net_mod_write_kv "Target" "$NET_TARGET"
    net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
    net_mod_write_kv "Scan Engine" "nmap"
    net_mod_write_kv "Fingerprint Method" "$method_desc"
    net_mod_write_kv "Port Scope" "$port_desc"

    net_mod_write_section "Operating System Identification"
    if [[ -n "$os_details" ]]; then
        net_mod_write_kv "OS Details" "$os_details"
        [[ -n "$os_running" ]] && net_mod_write_kv "OS Family / Kernel" "$os_running"
        [[ -n "$os_device" ]] && net_mod_write_kv "Device Category" "$os_device"
        [[ -n "$os_cpe" ]] && net_mod_write_kv "Common Platform Enum" "$os_cpe"
        [[ -n "$os_accuracy" ]] && net_mod_write_kv "Confidence Rating" "$os_accuracy"
        net_mod_write_footer "COMPLETED" "Identified OS: $os_details."
    else
        net_mod_write_kv "OS Details" "Unknown (insufficient fingerprint responses)"
        net_mod_write_footer "COMPLETED" "Operating system could not be fingerprinted."
    fi

    net_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    os_main "$@"
fi
