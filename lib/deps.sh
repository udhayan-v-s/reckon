#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# External dependency inspection and management library
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_LIB_DEPS_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_DEPS_LOADED=1

# State arrays tracking dependency inspection outcomes.
DEPS_AVAILABLE_TOOLS=()
DEPS_MISSING_TOOLS=()
DEPS_CHECKED_MODULES=()

# Last error recorded by dependency functions.
DEPS_ERROR=""

# Canonical list of 25 reconnaissance modules.
readonly _DEPS_ALL_MODULES=(
    "host"
    "dns"
    "port"
    "service"
    "os"
    "ssh"
    "ftp"
    "http"
    "https"
    "smb"
    "telnet"
    "http-probe"
    "subdomain"
    "crawl"
    "technology"
    "cms"
    "waf"
    "directory"
    "file"
    "vhost"
    "endpoint"
    "http-analysis"
    "tls"
    "resources"
    "historical-urls"
)

# Canonical list of 19 external security tools across all modules.
readonly _DEPS_ALL_TOOLS=(
    "curl"
    "dig"
    "dnsx"
    "enum4linux-ng"
    "ffuf"
    "fping"
    "gau"
    "httpx"
    "katana"
    "nc"
    "nmap"
    "openssl"
    "smbclient"
    "ssh-audit"
    "ssh-keyscan"
    "subfinder"
    "testssl.sh"
    "wafw00f"
    "whatweb"
)

# Initialize or reset dependency tracking state.
deps_init() {
    DEPS_AVAILABLE_TOOLS=()
    DEPS_MISSING_TOOLS=()
    DEPS_CHECKED_MODULES=()
    DEPS_ERROR=""
}

# Check if a single external tool is available in PATH.
#
# Arguments:
#   $1 - tool command name
#
# Returns:
#   0 if tool binary exists and is executable, 1 otherwise
deps_has_tool() {
    local tool="${1:-}"
    [[ -n "$tool" ]] && command -v -- "$tool" >/dev/null 2>&1
}

# Return a functional description for an external security tool.
#
# Arguments:
#   $1 - tool command name
#
# Outputs:
#   Descriptive string defining the tool's purpose.
deps_get_tool_desc() {
    local tool="${1:-}"

    case "$tool" in
        nmap)
            printf '%s\n' "Network exploration tool and security / port scanner"
            ;;
        fping)
            printf '%s\n' "High-performance ICMP ping sweep utility"
            ;;
        dig)
            printf '%s\n' "DNS lookup and domain interrogation utility"
            ;;
        nc)
            printf '%s\n' "Arbitrary TCP and UDP connection and listening utility (netcat)"
            ;;
        ssh-keyscan)
            printf '%s\n' "SSH public host key gatherer"
            ;;
        ssh-audit)
            printf '%s\n' "SSH server security auditing and configuration analysis tool"
            ;;
        curl)
            printf '%s\n' "Command line tool for transferring data with URLs"
            ;;
        openssl)
            printf '%s\n' "Cryptography toolkit and TLS/SSL diagnostic utility"
            ;;
        smbclient)
            printf '%s\n' "SMB/CIFS file sharing and share enumeration client"
            ;;
        enum4linux-ng)
            printf '%s\n' "Windows and Samba information enumeration tool"
            ;;
        httpx)
            printf '%s\n' "Fast and multi-purpose HTTP probing and analysis toolkit"
            ;;
        subfinder)
            printf '%s\n' "Passive subdomain discovery and enumeration tool"
            ;;
        dnsx)
            printf '%s\n' "Multi-purpose DNS query, probe, and resolution toolkit"
            ;;
        katana)
            printf '%s\n' "Next-generation crawling and spidering framework"
            ;;
        whatweb)
            printf '%s\n' "Web technology identifier and CMS detector"
            ;;
        wafw00f)
            printf '%s\n' "Web Application Firewall (WAF) fingerprinting tool"
            ;;
        ffuf)
            printf '%s\n' "Fast web fuzzer for directory, file, and vhost discovery"
            ;;
        testssl.sh)
            printf '%s\n' "TLS/SSL cipher suites and cryptographic vulnerability checker"
            ;;
        gau)
            printf '%s\n' "Fetch known URLs from AlienVault, Wayback Machine, and Common Crawl"
            ;;
        feroxbuster)
            printf '%s\n' "Fast, simple, recursive content discovery tool"
            ;;
        amass)
            printf '%s\n' "In-depth attack surface mapping and asset discovery tool"
            ;;
        host)
            printf '%s\n' "DNS lookup utility for resolving hostnames to IP addresses"
            ;;
        *)
            printf '%s\n' "External reconnaissance utility"
            ;;
    esac
}

# Return priority tier for an external security tool: 'required', 'recommended', or 'optional'.
#
# Arguments:
#   $1 - tool command name
#
# Returns:
#   0 always (prints tier name to stdout)
deps_get_tool_tier() {
    local tool="${1:-}"

    case "$tool" in
        curl|dig|ffuf|httpx|nc|nmap|openssl|smbclient)
            printf '%s\n' "required"
            ;;
        dnsx|enum4linux-ng|katana|ssh-audit|subfinder|wafw00f|whatweb)
            printf '%s\n' "recommended"
            ;;
        fping|gau|ssh-keyscan|testssl.sh)
            printf '%s\n' "optional"
            ;;
        *)
            printf '%s\n' "optional"
            ;;
    esac
    return 0
}

# Output the canonical list of all supported module identifiers (one per line).
deps_get_all_modules() {
    local mod
    for mod in "${_DEPS_ALL_MODULES[@]}"; do
        printf '%s\n' "$mod"
    done
}

# Output the canonical list of all unique external tools (one per line).
deps_get_all_tools() {
    local tool
    for tool in "${_DEPS_ALL_TOOLS[@]}"; do
        printf '%s\n' "$tool"
    done
}

# Output the external tools required by a given reconnaissance module.
#
# Arguments:
#   $1 - module identifier
#
# Outputs:
#   Required tool names, one per line.
#
# Returns:
#   0 on success, 1 on invalid module identifier (sets DEPS_ERROR)
deps_get_module_tools() {
    local module="${1:-}"

    DEPS_ERROR=""

    if [[ -z "$module" ]]; then
        DEPS_ERROR="Module identifier cannot be empty."
        return 1
    fi

    case "$module" in
        host)
            printf '%s\n' "nmap" "fping"
            ;;
        dns)
            printf '%s\n' "dig"
            ;;
        port|service|os)
            printf '%s\n' "nmap"
            ;;
        ssh)
            printf '%s\n' "nmap" "ssh-keyscan" "ssh-audit"
            ;;
        ftp)
            printf '%s\n' "nmap" "nc"
            ;;
        http)
            printf '%s\n' "nmap" "curl"
            ;;
        https)
            printf '%s\n' "nmap" "curl" "openssl" "testssl.sh"
            ;;
        smb)
            printf '%s\n' "nmap" "smbclient" "enum4linux-ng"
            ;;
        telnet)
            printf '%s\n' "nmap" "nc"
            ;;
        http-probe)
            printf '%s\n' "httpx"
            ;;
        subdomain)
            printf '%s\n' "subfinder" "dnsx"
            ;;
        crawl|endpoint)
            printf '%s\n' "katana"
            ;;
        technology|cms)
            printf '%s\n' "whatweb"
            ;;
        waf)
            printf '%s\n' "wafw00f"
            ;;
        directory|file|vhost)
            printf '%s\n' "ffuf"
            ;;
        tls)
            printf '%s\n' "testssl.sh" "openssl"
            ;;
        http-analysis|resources)
            printf '%s\n' "curl"
            ;;
        historical-urls)
            printf '%s\n' "gau"
            ;;
        *)
            DEPS_ERROR="Invalid module identifier: $module"
            return 1
            ;;
    esac

    return 0
}

# Check a list of external tools for presence in PATH.
# Deduplicates tool names and populates DEPS_AVAILABLE_TOOLS and DEPS_MISSING_TOOLS.
#
# Arguments:
#   $@ - list of tool command names
#
# Returns:
#   0 if all tools are available, 1 if any tool is missing
deps_check_tools() {
    local -a input_tools=("$@")
    local tool
    local seen_item
    local -a unique_tools=()

    DEPS_AVAILABLE_TOOLS=()
    DEPS_MISSING_TOOLS=()
    DEPS_ERROR=""

    if (( ${#input_tools[@]} == 0 )); then
        return 0
    fi

    # Deduplicate tool list while preserving order.
    for tool in "${input_tools[@]}"; do
        [[ -z "$tool" ]] && continue
        local already_seen=false
        for seen_item in "${unique_tools[@]}"; do
            if [[ "$seen_item" == "$tool" ]]; then
                already_seen=true
                break
            fi
        done
        if [[ "$already_seen" == false ]]; then
            unique_tools+=("$tool")
        fi
    done

    # Test presence of each unique tool.
    for tool in "${unique_tools[@]}"; do
        if deps_has_tool "$tool"; then
            DEPS_AVAILABLE_TOOLS+=("$tool")
        else
            DEPS_MISSING_TOOLS+=("$tool")
        fi
    done

    if (( ${#DEPS_MISSING_TOOLS[@]} > 0 )); then
        return 1
    fi

    return 0
}

# Check external tool dependencies for a set of reconnaissance modules.
# Aggregates required tools across all specified modules, deduplicates them,
# and checks tool availability.
#
# Arguments:
#   $@ - module identifiers
#
# Returns:
#   0 if all required tools are available, 1 if any tool is missing or module is invalid
deps_check_modules() {
    local -a modules=("$@")
    local mod
    local tool
    local -a collected_tools=()
    local -a mod_tools=()
    local ret=0

    deps_init

    if (( ${#modules[@]} == 0 )); then
        return 0
    fi

    # Validate each module and gather required tools.
    for mod in "${modules[@]}"; do
        [[ -z "$mod" ]] && continue

        mod_tools=()
        while IFS= read -r tool; do
            [[ -n "$tool" ]] && mod_tools+=("$tool")
        done < <(deps_get_module_tools "$mod" 2>/dev/null || true)

        if (( ${#mod_tools[@]} == 0 )); then
            # Verify if this was because of invalid module or really empty.
            if ! deps_get_module_tools "$mod" >/dev/null 2>&1; then
                DEPS_ERROR="Invalid module identifier: $mod"
                return 1
            fi
        fi

        DEPS_CHECKED_MODULES+=("$mod")
        collected_tools+=("${mod_tools[@]}")
    done

    deps_check_tools "${collected_tools[@]}"
    ret=$?

    return "$ret"
}

# Check external tool dependencies for the entire toolkit (all 25 modules).
#
# Returns:
#   0 if all tools are available, 1 if any tool is missing
deps_check_all() {
    DEPS_CHECKED_MODULES=("${_DEPS_ALL_MODULES[@]}")
    deps_check_tools "${_DEPS_ALL_TOOLS[@]}"
}

# Render a structured terminal report of dependency inspection results.
#
# Arguments:
#   $1 - optional report title/scope override
#
# Returns:
#   0 if all checked dependencies are available, 1 if any are missing
deps_render_report() {
    local custom_scope="${1:-}"
    local tool
    local desc
    local badge
    local total_count
    local avail_count
    local missing_count
    local scope_text
    local -a all_inspected=()

    avail_count=${#DEPS_AVAILABLE_TOOLS[@]}
    missing_count=${#DEPS_MISSING_TOOLS[@]}
    total_count=$(( avail_count + missing_count ))

    if (( total_count == 0 )); then
        printf 'No dependency inspection has been performed.\n'
        return 1
    fi

    # Determine scope description.
    if [[ -n "$custom_scope" ]]; then
        scope_text="$custom_scope"
    elif (( ${#DEPS_CHECKED_MODULES[@]} == 25 )); then
        scope_text="All Modules (25 modules)"
    elif (( ${#DEPS_CHECKED_MODULES[@]} > 0 )); then
        local IFS=', '
        scope_text="Modules: ${DEPS_CHECKED_MODULES[*]} (${#DEPS_CHECKED_MODULES[@]} modules)"
    else
        scope_text="Direct tool inspection ($total_count tools)"
    fi

    # Collect and sort all inspected tool names alphabetically using pure Bash.
    all_inspected=("${DEPS_AVAILABLE_TOOLS[@]}" "${DEPS_MISSING_TOOLS[@]}")
    local -a sorted_tools=("${all_inspected[@]}")
    local i j temp
    local n=${#sorted_tools[@]}
    for ((i = 0; i < n; i++)); do
        for ((j = i + 1; j < n; j++)); do
            if [[ "${sorted_tools[i]}" > "${sorted_tools[j]}" ]]; then
                temp="${sorted_tools[i]}"
                sorted_tools[i]="${sorted_tools[j]}"
                sorted_tools[j]="$temp"
            fi
        done
    done

    # Partition tools into tiers
    local -a req_tools=()
    local -a rec_tools=()
    local -a opt_tools=()
    local tier
    local req_avail=0 req_missing=0
    local rec_avail=0 rec_missing=0
    local opt_avail=0 opt_missing=0

    for tool in "${sorted_tools[@]}"; do
        tier="$(deps_get_tool_tier "$tool")"
        local is_tool_avail=false
        local t
        for t in "${DEPS_AVAILABLE_TOOLS[@]}"; do
            if [[ "$t" == "$tool" ]]; then
                is_tool_avail=true
                break
            fi
        done

        case "$tier" in
            required)
                req_tools+=("$tool")
                if [[ "$is_tool_avail" == true ]]; then (( req_avail += 1 )); else (( req_missing += 1 )); fi
                ;;
            recommended)
                rec_tools+=("$tool")
                if [[ "$is_tool_avail" == true ]]; then (( rec_avail += 1 )); else (( rec_missing += 1 )); fi
                ;;
            optional)
                opt_tools+=("$tool")
                if [[ "$is_tool_avail" == true ]]; then (( opt_avail += 1 )); else (( opt_missing += 1 )); fi
                ;;
        esac
    done

    # Header
    printf '%s\n' "================================================================================"
    if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
        printf '                       %s\n' "$(term_bold "RECKON - DEPENDENCY DASHBOARD")"
    else
        printf '                       RECKON - DEPENDENCY DASHBOARD\n'
    fi
    printf '%s\n\n' "================================================================================"
    printf '  RECKON - Dependency Status\n'
    printf '  Scope: %s\n' "$scope_text"
    if (( ${#DEPS_CHECKED_MODULES[@]} > 0 )); then
        printf '  Modules: %d\n' "${#DEPS_CHECKED_MODULES[@]}"
    fi
    printf '  Unique Tools: %d\n' "$total_count"

    # Helper function to print a tier block
    _deps_print_tier_block() {
        local tier_title="$1"
        shift
        local -a tools_list=("$@")
        (( ${#tools_list[@]} == 0 )) && return 0

        printf '\n%s\n' "--------------------------------------------------------------------------------"
        printf '  %s\n' "$tier_title"
        printf '%s\n\n' "--------------------------------------------------------------------------------"

        for tool in "${tools_list[@]}"; do
            desc="$(deps_get_tool_desc "$tool")"
            local is_avail=false
            local t
            for t in "${DEPS_AVAILABLE_TOOLS[@]}"; do
                if [[ "$t" == "$tool" ]]; then
                    is_avail=true
                    break
                fi
            done

            if [[ "$is_avail" == true ]]; then
                if declare -f term_green >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    badge="$(term_green "[FOUND]  ")"
                else
                    badge="[FOUND]  "
                fi
            else
                if declare -f term_red >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    badge="$(term_red "[MISSING]")"
                else
                    badge="[MISSING]"
                fi
            fi

            printf '  %s  %-15s %s\n' "$badge" "$tool" "$desc"
        done
    }

    if (( ${#req_tools[@]} > 0 )); then
        _deps_print_tier_block "REQUIRED DEPENDENCIES" "${req_tools[@]}"
    fi
    if (( ${#rec_tools[@]} > 0 )); then
        _deps_print_tier_block "RECOMMENDED DEPENDENCIES" "${rec_tools[@]}"
    fi
    if (( ${#opt_tools[@]} > 0 )); then
        _deps_print_tier_block "OPTIONAL DEPENDENCIES" "${opt_tools[@]}"
    fi

    # Determine status string
    local status_str="SATISFIED"
    if (( req_missing > 0 )); then
        status_str="CRITICAL"
    elif (( rec_missing > 0 || opt_missing > 0 )); then
        status_str="WARNINGS"
    fi

    # Footer summary
    printf '\n%s\n' "================================================================================"
    if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
        printf '  %s\n' "$(term_bold "DEPENDENCY SUMMARY")"
    else
        printf '  DEPENDENCY SUMMARY\n'
    fi
    printf '%s\n\n' "================================================================================"
    printf '  Summary: %d total inspected | %d available | %d missing\n' \
        "$total_count" "$avail_count" "$missing_count"
    printf '  Total Inspected         : %d\n' "$total_count"
    printf '  Available               : %d\n' "$avail_count"
    printf '  Missing Required        : %d\n' "$req_missing"
    printf '  Missing Recommended     : %d\n' "$rec_missing"
    printf '  Missing Optional        : %d\n\n' "$opt_missing"

    if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
        if [[ "$status_str" == "SATISFIED" ]]; then
            printf '  Status                  : %s\n' "$(term_green "SATISFIED")"
        elif [[ "$status_str" == "WARNINGS" ]]; then
            printf '  Status                  : %s\n' "$(term_yellow "WARNINGS")"
        else
            printf '  Status                  : %s\n' "$(term_red "CRITICAL")"
        fi
    else
        printf '  Status                  : %s\n' "$status_str"
    fi
    printf '%s\n' "================================================================================"

    if (( missing_count == 0 )); then
        if declare -f term_green >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
            printf '%s\n' "$(term_green "All required external dependencies are satisfied.")"
        else
            printf 'All required external dependencies are satisfied.\n'
        fi
        return 0
    else
        return 1
    fi
}
