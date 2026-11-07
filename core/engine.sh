#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Core scan planning and execution engine
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_CORE_ENGINE_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_CORE_ENGINE_LOADED=1

# Last error recorded by execution engine functions.
ENGINE_ERROR=""

# Canonical sequence of network reconnaissance modules (11 modules).
readonly _ENGINE_NETWORK_MODULES=(
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
)

# Canonical sequence of web reconnaissance modules (14 modules).
readonly _ENGINE_WEB_MODULES=(
    "http-probe"
    "subdomain"
    "technology"
    "cms"
    "waf"
    "directory"
    "file"
    "vhost"
    "crawl"
    "endpoint"
    "http-analysis"
    "tls"
    "resources"
    "historical-urls"
)

# Combined canonical execution order of all 25 modules.
readonly _ENGINE_ALL_MODULES=(
    "${_ENGINE_NETWORK_MODULES[@]}"
    "${_ENGINE_WEB_MODULES[@]}"
)

# Engine lifecycle counters.
ENGINE_TOTAL_TASKS=0
ENGINE_COMPLETED_TASKS=0
ENGINE_FAILED_TASKS=0
ENGINE_SKIPPED_TASKS=0
ENGINE_TIMEOUT_TASKS=0

# Reset the execution engine state.
engine_init() {
    ENGINE_TOTAL_TASKS=0
    ENGINE_COMPLETED_TASKS=0
    ENGINE_FAILED_TASKS=0
    ENGINE_SKIPPED_TASKS=0
    ENGINE_TIMEOUT_TASKS=0
    ENGINE_ERROR=""
}

# Output the canonical sequence of all 25 reconnaissance modules.
engine_get_all_modules() {
    local mod
    for mod in "${_ENGINE_ALL_MODULES[@]}"; do
        printf '%s\n' "$mod"
    done
}

# Output the canonical sequence of the 11 network modules.
engine_get_network_modules() {
    local mod
    for mod in "${_ENGINE_NETWORK_MODULES[@]}"; do
        printf '%s\n' "$mod"
    done
}

# Output the canonical sequence of the 14 web modules.
engine_get_web_modules() {
    local mod
    for mod in "${_ENGINE_WEB_MODULES[@]}"; do
        printf '%s\n' "$mod"
    done
}

# Check if a module identifier is valid.
#
# Arguments:
#   $1 - module identifier
#
# Returns:
#   0 if valid, 1 otherwise
engine_is_valid_module() {
    local mod="${1:-}"
    local m

    [[ -z "$mod" ]] && return 1

    for m in "${_ENGINE_ALL_MODULES[@]}"; do
        if [[ "$m" == "$mod" ]]; then
            return 0
        fi
    done

    return 1
}

# Return the operational category (network or web) for a module.
#
# Arguments:
#   $1 - module identifier
#
# Outputs:
#   "network" or "web"
#
# Returns:
#   0 on success, 1 on invalid module
engine_get_module_category() {
    local mod="${1:-}"
    local m

    ENGINE_ERROR=""

    for m in "${_ENGINE_NETWORK_MODULES[@]}"; do
        if [[ "$m" == "$mod" ]]; then
            printf '%s\n' "network"
            return 0
        fi
    done

    for m in "${_ENGINE_WEB_MODULES[@]}"; do
        if [[ "$m" == "$mod" ]]; then
            printf '%s\n' "web"
            return 0
        fi
    done

    ENGINE_ERROR="Invalid module identifier: $mod"
    return 1
}

# Return the friendly display name for a reconnaissance module.
#
# Arguments:
#   $1 - module identifier
#
# Outputs:
#   Human-readable module title
engine_get_module_name() {
    local mod="${1:-}"

    case "$mod" in
        host)            printf '%s\n' "Host Discovery" ;;
        dns)             printf '%s\n' "DNS Reconnaissance" ;;
        port)            printf '%s\n' "Port Scanning" ;;
        service)         printf '%s\n' "Service Detection" ;;
        os)              printf '%s\n' "OS Detection" ;;
        ssh)             printf '%s\n' "SSH Enumeration" ;;
        ftp)             printf '%s\n' "FTP Enumeration" ;;
        http)            printf '%s\n' "HTTP Enumeration" ;;
        https)           printf '%s\n' "HTTPS Enumeration" ;;
        smb)             printf '%s\n' "SMB Enumeration" ;;
        telnet)          printf '%s\n' "Telnet Enumeration" ;;
        http-probe)      printf '%s\n' "HTTP Probing" ;;
        subdomain)       printf '%s\n' "Subdomain Enumeration" ;;
        technology)      printf '%s\n' "Technology Fingerprinting" ;;
        cms)             printf '%s\n' "CMS Detection" ;;
        waf)             printf '%s\n' "WAF Detection" ;;
        directory)       printf '%s\n' "Directory Enumeration" ;;
        file)            printf '%s\n' "File Enumeration" ;;
        vhost)           printf '%s\n' "Virtual Host Enumeration" ;;
        crawl)           printf '%s\n' "Web Crawling" ;;
        endpoint)        printf '%s\n' "Endpoint Discovery" ;;
        http-analysis)   printf '%s\n' "HTTP Response Analysis" ;;
        tls)             printf '%s\n' "SSL/TLS Analysis" ;;
        resources)       printf '%s\n' "Web Resource Discovery" ;;
        historical-urls) printf '%s\n' "Historical URL Discovery" ;;
        *)               printf '%s\n' "$mod" ;;
    esac
}

# Return a functional summary for a reconnaissance module.
#
# Arguments:
#   $1 - module identifier
#
# Outputs:
#   Module functional description
engine_get_module_desc() {
    local mod="${1:-}"

    case "$mod" in
        host)            printf '%s\n' "ICMP reachability and network host availability checks" ;;
        dns)             printf '%s\n' "DNS record resolution, reverse lookups, and zone discovery" ;;
        port)            printf '%s\n' "TCP port discovery and state evaluation" ;;
        service)         printf '%s\n' "Service identification and version interrogation" ;;
        os)              printf '%s\n' "Operating system fingerprinting and heuristics" ;;
        ssh)             printf '%s\n' "SSH service banner, host keys, and cipher configuration auditing" ;;
        ftp)             printf '%s\n' "FTP service banner, capabilities, and anonymous access checks" ;;
        http)            printf '%s\n' "HTTP service detection, response inspection, and methods checking" ;;
        https)           printf '%s\n' "HTTPS service detection, certificate retrieval, and TLS inspection" ;;
        smb)             printf '%s\n' "SMB protocol version, domain information, and share enumeration" ;;
        telnet)          printf '%s\n' "Telnet service detection and banner collection" ;;
        http-probe)      printf '%s\n' "HTTP/HTTPS service discovery, title extraction, and probing" ;;
        subdomain)       printf '%s\n' "Passive subdomain discovery and DNS resolution" ;;
        technology)      printf '%s\n' "Web technology stack, frameworks, and server fingerprinting" ;;
        cms)             printf '%s\n' "Content Management System (CMS) identification" ;;
        waf)             printf '%s\n' "Web Application Firewall (WAF) detection and fingerprinting" ;;
        directory)       printf '%s\n' "Directory discovery through dictionary-based web fuzzing" ;;
        file)            printf '%s\n' "Accessible file and sensitive extension discovery" ;;
        vhost)           printf '%s\n' "Virtual host enumeration via HTTP Host header testing" ;;
        crawl)           printf '%s\n' "Active web spidering and recursive page link extraction" ;;
        endpoint)        printf '%s\n' "Web endpoint, parameter, and JavaScript URL discovery" ;;
        http-analysis)   printf '%s\n' "HTTP response header inspection and security analysis" ;;
        tls)             printf '%s\n' "SSL/TLS protocol version, cipher suite, and certificate analysis" ;;
        resources)       printf '%s\n' "Inspection of robots.txt, sitemap.xml, security.txt, and favicon" ;;
        historical-urls) printf '%s\n' "Passive historical URL extraction from public web archives" ;;
        *)               printf '%s\n' "Reconnaissance module" ;;
    esac
}

# Output the list of compatible target types for a module (one per line).
#
# Valid target types: ipv4, ipv4_cidr, ipv4_range, hostname, domain, url_http, url_https
#
# Arguments:
#   $1 - module identifier
#
# Returns:
#   0 on success, 1 on invalid module
engine_get_module_target_types() {
    local mod="${1:-}"

    ENGINE_ERROR=""

    case "$mod" in
        host)
            printf '%s\n' "ipv4" "ipv4_cidr" "ipv4_range" "hostname" "domain"
            ;;
        dns)
            printf '%s\n' "hostname" "domain"
            ;;
        port|service|os)
            printf '%s\n' "ipv4" "hostname" "domain"
            ;;
        ssh|ftp|smb|telnet)
            printf '%s\n' "ipv4" "hostname" "domain"
            ;;
        http|https)
            printf '%s\n' "ipv4" "hostname" "domain" "url_http" "url_https"
            ;;
        http-probe)
            printf '%s\n' "ipv4" "hostname" "domain" "url_http" "url_https"
            ;;
        subdomain)
            printf '%s\n' "domain"
            ;;
        crawl|endpoint|directory|file|vhost|resources)
            printf '%s\n' "url_http" "url_https" "hostname" "domain"
            ;;
        technology|cms|waf|http-analysis)
            printf '%s\n' "url_http" "url_https" "hostname" "domain" "ipv4"
            ;;
        tls)
            printf '%s\n' "url_https" "hostname" "domain" "ipv4"
            ;;
        historical-urls)
            printf '%s\n' "domain" "hostname"
            ;;
        *)
            ENGINE_ERROR="Invalid module identifier: $mod"
            return 1
            ;;
    esac

    return 0
}

# Check if a target type is compatible with a given module.
#
# Arguments:
#   $1 - module identifier
#   $2 - target type (ipv4, ipv4_cidr, ipv4_range, hostname, domain, url_http, url_https)
#
# Returns:
#   0 if compatible, 1 otherwise
engine_is_module_compatible() {
    local mod="${1:-}"
    local target_type="${2:-}"
    local t

    [[ -z "$mod" || -z "$target_type" ]] && return 1

    while IFS= read -r t; do
        if [[ "$t" == "$target_type" ]]; then
            return 0
        fi
    done < <(engine_get_module_target_types "$mod" 2>/dev/null || true)

    return 1
}
