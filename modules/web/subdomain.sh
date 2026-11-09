#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Subdomain Enumeration Module (modules/web/subdomain.sh)
#
# Performs passive and active subdomain enumeration and DNS validation for
# domain targets. Discovers fully-qualified domain names (FQDNs) and validates
# active DNS resolution.
#
# Supported target types:
#   domain
#
# Primary External Tools:
#   - subfinder (passive multi-source subdomain discovery)
#   - dnsx (high-speed active DNS validation and IP resolution)
#
# Fallback Engines:
#   - Certificate Transparency logs (crt.sh via curl)
#   - Native DNS interrogation (dig / host)
#

set -o nounset

SUBDOMAIN_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$SUBDOMAIN_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
SUBDOMAIN_SUBFINDER_BIN="${RECKON_MOCK_SUBFINDER_BIN:-subfinder}"
SUBDOMAIN_DNSX_BIN="${RECKON_MOCK_DNSX_BIN:-dnsx}"
SUBDOMAIN_DIG_BIN="${RECKON_MOCK_DIG_BIN:-dig}"
SUBDOMAIN_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Clean list of common subdomain prefixes for fallback active dictionary probing.
readonly _SUBDOMAIN_DICTIONARY=(
    "www"
    "mail"
    "remote"
    "blog"
    "webmail"
    "server"
    "ns1"
    "ns2"
    "smtp"
    "secure"
    "vpn"
    "api"
    "dev"
    "staging"
    "portal"
    "admin"
    "app"
    "auth"
    "login"
    "test"
    "beta"
    "internal"
    "gateway"
    "cdn"
    "cloud"
)

# Normalize and sanitize a discovered candidate subdomain string.
# Ensures the candidate is lowercase, non-empty, and ends with the target root domain.
_subdomain_clean_candidate() {
    local candidate="$1"
    local root_domain="$2"

    candidate="${candidate#"${candidate%%[![:space:]]*}"}"
    candidate="${candidate%"${candidate##*[![:space:]]}"}"
    candidate="${candidate//$'\r'/}"
    candidate="$(printf '%s' "$candidate" | tr '[:upper:]' '[:lower:]')"

    # Strip wildcards if present (e.g. *.example.com -> example.com)
    candidate="${candidate#\*.}"

    # Verify that candidate ends with .root_domain or matches root_domain
    if [[ "$candidate" == "$root_domain" || "$candidate" == *".$root_domain" ]]; then
        # Validate that candidate is a valid RFC domain structure
        if [[ "$candidate" =~ ^[a-z0-9]([a-z0-9\._-]*[a-z0-9])?$ ]]; then
            printf '%s\n' "$candidate"
        fi
    fi
}

# Resolve an IP address for a subdomain using dig or host.
_subdomain_dig_resolve() {
    local host_name="$1"
    local resolved_ip=""

    if web_mod_has_tool "$SUBDOMAIN_DIG_BIN"; then
        resolved_ip="$("$SUBDOMAIN_DIG_BIN" +short +time=3 +tries=2 A "$host_name" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)"
    elif web_mod_has_tool "host"; then
        resolved_ip="$(host -t A "$host_name" 2>/dev/null | grep "has address" | head -n 1 | awk '{print $NF}' || true)"
    fi

    printf '%s\n' "$resolved_ip"
}

# Main module runner function.
module_subdomain_run() {
    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    # Subdomain discovery is strictly compatible with 'domain' targets.
    local init_rc=0
    web_mod_init "$target" "$t_type" "$task_dir" domain || init_rc=$?
    if (( init_rc == 2 )); then
        # Target was not 'domain' (e.g. ipv4 or url) - gracefully skip.
        return 0
    elif (( init_rc != 0 )); then
        return 1
    fi

    web_mod_write_header "subdomain" "Subdomain Enumeration"

    local subdomains_file="${task_dir}/subdomains.txt"
    local resolved_file="${task_dir}/resolved_subdomains.txt"
    : > "$subdomains_file"
    : > "$resolved_file"

    local domain="$WEB_URL_HOST"
    local has_subfinder=false
    local has_dnsx=false

    web_mod_has_tool "$SUBDOMAIN_SUBFINDER_BIN" && has_subfinder=true
    web_mod_has_tool "$SUBDOMAIN_DNSX_BIN" && has_dnsx=true

    local discovery_engine="crt.sh + dictionary fallback"
    [[ "$has_subfinder" == true ]] && discovery_engine="subfinder"

    local resolver_engine="dig / host fallback"
    [[ "$has_dnsx" == true ]] && resolver_engine="dnsx"

    web_mod_write_section "Enumeration Configuration"
    web_mod_write_kv "Target Domain" "$domain"
    web_mod_write_kv "Discovery Engine" "$discovery_engine"
    web_mod_write_kv "Resolver Engine" "$resolver_engine"

    # Temporary collector file for raw candidate subdomains.
    local raw_candidates_file="${task_dir}/.candidates.tmp"
    : > "$raw_candidates_file"

    # 1. Primary Discovery Phase: Subfinder
    if [[ "$has_subfinder" == true ]]; then
        "$SUBDOMAIN_SUBFINDER_BIN" -d "$domain" -silent -nc >> "$raw_candidates_file" 2>/dev/null || true
    fi

    # 2. Fallback / Complementary Discovery Phase: Certificate Transparency & Dictionary
    if [[ "$has_subfinder" == false ]] || [[ ! -s "$raw_candidates_file" ]]; then
        # Check Certificate Transparency logs if curl is available
        if web_mod_has_tool "$SUBDOMAIN_CURL_BIN"; then
            local crt_output
            crt_output="$("$SUBDOMAIN_CURL_BIN" -s -k --max-time 6 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null || true)"
            if [[ -n "$crt_output" && "$crt_output" == *"name_value"* ]]; then
                printf '%s\n' "$crt_output" | grep -o '"name_value": *"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' >> "$raw_candidates_file" 2>/dev/null || true
            fi
        fi

        # Check standard dictionary words via DNS resolution
        local prefix cand_name
        for prefix in "${_SUBDOMAIN_DICTIONARY[@]}"; do
            cand_name="${prefix}.${domain}"
            local cand_ip
            cand_ip="$(_subdomain_dig_resolve "$cand_name")"
            if [[ -n "$cand_ip" ]]; then
                printf '%s\n' "$cand_name" >> "$raw_candidates_file"
            fi
        done
    fi

    # Deduplicate and sanitize discovered candidates.
    local -a unique_subdomains=()
    if [[ -s "$raw_candidates_file" ]]; then
        local line cleaned
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            cleaned="$(_subdomain_clean_candidate "$line" "$domain")"
            if [[ -n "$cleaned" ]]; then
                # Avoid duplicate insertion
                local exists=false
                local item
                for item in "${unique_subdomains[@]}"; do
                    if [[ "$item" == "$cleaned" ]]; then
                        exists=true
                        break
                    fi
                done
                if [[ "$exists" == false ]]; then
                    unique_subdomains+=("$cleaned")
                fi
            fi
        done < "$raw_candidates_file"
    fi
    rm -f "$raw_candidates_file"

    # 3. Active DNS Validation Phase.
    local -a resolved_entries=()
    if (( ${#unique_subdomains[@]} > 0 )); then
        # Sort and write subdomains list
        local -a sorted_subs=()
        mapfile -t sorted_subs < <(printf '%s\n' "${unique_subdomains[@]}" | sort -u)

        local sub
        for sub in "${sorted_subs[@]}"; do
            printf '%s\n' "$sub" >> "$subdomains_file"
        done

        if [[ "$has_dnsx" == true ]]; then
            # Run dnsx on the sorted subdomains list
            local dnsx_out="${task_dir}/.dnsx.tmp"
            "$SUBDOMAIN_DNSX_BIN" -l "$subdomains_file" -silent -a -resp -nc > "$dnsx_out" 2>/dev/null || true
            if [[ -f "$dnsx_out" ]]; then
                local d_line s_host s_ip
                while IFS= read -r d_line || [[ -n "$d_line" ]]; do
                    [[ -z "$d_line" ]] && continue
                    # dnsx output format: <subdomain> [<ip>]
                    s_host="${d_line%% *}"
                    s_ip=""
                    if [[ "$d_line" =~ \[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\] ]]; then
                        s_ip="${BASH_REMATCH[1]}"
                    elif [[ "$d_line" =~ [[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                        s_ip="${BASH_REMATCH[1]}"
                    fi
                    if [[ -n "$s_ip" ]]; then
                        printf '%s\t%s\n' "$s_host" "$s_ip" >> "$resolved_file"
                        resolved_entries+=("$s_host [$s_ip]")
                    else
                        printf '%s\t-\n' "$s_host" >> "$resolved_file"
                        resolved_entries+=("$s_host")
                    fi
                done < "$dnsx_out"
                rm -f "$dnsx_out"
            fi
        else
            # Dig fallback resolution
            for sub in "${sorted_subs[@]}"; do
                local ip_res
                ip_res="$(_subdomain_dig_resolve "$sub")"
                if [[ -n "$ip_res" ]]; then
                    printf '%s\t%s\n' "$sub" "$ip_res" >> "$resolved_file"
                    resolved_entries+=("$sub [$ip_res]")
                fi
            done
        fi
    fi

    # Write report sections.
    web_mod_write_section "Discovered Subdomains"
    web_mod_write_kv "Total Discovered" "${#unique_subdomains[@]}"
    web_mod_write_kv "Total Resolved" "${#resolved_entries[@]}"

    if (( ${#unique_subdomains[@]} > 0 )); then
        web_mod_write_raw "  Discovered Subdomains    :"
        local entry
        if (( ${#resolved_entries[@]} > 0 )); then
            for entry in "${resolved_entries[@]}"; do
                web_mod_write_raw "    - $entry"
            done
        else
            for entry in "${unique_subdomains[@]}"; do
                web_mod_write_raw "    - $entry"
            done
        fi
        web_mod_write_footer "COMPLETED" "Discovered ${#unique_subdomains[@]} subdomain(s) (${#resolved_entries[@]} resolved)."
    else
        web_mod_write_kv "Status" "No subdomains identified for target domain."
        web_mod_write_footer "COMPLETED" "No subdomains discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_subdomain_run "$@"
fi
