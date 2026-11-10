#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Result Processing & Normalization Library (lib/results.sh)
#
# Aggregates, parses, and normalizes findings generated across all 25 canonical
# network and web reconnaissance modules into a unified, structured JSON data model.
#

set -o nounset

# Include guard to prevent multiple inclusion.
if [[ -n "${_RECKON_LIB_RESULTS_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_RESULTS_LOADED=1

# Global result counters and state.
RESULTS_TOTAL_TARGETS=0
RESULTS_TOTAL_HOSTS_UP=0
RESULTS_TOTAL_OPEN_PORTS=0
RESULTS_TOTAL_SUBDOMAINS=0
RESULTS_TOTAL_ENDPOINTS=0
RESULTS_TOTAL_SECURITY_ISSUES=0
RESULTS_ERROR=""

# Reset and initialize result processing state.
results_init() {
    RESULTS_TOTAL_TARGETS=0
    RESULTS_TOTAL_HOSTS_UP=0
    RESULTS_TOTAL_OPEN_PORTS=0
    RESULTS_TOTAL_SUBDOMAINS=0
    RESULTS_TOTAL_ENDPOINTS=0
    RESULTS_TOTAL_SECURITY_ISSUES=0
    RESULTS_ERROR=""
}

# Safely escape arbitrary strings for inclusion in JSON values.
#
# Arguments:
#   $1 - raw string
#
# Output:
#   Escaped JSON string on stdout (without enclosing quotes)
results_escape_json() {
    local s="${1:-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Parse open TCP/UDP port list artifact into JSON integer array.
#
# Arguments:
#   $1 - path to open_ports.txt
#
# Output:
#   JSON array of integers on stdout: [80, 443]
results_parse_open_ports() {
    local port_file="${1:-}"
    local -a ports=()

    if [[ -f "$port_file" && -s "$port_file" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            if [[ "$line" =~ ^[0-9]+$ ]]; then
                ports+=("$line")
                (( RESULTS_TOTAL_OPEN_PORTS += 1 ))
            fi
        done < "$port_file"
    fi

    if (( ${#ports[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!ports[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${ports[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse services.txt artifact into JSON array of service objects.
#
# Arguments:
#   $1 - path to services.txt
#
# Output:
#   JSON array of objects on stdout
results_parse_services() {
    local svc_file="${1:-}"
    local -a items=()

    if [[ -f "$svc_file" && -s "$svc_file" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            local port_proto status svc ver
            port_proto="${line%%$'\t'*}"
            local rem="${line#*$'\t'}"
            status="${rem%%$'\t'*}"
            rem="${rem#*$'\t'}"
            svc="${rem%%$'\t'*}"
            ver="${rem#*$'\t'}"
            [[ "$ver" == "$svc" ]] && ver=""

            local p="${port_proto%%/*}"
            local proto="${port_proto##*/}"
            [[ -z "$p" ]] && continue

            local esc_svc esc_ver
            esc_svc="$(results_escape_json "$svc")"
            esc_ver="$(results_escape_json "$ver")"

            items+=("{\"port\": $p, \"protocol\": \"$proto\", \"status\": \"$status\", \"service\": \"$esc_svc\", \"version\": \"$esc_ver\"}")
        done < "$svc_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse dns_records.txt artifact into JSON array of record objects.
#
# Arguments:
#   $1 - path to dns_records.txt
#
# Output:
#   JSON array of objects on stdout
results_parse_dns_records() {
    local dns_file="${1:-}"
    local -a items=()

    if [[ -f "$dns_file" && -s "$dns_file" ]]; then
        local line
        while IFS=$'\t' read -r r_type r_name r_data || [[ -n "$r_type" ]]; do
            [[ -z "$r_type" || "$r_type" =~ ^# ]] && continue
            local esc_type esc_name esc_data
            esc_type="$(results_escape_json "$r_type")"
            esc_name="$(results_escape_json "$r_name")"
            esc_data="$(results_escape_json "$r_data")"

            items+=("{\"type\": \"$esc_type\", \"name\": \"$esc_name\", \"data\": \"$esc_data\"}")
        done < "$dns_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse os_detection.txt artifact into JSON array of OS candidate objects.
#
# Arguments:
#   $1 - path to os_detection.txt
results_parse_os() {
    local os_file="${1:-}"
    local -a items=()

    if [[ -f "$os_file" && -s "$os_file" ]]; then
        local line
        while IFS=$'\t' read -r os_fam acc det || [[ -n "$os_fam" ]]; do
            [[ -z "$os_fam" || "$os_fam" =~ ^# ]] && continue
            local esc_fam esc_acc esc_det
            esc_fam="$(results_escape_json "$os_fam")"
            esc_acc="$(results_escape_json "$acc")"
            esc_det="$(results_escape_json "$det")"

            items+=("{\"os_family\": \"$esc_fam\", \"accuracy\": \"$esc_acc\", \"details\": \"$esc_det\"}")
        done < "$os_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse subdomains.txt and resolved_subdomains.txt into JSON array of subdomain objects.
#
# Arguments:
#   $1 - path to subdomains.txt
#   $2 - path to resolved_subdomains.txt
results_parse_subdomains() {
    local sub_file="${1:-}"
    local res_file="${2:-}"
    local -a items=()

    # Prefer resolved mappings if present
    if [[ -f "$res_file" && -s "$res_file" ]]; then
        local sub ip
        while IFS=$'\t' read -r sub ip || [[ -n "$sub" ]]; do
            [[ -z "$sub" ]] && continue
            local esc_sub esc_ip
            esc_sub="$(results_escape_json "$sub")"
            esc_ip="$(results_escape_json "${ip:--}")"
            items+=("{\"subdomain\": \"$esc_sub\", \"ip\": \"$esc_ip\"}")
            (( RESULTS_TOTAL_SUBDOMAINS += 1 ))
        done < "$res_file"
    elif [[ -f "$sub_file" && -s "$sub_file" ]]; then
        local sub
        while IFS= read -r sub || [[ -n "$sub" ]]; do
            sub="${sub#"${sub%%[![:space:]]*}"}"
            sub="${sub%"${sub##*[![:space:]]}"}"
            [[ -z "$sub" ]] && continue
            local esc_sub
            esc_sub="$(results_escape_json "$sub")"
            items+=("{\"subdomain\": \"$esc_sub\", \"ip\": \"-\"}")
            (( RESULTS_TOTAL_SUBDOMAINS += 1 ))
        done < "$sub_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse technologies.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to technologies.txt
results_parse_technologies() {
    local tech_file="${1:-}"
    local -a items=()

    if [[ -f "$tech_file" && -s "$tech_file" ]]; then
        local name ver cats
        while IFS=$'\t' read -r name ver cats || [[ -n "$name" ]]; do
            [[ -z "$name" ]] && continue
            local esc_name esc_ver esc_cats
            esc_name="$(results_escape_json "$name")"
            esc_ver="$(results_escape_json "${ver:--}")"
            esc_cats="$(results_escape_json "${cats:--}")"
            items+=("{\"name\": \"$esc_name\", \"version\": \"$esc_ver\", \"categories\": \"$esc_cats\"}")
        done < "$tech_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse cms_detected.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to cms_detected.txt
results_parse_cms() {
    local cms_file="${1:-}"
    local -a items=()

    if [[ -f "$cms_file" && -s "$cms_file" ]]; then
        local name ver conf
        while IFS=$'\t' read -r name ver conf || [[ -n "$name" ]]; do
            [[ -z "$name" ]] && continue
            local esc_name esc_ver esc_conf
            esc_name="$(results_escape_json "$name")"
            esc_ver="$(results_escape_json "${ver:--}")"
            esc_conf="$(results_escape_json "${conf:-high}")"
            items+=("{\"name\": \"$esc_name\", \"version\": \"$esc_ver\", \"confidence\": \"$esc_conf\"}")
        done < "$cms_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse waf_detected.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to waf_detected.txt
results_parse_waf() {
    local waf_file="${1:-}"
    local -a items=()

    if [[ -f "$waf_file" && -s "$waf_file" ]]; then
        local name vendor
        while IFS=$'\t' read -r name vendor || [[ -n "$name" ]]; do
            [[ -z "$name" ]] && continue
            local esc_name esc_vend
            esc_name="$(results_escape_json "$name")"
            esc_vend="$(results_escape_json "${vendor:--}")"
            items+=("{\"name\": \"$esc_name\", \"vendor\": \"$esc_vend\"}")
        done < "$waf_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse directories.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to directories.txt
results_parse_directories() {
    local dir_file="${1:-}"
    local -a items=()

    if [[ -f "$dir_file" && -s "$dir_file" ]]; then
        local p code len redir
        while IFS=$'\t' read -r p code len redir || [[ -n "$p" ]]; do
            [[ -z "$p" ]] && continue
            local esc_p esc_code esc_len esc_redir
            esc_p="$(results_escape_json "$p")"
            esc_code="${code:-200}"
            esc_len="$(results_escape_json "${len:--}")"
            esc_redir="$(results_escape_json "${redir:--}")"
            items+=("{\"path\": \"$esc_p\", \"status\": $esc_code, \"length\": \"$esc_len\", \"redirect\": \"$esc_redir\"}")
        done < "$dir_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse files.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to files.txt
results_parse_files() {
    local file_file="${1:-}"
    local -a items=()

    if [[ -f "$file_file" && -s "$file_file" ]]; then
        local p code len class
        while IFS=$'\t' read -r p code len class || [[ -n "$p" ]]; do
            [[ -z "$p" ]] && continue
            local esc_p esc_code esc_len esc_class
            esc_p="$(results_escape_json "$p")"
            esc_code="${code:-200}"
            esc_len="$(results_escape_json "${len:--}")"
            esc_class="$(results_escape_json "${class:-General}")"
            items+=("{\"path\": \"$esc_p\", \"status\": $esc_code, \"length\": \"$esc_len\", \"classification\": \"$esc_class\"}")
        done < "$file_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse vhosts.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to vhosts.txt
results_parse_vhosts() {
    local vh_file="${1:-}"
    local -a items=()

    if [[ -f "$vh_file" && -s "$vh_file" ]]; then
        local vh code len redir
        while IFS=$'\t' read -r vh code len redir || [[ -n "$vh" ]]; do
            [[ -z "$vh" ]] && continue
            local esc_vh esc_code esc_len esc_redir
            esc_vh="$(results_escape_json "$vh")"
            esc_code="${code:-200}"
            esc_len="$(results_escape_json "${len:--}")"
            esc_redir="$(results_escape_json "${redir:--}")"
            items+=("{\"vhost\": \"$esc_vh\", \"status\": $esc_code, \"length\": \"$esc_len\", \"redirect\": \"$esc_redir\"}")
        done < "$vh_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse crawled_urls.txt artifact into JSON array of string URLs.
#
# Arguments:
#   $1 - path to crawled_urls.txt
results_parse_crawled_urls() {
    local crawl_file="${1:-}"
    local -a items=()

    if [[ -f "$crawl_file" && -s "$crawl_file" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            local esc_line
            esc_line="$(results_escape_json "$line")"
            items+=("\"$esc_line\"")
            (( RESULTS_TOTAL_ENDPOINTS += 1 ))
        done < "$crawl_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse endpoints.txt artifact into JSON array of endpoint objects.
#
# Arguments:
#   $1 - path to endpoints.txt
results_parse_endpoints() {
    local ep_file="${1:-}"
    local -a items=()

    if [[ -f "$ep_file" && -s "$ep_file" ]]; then
        local ep cat
        while IFS=$'\t' read -r ep cat || [[ -n "$ep" ]]; do
            [[ -z "$ep" ]] && continue
            local esc_ep esc_cat
            esc_ep="$(results_escape_json "$ep")"
            esc_cat="$(results_escape_json "${cat:-GENERAL}")"
            items+=("{\"endpoint\": \"$esc_ep\", \"category\": \"$esc_cat\"}")
            (( RESULTS_TOTAL_ENDPOINTS += 1 ))
        done < "$ep_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse http_analysis.txt artifact into structured JSON object.
#
# Arguments:
#   $1 - path to http_analysis.txt
results_parse_http_analysis() {
    local ha_file="${1:-}"
    local -a headers=()
    local -a disclosures=()
    local -a methods=()
    local cors_json="{\"origin_reflected\": false, \"credentials_allowed\": false, \"risk\": \"NONE\"}"

    if [[ -f "$ha_file" && -s "$ha_file" ]]; then
        local kind col1 col2 col3 col4
        while IFS=$'\t' read -r kind col1 col2 col3 col4 || [[ -n "$kind" ]]; do
            case "$kind" in
                HEADER)
                    local h_name="$col1"
                    local h_stat="$col2"
                    local h_val="${col3:--}"
                    local esc_hn esc_hv
                    esc_hn="$(results_escape_json "$h_name")"
                    esc_hv="$(results_escape_json "$h_val")"
                    headers+=("{\"header\": \"$esc_hn\", \"status\": \"$h_stat\", \"value\": \"$esc_hv\"}")
                    if [[ "$h_stat" == "MISSING" ]]; then
                        (( RESULTS_TOTAL_SECURITY_ISSUES += 1 ))
                    fi
                    ;;
                DISCLOSURE)
                    local d_name="$col1"
                    local d_val="$col2"
                    local esc_dn esc_dv
                    esc_dn="$(results_escape_json "$d_name")"
                    esc_dv="$(results_escape_json "$d_val")"
                    disclosures+=("{\"header\": \"$esc_dn\", \"value\": \"$esc_dv\"}")
                    ;;
                CORS)
                    local acao="$col1"
                    local acac="$col2"
                    local risk="$col3"
                    local status="${col4:--}"
                    local esc_acao esc_status
                    esc_acao="$(results_escape_json "$acao")"
                    esc_status="$(results_escape_json "$status")"
                    local refl="false"
                    local cred="false"
                    [[ -n "$acao" && "$acao" != "-" ]] && refl="true"
                    [[ "$acac" == "true" ]] && cred="true"
                    cors_json="{\"origin_reflected\": $refl, \"credentials_allowed\": $cred, \"risk\": \"$risk\", \"allow_origin\": \"$esc_acao\", \"status\": \"$esc_status\"}"
                    if [[ "$risk" == "HIGH" || "$risk" == "MEDIUM" ]]; then
                        (( RESULTS_TOTAL_SECURITY_ISSUES += 1 ))
                    fi
                    ;;
                METHOD)
                    local m_name="$col1"
                    local m_code="$col2"
                    local m_stat="$col3"
                    methods+=("{\"method\": \"$m_name\", \"status\": \"$m_stat\", \"code\": \"$m_code\"}")
                    ;;
            esac
        done < "$ha_file"
    fi

    # Build JSON object
    local h_arr="[]"
    if (( ${#headers[@]} > 0 )); then
        h_arr="["
        local i
        for i in "${!headers[@]}"; do
            (( i > 0 )) && h_arr+=", "
            h_arr+="${headers[i]}"
        done
        h_arr+="]"
    fi

    local d_arr="[]"
    if (( ${#disclosures[@]} > 0 )); then
        d_arr="["
        local i
        for i in "${!disclosures[@]}"; do
            (( i > 0 )) && d_arr+=", "
            d_arr+="${disclosures[i]}"
        done
        d_arr+="]"
    fi

    local m_arr="[]"
    if (( ${#methods[@]} > 0 )); then
        m_arr="["
        local i
        for i in "${!methods[@]}"; do
            (( i > 0 )) && m_arr+=", "
            m_arr+="${methods[i]}"
        done
        m_arr+="]"
    fi

    printf '{"headers": %s, "disclosures": %s, "cors": %s, "methods": %s}' "$h_arr" "$d_arr" "$cors_json" "$m_arr"
}

# Parse tls_audit.txt and cert_info.txt into JSON object.
#
# Arguments:
#   $1 - path to tls_audit.txt
#   $2 - path to cert_info.txt
results_parse_tls() {
    local audit_file="${1:-}"
    local cert_file="${2:-}"
    local -a protocols=()
    local cert_json="{}"

    if [[ -f "$audit_file" && -s "$audit_file" ]]; then
        local p_name status assess
        while IFS=$'\t' read -r p_name status assess || [[ -n "$p_name" ]]; do
            [[ -z "$p_name" ]] && continue
            local esc_pn esc_assess
            esc_pn="$(results_escape_json "$p_name")"
            esc_assess="$(results_escape_json "${assess:--}")"
            protocols+=("{\"protocol\": \"$esc_pn\", \"status\": \"$status\", \"assessment\": \"$esc_assess\"}")
            if [[ "$status" == "SUPPORTED" && ( "$assess" =~ CRITICAL || "$assess" =~ DEPRECATED ) ]]; then
                (( RESULTS_TOTAL_SECURITY_ISSUES += 1 ))
            fi
        done < "$audit_file"
    fi

    if [[ -f "$cert_file" && -s "$cert_file" ]]; then
        local line
        local c_subj="" c_issuer="" c_from="" c_until="" c_sans="" c_sig="" c_pub=""
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            local k="${line%%:*}"
            local v="${line#*: }"
            case "$k" in
                Subject)             c_subj="$(results_escape_json "$v")" ;;
                Issuer)              c_issuer="$(results_escape_json "$v")" ;;
                "Valid From")        c_from="$(results_escape_json "$v")" ;;
                "Valid Until")       c_until="$(results_escape_json "$v")" ;;
                SANs)                c_sans="$(results_escape_json "$v")" ;;
                "Signature Algorithm") c_sig="$(results_escape_json "$v")" ;;
                "Public Key")        c_pub="$(results_escape_json "$v")" ;;
            esac
        done < "$cert_file"
        cert_json="{\"subject\": \"$c_subj\", \"issuer\": \"$c_issuer\", \"valid_from\": \"$c_from\", \"valid_until\": \"$c_until\", \"sans\": \"$c_sans\", \"signature_algorithm\": \"$c_sig\", \"public_key\": \"$c_pub\"}"
    fi

    local proto_arr="[]"
    if (( ${#protocols[@]} > 0 )); then
        proto_arr="["
        local i
        for i in "${!protocols[@]}"; do
            (( i > 0 )) && proto_arr+=", "
            proto_arr+="${protocols[i]}"
        done
        proto_arr+="]"
    fi

    printf '{"protocols": %s, "certificate": %s}' "$proto_arr" "$cert_json"
}

# Parse resources.txt artifact into JSON array.
#
# Arguments:
#   $1 - path to resources.txt
results_parse_resources() {
    local res_file="${1:-}"
    local -a items=()

    if [[ -f "$res_file" && -s "$res_file" ]]; then
        local p code size details
        while IFS=$'\t' read -r p code size details || [[ -n "$p" ]]; do
            [[ -z "$p" ]] && continue
            local esc_p esc_size esc_det
            esc_p="$(results_escape_json "$p")"
            esc_size="$(results_escape_json "${size:--}")"
            esc_det="$(results_escape_json "${details:--}")"
            local c_val="${code:-200}"
            [[ "$c_val" =~ ^[0-9]+$ ]] || c_val=200
            items+=("{\"path\": \"$esc_p\", \"status\": $c_val, \"size\": \"$esc_size\", \"details\": \"$esc_det\"}")
        done < "$res_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Parse historical_urls.txt artifact into JSON array of string URLs.
#
# Arguments:
#   $1 - path to historical_urls.txt
results_parse_historical_urls() {
    local hist_file="${1:-}"
    local -a items=()

    if [[ -f "$hist_file" && -s "$hist_file" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            local esc_line
            esc_line="$(results_escape_json "$line")"
            items+=("\"$esc_line\"")
        done < "$hist_file"
    fi

    if (( ${#items[@]} == 0 )); then
        printf '[]'
        return 0
    fi

    local out="["
    local idx=0
    for idx in "${!items[@]}"; do
        (( idx > 0 )) && out+=", "
        out+="${items[idx]}"
    done
    out+="]"
    printf '%s' "$out"
}

# Collect and normalize all findings for a single target directory.
#
# Arguments:
#   $1 - target identifier (e.g. enterprise.corp)
#   $2 - target type (e.g. domain, url_https, ipv4)
#   $3 - target output directory containing module subfolders
#
# Output:
#   Complete JSON object for the target on stdout
results_collect_target() {
    local target="${1:-}"
    local t_type="${2:-}"
    local target_dir="${3:-}"

    if [[ ! -d "$target_dir" ]]; then
        printf '{}'
        return 0
    fi

    (( RESULTS_TOTAL_TARGETS += 1 ))

    local esc_target esc_ttype
    esc_target="$(results_escape_json "$target")"
    esc_ttype="$(results_escape_json "$t_type")"

    # Host status
    local host_status="UNKNOWN"
    if [[ -f "$target_dir/ping/output.txt" ]]; then
        if grep -q "Host is UP" "$target_dir/ping/output.txt"; then
            host_status="UP"
            (( RESULTS_TOTAL_HOSTS_UP += 1 ))
        elif grep -q "Host is DOWN" "$target_dir/ping/output.txt"; then
            host_status="DOWN"
        fi
    else
        host_status="UP"
        (( RESULTS_TOTAL_HOSTS_UP += 1 ))
    fi

    # Parsed modules
    local dns_json ports_json svcs_json os_json subs_json tech_json cms_json waf_json
    local dirs_json files_json vhosts_json crawl_json ep_json ha_json tls_json res_json hist_json

    dns_json="$(results_parse_dns_records "$target_dir/dns/dns_records.txt")"
    ports_json="$(results_parse_open_ports "$target_dir/port/open_ports.txt")"
    svcs_json="$(results_parse_services "$target_dir/service/services.txt")"
    os_json="$(results_parse_os "$target_dir/os/os_detection.txt")"
    subs_json="$(results_parse_subdomains "$target_dir/subdomain/subdomains.txt" "$target_dir/subdomain/resolved_subdomains.txt")"
    tech_json="$(results_parse_technologies "$target_dir/technology/technologies.txt")"
    cms_json="$(results_parse_cms "$target_dir/cms/cms_detected.txt")"
    waf_json="$(results_parse_waf "$target_dir/waf/waf_detected.txt")"
    dirs_json="$(results_parse_directories "$target_dir/directory/directories.txt")"
    files_json="$(results_parse_files "$target_dir/file/files.txt")"
    vhosts_json="$(results_parse_vhosts "$target_dir/vhost/vhosts.txt")"
    crawl_json="$(results_parse_crawled_urls "$target_dir/crawl/crawled_urls.txt")"
    ep_json="$(results_parse_endpoints "$target_dir/endpoint/endpoints.txt")"
    ha_json="$(results_parse_http_analysis "$target_dir/http-analysis/http_analysis.txt")"
    tls_json="$(results_parse_tls "$target_dir/tls/tls_audit.txt" "$target_dir/tls/cert_info.txt")"
    res_json="$(results_parse_resources "$target_dir/resources/resources.txt")"
    hist_json="$(results_parse_historical_urls "$target_dir/historical-urls/historical_urls.txt")"

    cat <<TARGET_JSON
{
  "target": "$esc_target",
  "target_type": "$esc_ttype",
  "host_status": "$host_status",
  "dns": $dns_json,
  "ports": $ports_json,
  "services": $svcs_json,
  "os": $os_json,
  "subdomains": $subs_json,
  "technologies": $tech_json,
  "cms": $cms_json,
  "waf": $waf_json,
  "directories": $dirs_json,
  "files": $files_json,
  "vhosts": $vhosts_json,
  "crawled_urls": $crawl_json,
  "endpoints": $ep_json,
  "http_analysis": $ha_json,
  "tls": $tls_json,
  "resources": $res_json,
  "historical_urls": $hist_json
}
TARGET_JSON
}

# Internal helper to accumulate metrics for a single target directory in caller shell.
_results_accumulate_target_metrics() {
    local target_dir="${1:-}"
    [[ ! -d "$target_dir" ]] && return 0

    # Host status
    if [[ -f "$target_dir/ping/output.txt" ]]; then
        if grep -q "Host is UP" "$target_dir/ping/output.txt"; then
            (( RESULTS_TOTAL_HOSTS_UP += 1 ))
        fi
    else
        (( RESULTS_TOTAL_HOSTS_UP += 1 ))
    fi

    # Ports
    if [[ -f "$target_dir/port/open_ports.txt" ]]; then
        local cnt
        cnt="$(grep -c -E '^[0-9]+$' "$target_dir/port/open_ports.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_OPEN_PORTS += cnt ))
    fi

    # Subdomains
    if [[ -f "$target_dir/subdomain/resolved_subdomains.txt" && -s "$target_dir/subdomain/resolved_subdomains.txt" ]]; then
        local cnt
        cnt="$(grep -c -v -E '^[[:space:]]*$' "$target_dir/subdomain/resolved_subdomains.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_SUBDOMAINS += cnt ))
    elif [[ -f "$target_dir/subdomain/subdomains.txt" && -s "$target_dir/subdomain/subdomains.txt" ]]; then
        local cnt
        cnt="$(grep -c -v -E '^[[:space:]]*$' "$target_dir/subdomain/subdomains.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_SUBDOMAINS += cnt ))
    fi

    # Web Endpoints (crawled + endpoints)
    if [[ -f "$target_dir/crawl/crawled_urls.txt" && -s "$target_dir/crawl/crawled_urls.txt" ]]; then
        local cnt
        cnt="$(grep -c -v -E '^[[:space:]]*$' "$target_dir/crawl/crawled_urls.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_ENDPOINTS += cnt ))
    fi
    if [[ -f "$target_dir/endpoint/endpoints.txt" && -s "$target_dir/endpoint/endpoints.txt" ]]; then
        local cnt
        cnt="$(grep -c -v -E '^[[:space:]]*$' "$target_dir/endpoint/endpoints.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_ENDPOINTS += cnt ))
    fi

    # Security Issues
    if [[ -f "$target_dir/http-analysis/http_analysis.txt" ]]; then
        local cnt
        cnt="$(grep -c -E '^HEADER[[:space:]]+.*[[:space:]]+MISSING' "$target_dir/http-analysis/http_analysis.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_SECURITY_ISSUES += cnt ))
        cnt="$(grep -c -E '^CORS[[:space:]]+.*[[:space:]]+(HIGH|MEDIUM)' "$target_dir/http-analysis/http_analysis.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_SECURITY_ISSUES += cnt ))
    fi
    if [[ -f "$target_dir/tls/tls_audit.txt" ]]; then
        local cnt
        cnt="$(grep -c -E '^.*\bSUPPORTED\b.*(CRITICAL|DEPRECATED)' "$target_dir/tls/tls_audit.txt" 2>/dev/null || true)"
        [[ "$cnt" =~ ^[0-9]+$ ]] && (( RESULTS_TOTAL_SECURITY_ISSUES += cnt ))
    fi
}

# Aggregate all target findings under output directory and generate unified results.json.
#
# Arguments:
#   $1 - root output directory of scan run
#   $2 - optional destination file path (default: $output_dir/results.json)
#
# Returns:
#   0 on success, 1 on error
results_generate_json() {
    local output_dir="${1:-}"
    local out_json="${2:-}"

    if [[ -z "$output_dir" || ! -d "$output_dir" ]]; then
        RESULTS_ERROR="Output directory does not exist or was not specified: $output_dir"
        printf 'Error: %s\n' "$RESULTS_ERROR" >&2
        return 1
    fi

    [[ -z "$out_json" ]] && out_json="${output_dir}/results.json"

    results_init

    local -a target_objs=()

    # Discover all target directories (subdirectories containing module folders)
    local t_dir
    while IFS= read -r t_dir || [[ -n "$t_dir" ]]; do
        [[ -z "$t_dir" || ! -d "$t_dir" ]] && continue
        local t_name
        t_name="$(basename "$t_dir")"

        # Determine target type
        local t_type="domain"
        if [[ "$t_name" =~ ^http_ ]]; then
            t_type="url_http"
        elif [[ "$t_name" =~ ^https_ ]]; then
            t_type="url_https"
        elif [[ "$t_name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            t_type="ipv4"
        fi

        local t_json
        t_json="$(results_collect_target "$t_name" "$t_type" "$t_dir")"
        if [[ -n "$t_json" && "$t_json" != "{}" ]]; then
            target_objs+=("$t_json")
            _results_accumulate_target_metrics "$t_dir"
        fi
    done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d | sort)

    RESULTS_TOTAL_TARGETS="${#target_objs[@]}"

    local targets_array="[]"
    if (( ${#target_objs[@]} > 0 )); then
        targets_array="["
        local i
        for i in "${!target_objs[@]}"; do
            (( i > 0 )) && targets_array+=", "
            targets_array+="${target_objs[i]}"
        done
        targets_array+="]"
    fi

    local timestamp
    timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")"

    local raw_json_tmp="${out_json}.tmp"
    cat <<EOF > "$raw_json_tmp"
{
  "schema_version": "1.0",
  "scan_metadata": {
    "app_name": "RECKON",
    "app_version": "${APP_VERSION:-1.0.0}",
    "timestamp": "$timestamp",
    "output_directory": "$output_dir",
    "targets_count": $RESULTS_TOTAL_TARGETS
  },
  "summary": {
    "total_targets": $RESULTS_TOTAL_TARGETS,
    "total_hosts_up": $RESULTS_TOTAL_HOSTS_UP,
    "total_open_ports": $RESULTS_TOTAL_OPEN_PORTS,
    "total_subdomains": $RESULTS_TOTAL_SUBDOMAINS,
    "total_web_endpoints": $RESULTS_TOTAL_ENDPOINTS,
    "total_security_issues": $RESULTS_TOTAL_SECURITY_ISSUES,
    "modules_completed": ${ENGINE_COMPLETED_TASKS:-0},
    "modules_not_applicable": ${ENGINE_NOT_APPLICABLE_TASKS:-0},
    "modules_failed": $(( ${ENGINE_FAILED_TASKS:-0} + ${ENGINE_TIMEOUT_TASKS:-0} )),
    "modules_skipped": ${ENGINE_SKIPPED_TASKS:-0}
  },
  "targets": $targets_array
}
EOF

    # Pretty-format JSON if jq is available
    if command -v jq >/dev/null 2>&1; then
        jq . "$raw_json_tmp" > "$out_json" 2>/dev/null || mv -f "$raw_json_tmp" "$out_json"
        rm -f "$raw_json_tmp"
    else
        mv -f "$raw_json_tmp" "$out_json"
    fi

    chmod 0640 "$out_json" 2>/dev/null || true
    return 0
}
