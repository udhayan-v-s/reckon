#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Multi-Format Reporting Engine (lib/reporting.sh)
#
# Transforms normalized scan findings and schema results into comprehensive,
# human-readable Markdown, Plain Text, and HTML assessment reports.
#

set -o nounset

# Include guard to prevent multiple inclusion.
if [[ -n "${_RECKON_LIB_REPORTING_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_REPORTING_LOADED=1

# Load results library if not already loaded.
if [[ -z "${_RECKON_LIB_RESULTS_LOADED:-}" ]]; then
    _REPORING_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    if [[ -f "$_REPORING_LIB_DIR/results.sh" ]]; then
        # shellcheck source=lib/results.sh
        source "$_REPORING_LIB_DIR/results.sh"
    fi
fi

# Reporting state and tracking.
REPORTING_ERROR=""
REPORTING_GENERATED_FILES=()

# Reset and initialize reporting state.
reporting_init() {
    REPORTING_ERROR=""
    REPORTING_GENERATED_FILES=()
}

# Ensure results.json exists in target output directory, generating it if necessary.
#
# Arguments:
#   $1 - output directory
#
# Returns:
#   0 on success, 1 on failure
_reporting_ensure_results_json() {
    local output_dir="${1:-}"
    local results_file="${output_dir}/results.json"

    if [[ -f "$results_file" && -s "$results_file" ]]; then
        return 0
    fi

    if declare -f results_generate_json >/dev/null 2>&1; then
        if results_generate_json "$output_dir" "$results_file"; then
            return 0
        fi
    fi

    REPORTING_ERROR="results.json missing in $output_dir and could not be generated"
    return 1
}

# Export Markdown format assessment report (report.md).
#
# Arguments:
#   $1 - root output directory of scan run
#   $2 - optional destination file path (default: $output_dir/report.md)
#
# Returns:
#   0 on success, 1 on error
# shellcheck disable=SC2016
reporting_export_markdown() {
    local output_dir="${1:-}"
    local out_file="${2:-}"

    if [[ -z "$output_dir" || ! -d "$output_dir" ]]; then
        REPORTING_ERROR="Output directory does not exist or was not specified: $output_dir"
        printf 'Error: %s\n' "$REPORTING_ERROR" >&2
        return 1
    fi

    [[ -z "$out_file" ]] && out_file="${output_dir}/report.md"

    if ! _reporting_ensure_results_json "$output_dir"; then
        return 1
    fi

    local results_file="${output_dir}/results.json"
    local raw_md_tmp="${out_file}.tmp"

    # Extract metadata using jq
    local app_name app_version scan_ts total_targets
    local hosts_up open_ports subdomains endpoints security_issues

    app_name="$(jq -r '.scan_metadata.app_name // "RECKON"' "$results_file" 2>/dev/null)"
    app_version="$(jq -r '.scan_metadata.app_version // "1.0.0"' "$results_file" 2>/dev/null)"
    scan_ts="$(jq -r '.scan_metadata.timestamp // "Unknown"' "$results_file" 2>/dev/null)"
    total_targets="$(jq -r '.summary.total_targets // 0' "$results_file" 2>/dev/null)"
    hosts_up="$(jq -r '.summary.total_hosts_up // 0' "$results_file" 2>/dev/null)"
    open_ports="$(jq -r '.summary.total_open_ports // 0' "$results_file" 2>/dev/null)"
    subdomains="$(jq -r '.summary.total_subdomains // 0' "$results_file" 2>/dev/null)"
    endpoints="$(jq -r '.summary.total_web_endpoints // 0' "$results_file" 2>/dev/null)"
    security_issues="$(jq -r '.summary.total_security_issues // 0' "$results_file" 2>/dev/null)"

    {
        printf '# %s Reconnaissance Assessment Report\n\n' "$app_name"
        printf '**Generated:** %s  \n' "$scan_ts"
        printf '**Application:** %s v%s  \n' "$app_name" "$app_version"
        printf '**Output Directory:** `%s`  \n' "$output_dir"
        printf '**Total Targets Assessed:** %s  \n\n' "$total_targets"
        printf -- '---\n\n'

        # Executive Summary
        printf '## Executive Summary\n\n'
        printf '| Metric | Count |\n'
        printf '| :--- | :--- |\n'
        printf '| **Total Targets** | %s |\n' "$total_targets"
        printf '| **Hosts Up** | %s |\n' "$hosts_up"
        printf '| **Open Ports** | %s |\n' "$open_ports"
        printf '| **Subdomains Discovered** | %s |\n' "$subdomains"
        printf '| **Web Endpoints Identified** | %s |\n' "$endpoints"
        printf '| **Security Issues / Observations** | %s |\n\n' "$security_issues"
        printf -- '---\n\n'

        # Target Findings Breakdown
        local targets_len
        targets_len="$(jq -r '.targets | length' "$results_file" 2>/dev/null || echo 0)"

        local t_idx=0
        while (( t_idx < targets_len )); do
            local t_name t_type h_stat
            t_name="$(jq -r ".targets[$t_idx].target // \"-\"" "$results_file")"
            t_type="$(jq -r ".targets[$t_idx].target_type // \"-\"" "$results_file")"
            h_stat="$(jq -r ".targets[$t_idx].host_status // \"UNKNOWN\"" "$results_file")"

            printf '## Target: %s\n\n' "$t_name"
            printf -- '- **Target Type:** `%s`\n' "$t_type"
            printf -- '- **Host Status:** **%s**\n\n' "$h_stat"

            # DNS Records
            local dns_count
            dns_count="$(jq -r ".targets[$t_idx].dns | length" "$results_file" 2>/dev/null || echo 0)"
            if (( dns_count > 0 )); then
                printf '### DNS Records\n\n'
                printf '| Type | Record Name | Record Value |\n'
                printf '| :--- | :--- | :--- |\n'
                local d_i=0
                while (( d_i < dns_count )); do
                    local dtype dname dval
                    dtype="$(jq -r ".targets[$t_idx].dns[$d_i].type // \"-\"" "$results_file")"
                    dname="$(jq -r ".targets[$t_idx].dns[$d_i].name // \"-\"" "$results_file")"
                    dval="$(jq -r ".targets[$t_idx].dns[$d_i].data // \"-\"" "$results_file")"
                    printf '| %s | %s | %s |\n' "$dtype" "$dname" "$dval"
                    (( d_i += 1 ))
                done
                printf '\n'
            fi

            # Open Ports & Services
            local svc_count
            svc_count="$(jq -r ".targets[$t_idx].services | length" "$results_file" 2>/dev/null || echo 0)"
            if (( svc_count > 0 )); then
                printf '### Open Ports & Services\n\n'
                printf '| Port | Protocol | Status | Service | Version |\n'
                printf '| :--- | :--- | :--- | :--- | :--- |\n'
                local s_i=0
                while (( s_i < svc_count )); do
                    local sport sproto sstat sname sver
                    sport="$(jq -r ".targets[$t_idx].services[$s_i].port // \"-\"" "$results_file")"
                    sproto="$(jq -r ".targets[$t_idx].services[$s_i].protocol // \"tcp\"" "$results_file")"
                    sstat="$(jq -r ".targets[$t_idx].services[$s_i].status // \"open\"" "$results_file")"
                    sname="$(jq -r ".targets[$t_idx].services[$s_i].service // \"-\"" "$results_file")"
                    sver="$(jq -r ".targets[$t_idx].services[$s_i].version // \"-\"" "$results_file")"
                    printf '| %s | %s | %s | %s | %s |\n' "$sport" "$sproto" "$sstat" "$sname" "$sver"
                    (( s_i += 1 ))
                done
                printf '\n'
            else
                local port_count
                port_count="$(jq -r ".targets[$t_idx].ports | length" "$results_file" 2>/dev/null || echo 0)"
                if (( port_count > 0 )); then
                    printf '### Open Ports\n\n'
                    local p_list
                    p_list="$(jq -r ".targets[$t_idx].ports | join(\", \")" "$results_file")"
                    printf 'Discovered open ports: `%s`\n\n' "$p_list"
                fi
            fi

            # Operating System Candidates
            local os_count
            os_count="$(jq -r ".targets[$t_idx].os | length" "$results_file" 2>/dev/null || echo 0)"
            if (( os_count > 0 )); then
                printf '### Operating System Detection\n\n'
                local o_i=0
                while (( o_i < os_count )); do
                    local ofam oacc odet
                    ofam="$(jq -r ".targets[$t_idx].os[$o_i].os_family // \"-\"" "$results_file")"
                    oacc="$(jq -r ".targets[$t_idx].os[$o_i].accuracy // \"-\"" "$results_file")"
                    odet="$(jq -r ".targets[$t_idx].os[$o_i].details // \"-\"" "$results_file")"
                    printf -- '- **%s** (Accuracy: %s) — `%s`\n' "$ofam" "$oacc" "$odet"
                    (( o_i += 1 ))
                done
                printf '\n'
            fi

            # Subdomains
            local sub_count
            sub_count="$(jq -r ".targets[$t_idx].subdomains | length" "$results_file" 2>/dev/null || echo 0)"
            if (( sub_count > 0 )); then
                printf '### Subdomains & Hostnames\n\n'
                printf '| Subdomain | Resolved IP |\n'
                printf '| :--- | :--- |\n'
                local sub_i=0
                while (( sub_i < sub_count )); do
                    local sub_name sub_ip
                    sub_name="$(jq -r ".targets[$t_idx].subdomains[$sub_i].subdomain // \"-\"" "$results_file")"
                    sub_ip="$(jq -r ".targets[$t_idx].subdomains[$sub_i].ip // \"-\"" "$results_file")"
                    printf '| %s | %s |\n' "$sub_name" "$sub_ip"
                    (( sub_i += 1 ))
                done
                printf '\n'
            fi

            # Web Technologies, CMS & WAF
            local tech_count cms_count waf_count
            tech_count="$(jq -r ".targets[$t_idx].technologies | length" "$results_file" 2>/dev/null || echo 0)"
            cms_count="$(jq -r ".targets[$t_idx].cms | length" "$results_file" 2>/dev/null || echo 0)"
            waf_count="$(jq -r ".targets[$t_idx].waf | length" "$results_file" 2>/dev/null || echo 0)"

            if (( tech_count > 0 || cms_count > 0 || waf_count > 0 )); then
                printf '### Web Fingerprinting & Technologies\n\n'
                if (( tech_count > 0 )); then
                    printf -- '- **Technologies:**\n'
                    local t_i=0
                    while (( t_i < tech_count )); do
                        local tname tver tcat
                        tname="$(jq -r ".targets[$t_idx].technologies[$t_i].name // \"-\"" "$results_file")"
                        tver="$(jq -r ".targets[$t_idx].technologies[$t_i].version // \"-\"" "$results_file")"
                        tcat="$(jq -r ".targets[$t_idx].technologies[$t_i].categories // \"-\"" "$results_file")"
                        printf '  - %s (Version: %s, Category: %s)\n' "$tname" "$tver" "$tcat"
                        (( t_i += 1 ))
                    done
                fi
                if (( cms_count > 0 )); then
                    printf -- '- **Content Management Systems (CMS):**\n'
                    local c_i=0
                    while (( c_i < cms_count )); do
                        local cname cver cconf
                        cname="$(jq -r ".targets[$t_idx].cms[$c_i].name // \"-\"" "$results_file")"
                        cver="$(jq -r ".targets[$t_idx].cms[$c_i].version // \"-\"" "$results_file")"
                        cconf="$(jq -r ".targets[$t_idx].cms[$c_i].confidence // \"-\"" "$results_file")"
                        printf '  - %s (Version: %s, Confidence: %s)\n' "$cname" "$cver" "$cconf"
                        (( c_i += 1 ))
                    done
                fi
                if (( waf_count > 0 )); then
                    printf -- '- **Web Application Firewall (WAF):**\n'
                    local w_i=0
                    while (( w_i < waf_count )); do
                        local wname wvend
                        wname="$(jq -r ".targets[$t_idx].waf[$w_i].name // \"-\"" "$results_file")"
                        wvend="$(jq -r ".targets[$t_idx].waf[$w_i].vendor // \"-\"" "$results_file")"
                        printf '  - %s (Vendor: %s)\n' "$wname" "$wvend"
                        (( w_i += 1 ))
                    done
                fi
                printf '\n'
            fi

            # Discovered Content (Directories & Files)
            local dir_count file_count
            dir_count="$(jq -r ".targets[$t_idx].directories | length" "$results_file" 2>/dev/null || echo 0)"
            file_count="$(jq -r ".targets[$t_idx].files | length" "$results_file" 2>/dev/null || echo 0)"

            if (( dir_count > 0 || file_count > 0 )); then
                printf '### Discovered Content & Paths\n\n'
                if (( dir_count > 0 )); then
                    printf '#### Directories\n\n'
                    printf '| Path | Status Code | Content Length | Redirect Location |\n'
                    printf '| :--- | :--- | :--- | :--- |\n'
                    local d_i=0
                    while (( d_i < dir_count )); do
                        local dp dstat dlen dred
                        dp="$(jq -r ".targets[$t_idx].directories[$d_i].path // \"-\"" "$results_file")"
                        dstat="$(jq -r ".targets[$t_idx].directories[$d_i].status // 200" "$results_file")"
                        dlen="$(jq -r ".targets[$t_idx].directories[$d_i].length // \"-\"" "$results_file")"
                        dred="$(jq -r ".targets[$t_idx].directories[$d_i].redirect // \"-\"" "$results_file")"
                        printf '| `%s` | %s | %s | `%s` |\n' "$dp" "$dstat" "$dlen" "$dred"
                        (( d_i += 1 ))
                    done
                    printf '\n'
                fi
                if (( file_count > 0 )); then
                    printf '#### Sensitive & Discovered Files\n\n'
                    printf '| Path | Status Code | Content Length | Classification |\n'
                    printf '| :--- | :--- | :--- | :--- |\n'
                    local f_i=0
                    while (( f_i < file_count )); do
                        local fp fstat flen fclass
                        fp="$(jq -r ".targets[$t_idx].files[$f_i].path // \"-\"" "$results_file")"
                        fstat="$(jq -r ".targets[$t_idx].files[$f_i].status // 200" "$results_file")"
                        flen="$(jq -r ".targets[$t_idx].files[$f_i].length // \"-\"" "$results_file")"
                        fclass="$(jq -r ".targets[$t_idx].files[$f_i].classification // \"-\"" "$results_file")"
                        printf '| `%s` | %s | %s | %s |\n' "$fp" "$fstat" "$flen" "$fclass"
                        (( f_i += 1 ))
                    done
                    printf '\n'
                fi
            fi

            # Virtual Hosts
            local vh_count
            vh_count="$(jq -r ".targets[$t_idx].vhosts | length" "$results_file" 2>/dev/null || echo 0)"
            if (( vh_count > 0 )); then
                printf '### Virtual Hosts\n\n'
                printf '| Virtual Host | Status Code | Content Length | Redirect Location |\n'
                printf '| :--- | :--- | :--- | :--- |\n'
                local v_i=0
                while (( v_i < vh_count )); do
                    local vhost vstat vlen vred
                    vhost="$(jq -r ".targets[$t_idx].vhosts[$v_i].vhost // \"-\"" "$results_file")"
                    vstat="$(jq -r ".targets[$t_idx].vhosts[$v_i].status // 200" "$results_file")"
                    vlen="$(jq -r ".targets[$t_idx].vhosts[$v_i].length // \"-\"" "$results_file")"
                    vred="$(jq -r ".targets[$t_idx].vhosts[$v_i].redirect // \"-\"" "$results_file")"
                    printf '| `%s` | %s | %s | `%s` |\n' "$vhost" "$vstat" "$vlen" "$vred"
                    (( v_i += 1 ))
                done
                printf '\n'
            fi

            # Endpoints & Crawled URLs
            local ep_count crawl_count
            ep_count="$(jq -r ".targets[$t_idx].endpoints | length" "$results_file" 2>/dev/null || echo 0)"
            crawl_count="$(jq -r ".targets[$t_idx].crawled_urls | length" "$results_file" 2>/dev/null || echo 0)"

            if (( ep_count > 0 || crawl_count > 0 )); then
                printf '### Web Endpoints & Crawled URLs\n\n'
                if (( ep_count > 0 )); then
                    printf '#### Identified Endpoints\n\n'
                    printf '| Endpoint | Category |\n'
                    printf '| :--- | :--- |\n'
                    local ep_i=0
                    while (( ep_i < ep_count )); do
                        local ep_val ep_cat
                        ep_val="$(jq -r ".targets[$t_idx].endpoints[$ep_i].endpoint // \"-\"" "$results_file")"
                        ep_cat="$(jq -r ".targets[$t_idx].endpoints[$ep_i].category // \"-\"" "$results_file")"
                        printf '| `%s` | %s |\n' "$ep_val" "$ep_cat"
                        (( ep_i += 1 ))
                    done
                    printf '\n'
                fi
                if (( crawl_count > 0 )); then
                    printf '#### Active Crawled URLs (%d discovered)\n\n' "$crawl_count"
                    local cr_i=0
                    while (( cr_i < crawl_count && cr_i < 50 )); do
                        local curl_val
                        curl_val="$(jq -r ".targets[$t_idx].crawled_urls[$cr_i] // \"-\"" "$results_file")"
                        printf -- '- `%s`\n' "$curl_val"
                        (( cr_i += 1 ))
                    done
                    if (( crawl_count > 50 )); then
                        printf -- '- *(and %d additional crawled URLs...)*\n' "$(( crawl_count - 50 ))"
                    fi
                    printf '\n'
                fi
            fi

            # Security Analysis & Audits
            local hdr_count disc_count mth_count
            hdr_count="$(jq -r ".targets[$t_idx].http_analysis.headers | length" "$results_file" 2>/dev/null || echo 0)"
            disc_count="$(jq -r ".targets[$t_idx].http_analysis.disclosures | length" "$results_file" 2>/dev/null || echo 0)"
            mth_count="$(jq -r ".targets[$t_idx].http_analysis.methods | length" "$results_file" 2>/dev/null || echo 0)"
            local cors_risk
            cors_risk="$(jq -r ".targets[$t_idx].http_analysis.cors.risk // \"NONE\"" "$results_file" 2>/dev/null)"

            if (( hdr_count > 0 || disc_count > 0 || mth_count > 0 )) || [[ "$cors_risk" != "NONE" && "$cors_risk" != "null" ]]; then
                printf '### HTTP Security Analysis\n\n'
                if (( hdr_count > 0 )); then
                    printf '#### Security Headers Compliance\n\n'
                    printf '| Header Name | Status | Value |\n'
                    printf '| :--- | :--- | :--- |\n'
                    local h_i=0
                    while (( h_i < hdr_count )); do
                        local hname hstat hval
                        hname="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].header // \"-\"" "$results_file")"
                        hstat="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].status // \"-\"" "$results_file")"
                        hval="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].value // \"-\"" "$results_file")"
                        printf '| %s | **%s** | `%s` |\n' "$hname" "$hstat" "$hval"
                        (( h_i += 1 ))
                    done
                    printf '\n'
                fi
                if (( disc_count > 0 )); then
                    printf '#### Information Disclosures\n\n'
                    local d_i=0
                    while (( d_i < disc_count )); do
                        local dhead dval
                        dhead="$(jq -r ".targets[$t_idx].http_analysis.disclosures[$d_i].header // \"-\"" "$results_file")"
                        dval="$(jq -r ".targets[$t_idx].http_analysis.disclosures[$d_i].value // \"-\"" "$results_file")"
                        printf -- '- **%s:** `%s`\n' "$dhead" "$dval"
                        (( d_i += 1 ))
                    done
                    printf '\n'
                fi
                if [[ "$cors_risk" != "NONE" && "$cors_risk" != "null" ]]; then
                    local corig ccred cstatus
                    corig="$(jq -r ".targets[$t_idx].http_analysis.cors.allow_origin // \"-\"" "$results_file")"
                    ccred="$(jq -r ".targets[$t_idx].http_analysis.cors.credentials_allowed // false" "$results_file")"
                    cstatus="$(jq -r ".targets[$t_idx].http_analysis.cors.status // \"-\"" "$results_file")"
                    printf '#### CORS Configuration Risk\n\n'
                    printf -- '- **Risk Assessment:** **%s**\n' "$cors_risk"
                    printf -- '- **Access-Control-Allow-Origin:** `%s`\n' "$corig"
                    printf -- '- **Credentials Allowed:** `%s`\n' "$ccred"
                    printf -- '- **Finding:** %s\n\n' "$cstatus"
                fi
                if (( mth_count > 0 )); then
                    printf '#### HTTP Method Permissions\n\n'
                    printf '| Method | Status | HTTP Code |\n'
                    printf '| :--- | :--- | :--- |\n'
                    local m_i=0
                    while (( m_i < mth_count )); do
                        local mmeth mstat mcode
                        mmeth="$(jq -r ".targets[$t_idx].http_analysis.methods[$m_i].method // \"-\"" "$results_file")"
                        mstat="$(jq -r ".targets[$t_idx].http_analysis.methods[$m_i].status // \"-\"" "$results_file")"
                        mcode="$(jq -r ".targets[$t_idx].http_analysis.methods[$m_i].code // \"-\"" "$results_file")"
                        printf '| %s | %s | %s |\n' "$mmeth" "$mstat" "$mcode"
                        (( m_i += 1 ))
                    done
                    printf '\n'
                fi
            fi

            # TLS & SSL Audits
            local tls_proto_count
            tls_proto_count="$(jq -r ".targets[$t_idx].tls.protocols | length" "$results_file" 2>/dev/null || echo 0)"
            local cert_subj
            cert_subj="$(jq -r ".targets[$t_idx].tls.certificate.subject // empty" "$results_file" 2>/dev/null)"

            if (( tls_proto_count > 0 )) || [[ -n "$cert_subj" ]]; then
                printf '### TLS & Cryptographic Audits\n\n'
                if (( tls_proto_count > 0 )); then
                    printf '#### Supported Protocols\n\n'
                    printf '| Protocol | Status | Security Assessment |\n'
                    printf '| :--- | :--- | :--- |\n'
                    local p_i=0
                    while (( p_i < tls_proto_count )); do
                        local proto pstat passess
                        proto="$(jq -r ".targets[$t_idx].tls.protocols[$p_i].protocol // \"-\"" "$results_file")"
                        pstat="$(jq -r ".targets[$t_idx].tls.protocols[$p_i].status // \"-\"" "$results_file")"
                        passess="$(jq -r ".targets[$t_idx].tls.protocols[$p_i].assessment // \"-\"" "$results_file")"
                        printf '| %s | %s | %s |\n' "$proto" "$pstat" "$passess"
                        (( p_i += 1 ))
                    done
                    printf '\n'
                fi
                if [[ -n "$cert_subj" ]]; then
                    local c_iss c_from c_until c_sans
                    c_iss="$(jq -r ".targets[$t_idx].tls.certificate.issuer // \"-\"" "$results_file")"
                    c_from="$(jq -r ".targets[$t_idx].tls.certificate.valid_from // \"-\"" "$results_file")"
                    c_until="$(jq -r ".targets[$t_idx].tls.certificate.valid_until // \"-\"" "$results_file")"
                    c_sans="$(jq -r ".targets[$t_idx].tls.certificate.sans // \"-\"" "$results_file")"
                    printf '#### Certificate Details\n\n'
                    printf -- '- **Subject:** `%s`\n' "$cert_subj"
                    printf -- '- **Issuer:** `%s`\n' "$c_iss"
                    printf -- '- **Validity:** %s to %s\n' "$c_from" "$c_until"
                    printf -- '- **Subject Alternative Names (SANs):** `%s`\n\n' "$c_sans"
                fi
            fi

            # Resources & Historical URLs
            local res_count hist_count
            res_count="$(jq -r ".targets[$t_idx].resources | length" "$results_file" 2>/dev/null || echo 0)"
            hist_count="$(jq -r ".targets[$t_idx].historical_urls | length" "$results_file" 2>/dev/null || echo 0)"

            if (( res_count > 0 || hist_count > 0 )); then
                printf '### Web Resources & Historical Intelligence\n\n'
                if (( res_count > 0 )); then
                    printf '#### Web Metadata Resources\n\n'
                    local r_i=0
                    while (( r_i < res_count )); do
                        local rp rstat rsize rdet
                        rp="$(jq -r ".targets[$t_idx].resources[$r_i].path // \"-\"" "$results_file")"
                        rstat="$(jq -r ".targets[$t_idx].resources[$r_i].status // 200" "$results_file")"
                        rsize="$(jq -r ".targets[$t_idx].resources[$r_i].size // \"-\"" "$results_file")"
                        rdet="$(jq -r ".targets[$t_idx].resources[$r_i].details // \"-\"" "$results_file")"
                        printf -- '- `%s` (Status: %s, Size: %s) — %s\n' "$rp" "$rstat" "$rsize" "$rdet"
                        (( r_i += 1 ))
                    done
                    printf '\n'
                fi
                if (( hist_count > 0 )); then
                    printf '#### Historical Wayback URLs (%d discovered)\n\n' "$hist_count"
                    local h_i=0
                    while (( h_i < hist_count && h_i < 25 )); do
                        local hurl
                        hurl="$(jq -r ".targets[$t_idx].historical_urls[$h_i] // \"-\"" "$results_file")"
                        printf -- '- `%s`\n' "$hurl"
                        (( h_i += 1 ))
                    done
                    if (( hist_count > 25 )); then
                        printf -- '- *(and %d additional historical URLs...)*\n' "$(( hist_count - 25 ))"
                    fi
                    printf '\n'
                fi
            fi

            printf -- '---\n\n'
            (( t_idx += 1 ))
        done
    } > "$raw_md_tmp"

    mv -f "$raw_md_tmp" "$out_file"
    chmod 0640 "$out_file" 2>/dev/null || true
    REPORTING_GENERATED_FILES+=("$out_file")
    return 0
}

# Export Plain Text assessment report (report.txt).
#
# Arguments:
#   $1 - root output directory of scan run
#   $2 - optional destination file path (default: $output_dir/report.txt)
#
# Returns:
#   0 on success, 1 on error
reporting_export_text() {
    local output_dir="${1:-}"
    local out_file="${2:-}"

    if [[ -z "$output_dir" || ! -d "$output_dir" ]]; then
        REPORTING_ERROR="Output directory does not exist or was not specified: $output_dir"
        printf 'Error: %s\n' "$REPORTING_ERROR" >&2
        return 1
    fi

    [[ -z "$out_file" ]] && out_file="${output_dir}/report.txt"

    if ! _reporting_ensure_results_json "$output_dir"; then
        return 1
    fi

    local results_file="${output_dir}/results.json"
    local raw_txt_tmp="${out_file}.tmp"

    local app_name app_version scan_ts total_targets
    local hosts_up open_ports subdomains endpoints security_issues

    app_name="$(jq -r '.scan_metadata.app_name // "RECKON"' "$results_file" 2>/dev/null)"
    app_version="$(jq -r '.scan_metadata.app_version // "1.0.0"' "$results_file" 2>/dev/null)"
    scan_ts="$(jq -r '.scan_metadata.timestamp // "Unknown"' "$results_file" 2>/dev/null)"
    total_targets="$(jq -r '.summary.total_targets // 0' "$results_file" 2>/dev/null)"
    hosts_up="$(jq -r '.summary.total_hosts_up // 0' "$results_file" 2>/dev/null)"
    open_ports="$(jq -r '.summary.total_open_ports // 0' "$results_file" 2>/dev/null)"
    subdomains="$(jq -r '.summary.total_subdomains // 0' "$results_file" 2>/dev/null)"
    endpoints="$(jq -r '.summary.total_web_endpoints // 0' "$results_file" 2>/dev/null)"
    security_issues="$(jq -r '.summary.total_security_issues // 0' "$results_file" 2>/dev/null)"

    {
        printf '%s\n' "================================================================================"
        printf '%s RECONNAISSANCE ASSESSMENT REPORT\n' "$app_name"
        printf '%s\n' "================================================================================"
        printf 'Generated:         %s\n' "$scan_ts"
        printf 'Application:       %s v%s\n' "$app_name" "$app_version"
        printf 'Output Directory:  %s\n' "$output_dir"
        printf 'Total Targets:     %s\n\n' "$total_targets"

        printf '%s\n' "--------------------------------------------------------------------------------"
        printf 'EXECUTIVE SUMMARY\n'
        printf '%s\n' "--------------------------------------------------------------------------------"
        printf '  Total Targets:                      %s\n' "$total_targets"
        printf '  Hosts Up:                           %s\n' "$hosts_up"
        printf '  Open Ports:                         %s\n' "$open_ports"
        printf '  Subdomains Discovered:              %s\n' "$subdomains"
        printf '  Web Endpoints Identified:           %s\n' "$endpoints"
        printf '  Security Issues / Observations:     %s\n\n' "$security_issues"

        local targets_len
        targets_len="$(jq -r '.targets | length' "$results_file" 2>/dev/null || echo 0)"

        local t_idx=0
        while (( t_idx < targets_len )); do
            local t_name t_type h_stat
            t_name="$(jq -r ".targets[$t_idx].target // \"-\"" "$results_file")"
            t_type="$(jq -r ".targets[$t_idx].target_type // \"-\"" "$results_file")"
            h_stat="$(jq -r ".targets[$t_idx].host_status // \"UNKNOWN\"" "$results_file")"

            printf '%s\n' "================================================================================"
            printf 'TARGET: %s (%s) [%s]\n' "$t_name" "$t_type" "$h_stat"
            printf '%s\n\n' "================================================================================"

            # DNS
            local dns_count
            dns_count="$(jq -r ".targets[$t_idx].dns | length" "$results_file" 2>/dev/null || echo 0)"
            if (( dns_count > 0 )); then
                printf '[+] DNS RECORDS:\n'
                local d_i=0
                while (( d_i < dns_count )); do
                    local dtype dname dval
                    dtype="$(jq -r ".targets[$t_idx].dns[$d_i].type // \"-\"" "$results_file")"
                    dname="$(jq -r ".targets[$t_idx].dns[$d_i].name // \"-\"" "$results_file")"
                    dval="$(jq -r ".targets[$t_idx].dns[$d_i].data // \"-\"" "$results_file")"
                    printf '    %-8s %-30s %s\n' "$dtype" "$dname" "$dval"
                    (( d_i += 1 ))
                done
                printf '\n'
            fi

            # Services
            local svc_count
            svc_count="$(jq -r ".targets[$t_idx].services | length" "$results_file" 2>/dev/null || echo 0)"
            if (( svc_count > 0 )); then
                printf '[+] OPEN PORTS & SERVICES:\n'
                printf '    %-8s %-7s %-8s %-16s %s\n' "PORT" "PROTO" "STATUS" "SERVICE" "VERSION"
                printf '    %-8s %-7s %-8s %-16s %s\n' "----" "-----" "------" "-------" "-------"
                local s_i=0
                while (( s_i < svc_count )); do
                    local sport sproto sstat sname sver
                    sport="$(jq -r ".targets[$t_idx].services[$s_i].port // \"-\"" "$results_file")"
                    sproto="$(jq -r ".targets[$t_idx].services[$s_i].protocol // \"tcp\"" "$results_file")"
                    sstat="$(jq -r ".targets[$t_idx].services[$s_i].status // \"open\"" "$results_file")"
                    sname="$(jq -r ".targets[$t_idx].services[$s_i].service // \"-\"" "$results_file")"
                    sver="$(jq -r ".targets[$t_idx].services[$s_i].version // \"-\"" "$results_file")"
                    printf '    %-8s %-7s %-8s %-16s %s\n' "$sport" "$sproto" "$sstat" "$sname" "$sver"
                    (( s_i += 1 ))
                done
                printf '\n'
            fi

            # OS
            local os_count
            os_count="$(jq -r ".targets[$t_idx].os | length" "$results_file" 2>/dev/null || echo 0)"
            if (( os_count > 0 )); then
                printf '[+] OS DETECTION:\n'
                local o_i=0
                while (( o_i < os_count )); do
                    local ofam oacc odet
                    ofam="$(jq -r ".targets[$t_idx].os[$o_i].os_family // \"-\"" "$results_file")"
                    oacc="$(jq -r ".targets[$t_idx].os[$o_i].accuracy // \"-\"" "$results_file")"
                    odet="$(jq -r ".targets[$t_idx].os[$o_i].details // \"-\"" "$results_file")"
                    printf '    - %s (%s) Details: %s\n' "$ofam" "$oacc" "$odet"
                    (( o_i += 1 ))
                done
                printf '\n'
            fi

            # Subdomains
            local sub_count
            sub_count="$(jq -r ".targets[$t_idx].subdomains | length" "$results_file" 2>/dev/null || echo 0)"
            if (( sub_count > 0 )); then
                printf '[+] SUBDOMAINS:\n'
                local sub_i=0
                while (( sub_i < sub_count )); do
                    local sub_name sub_ip
                    sub_name="$(jq -r ".targets[$t_idx].subdomains[$sub_i].subdomain // \"-\"" "$results_file")"
                    sub_ip="$(jq -r ".targets[$t_idx].subdomains[$sub_i].ip // \"-\"" "$results_file")"
                    printf '    %-35s %s\n' "$sub_name" "$sub_ip"
                    (( sub_i += 1 ))
                done
                printf '\n'
            fi

            # Web Technologies
            local tech_count cms_count waf_count
            tech_count="$(jq -r ".targets[$t_idx].technologies | length" "$results_file" 2>/dev/null || echo 0)"
            cms_count="$(jq -r ".targets[$t_idx].cms | length" "$results_file" 2>/dev/null || echo 0)"
            waf_count="$(jq -r ".targets[$t_idx].waf | length" "$results_file" 2>/dev/null || echo 0)"

            if (( tech_count > 0 || cms_count > 0 || waf_count > 0 )); then
                printf '[+] WEB TECHNOLOGIES & FINGERPRINTING:\n'
                if (( tech_count > 0 )); then
                    local t_i=0
                    while (( t_i < tech_count )); do
                        local tname tver
                        tname="$(jq -r ".targets[$t_idx].technologies[$t_i].name // \"-\"" "$results_file")"
                        tver="$(jq -r ".targets[$t_idx].technologies[$t_i].version // \"-\"" "$results_file")"
                        printf '    - Tech:  %s (%s)\n' "$tname" "$tver"
                        (( t_i += 1 ))
                    done
                fi
                if (( cms_count > 0 )); then
                    local c_i=0
                    while (( c_i < cms_count )); do
                        local cname cver cconf
                        cname="$(jq -r ".targets[$t_idx].cms[$c_i].name // \"-\"" "$results_file")"
                        cver="$(jq -r ".targets[$t_idx].cms[$c_i].version // \"-\"" "$results_file")"
                        cconf="$(jq -r ".targets[$t_idx].cms[$c_i].confidence // \"-\"" "$results_file")"
                        printf '    - CMS:   %s (%s) [Confidence: %s]\n' "$cname" "$cver" "$cconf"
                        (( c_i += 1 ))
                    done
                fi
                if (( waf_count > 0 )); then
                    local w_i=0
                    while (( w_i < waf_count )); do
                        local wname wvend
                        wname="$(jq -r ".targets[$t_idx].waf[$w_i].name // \"-\"" "$results_file")"
                        wvend="$(jq -r ".targets[$t_idx].waf[$w_i].vendor // \"-\"" "$results_file")"
                        printf '    - WAF:   %s (%s)\n' "$wname" "$wvend"
                        (( w_i += 1 ))
                    done
                fi
                printf '\n'
            fi

            # Discovered Content
            local dir_count file_count
            dir_count="$(jq -r ".targets[$t_idx].directories | length" "$results_file" 2>/dev/null || echo 0)"
            file_count="$(jq -r ".targets[$t_idx].files | length" "$results_file" 2>/dev/null || echo 0)"

            if (( dir_count > 0 || file_count > 0 )); then
                printf '[+] DISCOVERED CONTENT:\n'
                if (( dir_count > 0 )); then
                    local d_i=0
                    while (( d_i < dir_count )); do
                        local dp dstat dlen dred
                        dp="$(jq -r ".targets[$t_idx].directories[$d_i].path // \"-\"" "$results_file")"
                        dstat="$(jq -r ".targets[$t_idx].directories[$d_i].status // 200" "$results_file")"
                        dlen="$(jq -r ".targets[$t_idx].directories[$d_i].length // \"-\"" "$results_file")"
                        dred="$(jq -r ".targets[$t_idx].directories[$d_i].redirect // \"-\"" "$results_file")"
                        printf '    DIR   %-30s [%s] Length: %-6s Redirect: %s\n' "$dp" "$dstat" "$dlen" "$dred"
                        (( d_i += 1 ))
                    done
                fi
                if (( file_count > 0 )); then
                    local f_i=0
                    while (( f_i < file_count )); do
                        local fp fstat flen fclass
                        fp="$(jq -r ".targets[$t_idx].files[$f_i].path // \"-\"" "$results_file")"
                        fstat="$(jq -r ".targets[$t_idx].files[$f_i].status // 200" "$results_file")"
                        flen="$(jq -r ".targets[$t_idx].files[$f_i].length // \"-\"" "$results_file")"
                        fclass="$(jq -r ".targets[$t_idx].files[$f_i].classification // \"-\"" "$results_file")"
                        printf '    FILE  %-30s [%s] Length: %-6s Class: %s\n' "$fp" "$fstat" "$flen" "$fclass"
                        (( f_i += 1 ))
                    done
                fi
                printf '\n'
            fi

            # Virtual Hosts
            local vh_count
            vh_count="$(jq -r ".targets[$t_idx].vhosts | length" "$results_file" 2>/dev/null || echo 0)"
            if (( vh_count > 0 )); then
                printf '[+] VIRTUAL HOSTS:\n'
                local v_i=0
                while (( v_i < vh_count )); do
                    local vhost vstat vlen
                    vhost="$(jq -r ".targets[$t_idx].vhosts[$v_i].vhost // \"-\"" "$results_file")"
                    vstat="$(jq -r ".targets[$t_idx].vhosts[$v_i].status // 200" "$results_file")"
                    vlen="$(jq -r ".targets[$t_idx].vhosts[$v_i].length // \"-\"" "$results_file")"
                    printf '    %-35s [%s] Length: %s\n' "$vhost" "$vstat" "$vlen"
                    (( v_i += 1 ))
                done
                printf '\n'
            fi

            # Endpoints
            local ep_count crawl_count
            ep_count="$(jq -r ".targets[$t_idx].endpoints | length" "$results_file" 2>/dev/null || echo 0)"
            crawl_count="$(jq -r ".targets[$t_idx].crawled_urls | length" "$results_file" 2>/dev/null || echo 0)"

            if (( ep_count > 0 || crawl_count > 0 )); then
                printf '[+] ENDPOINTS & CRAWLED URLS:\n'
                if (( ep_count > 0 )); then
                    local ep_i=0
                    while (( ep_i < ep_count )); do
                        local ep_val ep_cat
                        ep_val="$(jq -r ".targets[$t_idx].endpoints[$ep_i].endpoint // \"-\"" "$results_file")"
                        ep_cat="$(jq -r ".targets[$t_idx].endpoints[$ep_i].category // \"-\"" "$results_file")"
                        printf '    [%-6s] %s\n' "$ep_cat" "$ep_val"
                        (( ep_i += 1 ))
                    done
                fi
                if (( crawl_count > 0 )); then
                    local cr_i=0
                    while (( cr_i < crawl_count && cr_i < 30 )); do
                        local curl_val
                        curl_val="$(jq -r ".targets[$t_idx].crawled_urls[$cr_i] // \"-\"" "$results_file")"
                        printf '    [CRAWL ] %s\n' "$curl_val"
                        (( cr_i += 1 ))
                    done
                fi
                printf '\n'
            fi

            # Security Analysis
            local hdr_count disc_count cors_risk
            hdr_count="$(jq -r ".targets[$t_idx].http_analysis.headers | length" "$results_file" 2>/dev/null || echo 0)"
            disc_count="$(jq -r ".targets[$t_idx].http_analysis.disclosures | length" "$results_file" 2>/dev/null || echo 0)"
            cors_risk="$(jq -r ".targets[$t_idx].http_analysis.cors.risk // \"NONE\"" "$results_file" 2>/dev/null)"

            if (( hdr_count > 0 || disc_count > 0 )) || [[ "$cors_risk" != "NONE" && "$cors_risk" != "null" ]]; then
                printf '[+] SECURITY ANALYSIS & AUDITS:\n'
                if (( hdr_count > 0 )); then
                    printf '    [*] Headers:\n'
                    local h_i=0
                    while (( h_i < hdr_count )); do
                        local hname hstat hval
                        hname="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].header // \"-\"" "$results_file")"
                        hstat="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].status // \"-\"" "$results_file")"
                        hval="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].value // \"-\"" "$results_file")"
                        printf '        [%-7s] %-30s %s\n' "$hstat" "$hname:" "$hval"
                        (( h_i += 1 ))
                    done
                fi
                if (( disc_count > 0 )); then
                    printf '    [*] Disclosures:\n'
                    local d_i=0
                    while (( d_i < disc_count )); do
                        local dhead dval
                        dhead="$(jq -r ".targets[$t_idx].http_analysis.disclosures[$d_i].header // \"-\"" "$results_file")"
                        dval="$(jq -r ".targets[$t_idx].http_analysis.disclosures[$d_i].value // \"-\"" "$results_file")"
                        printf '        - %s: %s\n' "$dhead" "$dval"
                        (( d_i += 1 ))
                    done
                fi
                if [[ "$cors_risk" != "NONE" && "$cors_risk" != "null" ]]; then
                    local corig ccred
                    corig="$(jq -r ".targets[$t_idx].http_analysis.cors.allow_origin // \"-\"" "$results_file")"
                    ccred="$(jq -r ".targets[$t_idx].http_analysis.cors.credentials_allowed // false" "$results_file")"
                    printf '    [*] CORS Risk: [%s] Origin: %s (Credentials: %s)\n' "$cors_risk" "$corig" "$ccred"
                fi
                printf '\n'
            fi

            # TLS
            local tls_proto_count cert_subj
            tls_proto_count="$(jq -r ".targets[$t_idx].tls.protocols | length" "$results_file" 2>/dev/null || echo 0)"
            cert_subj="$(jq -r ".targets[$t_idx].tls.certificate.subject // empty" "$results_file" 2>/dev/null)"

            if (( tls_proto_count > 0 )) || [[ -n "$cert_subj" ]]; then
                printf '[+] TLS & CRYPTOGRAPHIC AUDITS:\n'
                if (( tls_proto_count > 0 )); then
                    local p_i=0
                    while (( p_i < tls_proto_count )); do
                        local proto pstat passess
                        proto="$(jq -r ".targets[$t_idx].tls.protocols[$p_i].protocol // \"-\"" "$results_file")"
                        pstat="$(jq -r ".targets[$t_idx].tls.protocols[$p_i].status // \"-\"" "$results_file")"
                        passess="$(jq -r ".targets[$t_idx].tls.protocols[$p_i].assessment // \"-\"" "$results_file")"
                        printf '    - %-10s %-12s Assessment: %s\n' "$proto" "[$pstat]" "$passess"
                        (( p_i += 1 ))
                    done
                fi
                if [[ -n "$cert_subj" ]]; then
                    local c_iss c_from c_until
                    c_iss="$(jq -r ".targets[$t_idx].tls.certificate.issuer // \"-\"" "$results_file")"
                    c_from="$(jq -r ".targets[$t_idx].tls.certificate.valid_from // \"-\"" "$results_file")"
                    c_until="$(jq -r ".targets[$t_idx].tls.certificate.valid_until // \"-\"" "$results_file")"
                    printf '    - Certificate:  %s\n' "$cert_subj"
                    printf '      Issuer:       %s\n' "$c_iss"
                    printf '      Validity:     %s to %s\n' "$c_from" "$c_until"
                fi
                printf '\n'
            fi

            # Resources & Historical
            local res_count hist_count
            res_count="$(jq -r ".targets[$t_idx].resources | length" "$results_file" 2>/dev/null || echo 0)"
            hist_count="$(jq -r ".targets[$t_idx].historical_urls | length" "$results_file" 2>/dev/null || echo 0)"

            if (( res_count > 0 || hist_count > 0 )); then
                printf '[+] RESOURCES & HISTORICAL INTELLIGENCE:\n'
                if (( res_count > 0 )); then
                    local r_i=0
                    while (( r_i < res_count )); do
                        local rp rstat rsize rdet
                        rp="$(jq -r ".targets[$t_idx].resources[$r_i].path // \"-\"" "$results_file")"
                        rstat="$(jq -r ".targets[$t_idx].resources[$r_i].status // 200" "$results_file")"
                        rsize="$(jq -r ".targets[$t_idx].resources[$r_i].size // \"-\"" "$results_file")"
                        rdet="$(jq -r ".targets[$t_idx].resources[$r_i].details // \"-\"" "$results_file")"
                        printf '    [RES ] %-20s (Status: %s, Size: %s) -> %s\n' "$rp" "$rstat" "$rsize" "$rdet"
                        (( r_i += 1 ))
                    done
                fi
                if (( hist_count > 0 )); then
                    local h_i=0
                    while (( h_i < hist_count && h_i < 20 )); do
                        local hurl
                        hurl="$(jq -r ".targets[$t_idx].historical_urls[$h_i] // \"-\"" "$results_file")"
                        printf '    [HIST] %s\n' "$hurl"
                        (( h_i += 1 ))
                    done
                fi
                printf '\n'
            fi

            (( t_idx += 1 ))
        done
        printf '%s\n' "================================================================================"
        printf 'END OF REPORT\n'
        printf '%s\n' "================================================================================"
    } > "$raw_txt_tmp"

    mv -f "$raw_txt_tmp" "$out_file"
    chmod 0640 "$out_file" 2>/dev/null || true
    REPORTING_GENERATED_FILES+=("$out_file")
    return 0
}

# Export standalone HTML dashboard assessment report (report.html).
#
# Arguments:
#   $1 - root output directory of scan run
#   $2 - optional destination file path (default: $output_dir/report.html)
#
# Returns:
#   0 on success, 1 on error
reporting_export_html() {
    local output_dir="${1:-}"
    local out_file="${2:-}"

    if [[ -z "$output_dir" || ! -d "$output_dir" ]]; then
        REPORTING_ERROR="Output directory does not exist or was not specified: $output_dir"
        printf 'Error: %s\n' "$REPORTING_ERROR" >&2
        return 1
    fi

    [[ -z "$out_file" ]] && out_file="${output_dir}/report.html"

    if ! _reporting_ensure_results_json "$output_dir"; then
        return 1
    fi

    local results_file="${output_dir}/results.json"
    local raw_html_tmp="${out_file}.tmp"

    local app_name app_version scan_ts total_targets
    local hosts_up open_ports subdomains endpoints security_issues

    app_name="$(jq -r '.scan_metadata.app_name // "RECKON"' "$results_file" 2>/dev/null)"
    app_version="$(jq -r '.scan_metadata.app_version // "1.0.0"' "$results_file" 2>/dev/null)"
    scan_ts="$(jq -r '.scan_metadata.timestamp // "Unknown"' "$results_file" 2>/dev/null)"
    total_targets="$(jq -r '.summary.total_targets // 0' "$results_file" 2>/dev/null)"
    hosts_up="$(jq -r '.summary.total_hosts_up // 0' "$results_file" 2>/dev/null)"
    open_ports="$(jq -r '.summary.total_open_ports // 0' "$results_file" 2>/dev/null)"
    subdomains="$(jq -r '.summary.total_subdomains // 0' "$results_file" 2>/dev/null)"
    endpoints="$(jq -r '.summary.total_web_endpoints // 0' "$results_file" 2>/dev/null)"
    security_issues="$(jq -r '.summary.total_security_issues // 0' "$results_file" 2>/dev/null)"

    cat <<HTML_HEAD > "$raw_html_tmp"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${app_name} Reconnaissance Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
      --code-bg: #0b0e14;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 30px;
    }
    h1 { color: var(--accent); margin: 0 0 10px 0; }
    h2 { color: #f0f6fc; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 36px; }
    h3 { color: var(--accent); margin-top: 24px; }
    h4 { color: var(--text-muted); text-transform: uppercase; font-size: 0.85em; margin-top: 18px; }
    .meta { color: var(--text-muted); font-size: 0.9em; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin: 24px 0;
    }
    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      text-align: center;
    }
    .metric-num { font-size: 2em; font-weight: bold; color: var(--accent); }
    .metric-num.danger { color: var(--danger); }
    .metric-num.success { color: var(--success); }
    .metric-label { font-size: 0.85em; color: var(--text-muted); text-transform: uppercase; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 30px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 0.95em;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 10px 12px;
      text-align: left;
    }
    th { background: #21262d; color: #f0f6fc; }
    tr:nth-child(even) { background: #0f131a; }
    code {
      background: var(--code-bg);
      color: #79c0ff;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 0.9em;
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.8em;
      font-weight: 600;
    }
    .badge-open, .badge-up, .badge-present { background: rgba(63, 185, 80, 0.15); color: var(--success); }
    .badge-missing, .badge-high { background: rgba(248, 81, 73, 0.15); color: var(--danger); }
    .badge-down { background: rgba(248, 81, 73, 0.15); color: var(--danger); }
    .badge-info { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
    ul { padding-left: 20px; }
    li { margin-bottom: 4px; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>${app_name} Reconnaissance Assessment Report</h1>
    <div class="meta">
      Application: <strong>${app_name} v${app_version}</strong> |
      Generated: <strong>${scan_ts}</strong> |
      Output Directory: <code>${output_dir}</code>
    </div>
  </header>

  <section>
    <h2>Executive Summary</h2>
    <div class="grid">
      <div class="metric-card">
        <div class="metric-num">${total_targets}</div>
        <div class="metric-label">Total Targets</div>
      </div>
      <div class="metric-card">
        <div class="metric-num success">${hosts_up}</div>
        <div class="metric-label">Hosts Up</div>
      </div>
      <div class="metric-card">
        <div class="metric-num">${open_ports}</div>
        <div class="metric-label">Open Ports</div>
      </div>
      <div class="metric-card">
        <div class="metric-num">${subdomains}</div>
        <div class="metric-label">Subdomains</div>
      </div>
      <div class="metric-card">
        <div class="metric-num">${endpoints}</div>
        <div class="metric-label">Web Endpoints</div>
      </div>
      <div class="metric-card">
        <div class="metric-num danger">${security_issues}</div>
        <div class="metric-label">Security Issues</div>
      </div>
    </div>
  </section>
HTML_HEAD

    # Render target cards
    local targets_len
    targets_len="$(jq -r '.targets | length' "$results_file" 2>/dev/null || echo 0)"

    local t_idx=0
    while (( t_idx < targets_len )); do
        local t_name t_type h_stat
        t_name="$(jq -r ".targets[$t_idx].target // \"-\"" "$results_file")"
        t_type="$(jq -r ".targets[$t_idx].target_type // \"-\"" "$results_file")"
        h_stat="$(jq -r ".targets[$t_idx].host_status // \"UNKNOWN\"" "$results_file")"

        cat <<TARGET_START >> "$raw_html_tmp"
  <article class="card">
    <h2>Target: ${t_name}</h2>
    <p>Type: <code>${t_type}</code> | Status: <span class="badge badge-up">${h_stat}</span></p>
TARGET_START

        # DNS
        local dns_count
        dns_count="$(jq -r ".targets[$t_idx].dns | length" "$results_file" 2>/dev/null || echo 0)"
        if (( dns_count > 0 )); then
            cat <<'HTML_DNS_HEAD' >> "$raw_html_tmp"
    <h3>DNS Records</h3>
    <table>
      <thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead>
      <tbody>
HTML_DNS_HEAD
            local d_i=0
            while (( d_i < dns_count )); do
                local dtype dname dval
                dtype="$(jq -r ".targets[$t_idx].dns[$d_i].type // \"-\"" "$results_file")"
                dname="$(jq -r ".targets[$t_idx].dns[$d_i].name // \"-\"" "$results_file")"
                dval="$(jq -r ".targets[$t_idx].dns[$d_i].data // \"-\"" "$results_file")"
                printf '        <tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>\n' \
                    "$dtype" "$dname" "$dval" >> "$raw_html_tmp"
                (( d_i += 1 ))
            done
            printf '      </tbody>\n    </table>\n' >> "$raw_html_tmp"
        fi

        # Services
        local svc_count
        svc_count="$(jq -r ".targets[$t_idx].services | length" "$results_file" 2>/dev/null || echo 0)"
        if (( svc_count > 0 )); then
            cat <<'HTML_SVC_HEAD' >> "$raw_html_tmp"
    <h3>Open Ports &amp; Services</h3>
    <table>
      <thead><tr><th>Port</th><th>Protocol</th><th>Status</th><th>Service</th><th>Version</th></tr></thead>
      <tbody>
HTML_SVC_HEAD
            local s_i=0
            while (( s_i < svc_count )); do
                local sport sproto sstat sname sver
                sport="$(jq -r ".targets[$t_idx].services[$s_i].port // \"-\"" "$results_file")"
                sproto="$(jq -r ".targets[$t_idx].services[$s_i].protocol // \"tcp\"" "$results_file")"
                sstat="$(jq -r ".targets[$t_idx].services[$s_i].status // \"open\"" "$results_file")"
                sname="$(jq -r ".targets[$t_idx].services[$s_i].service // \"-\"" "$results_file")"
                sver="$(jq -r ".targets[$t_idx].services[$s_i].version // \"-\"" "$results_file")"
                printf '        <tr><td><strong>%s</strong></td><td>%s</td><td><span class="badge badge-open">%s</span></td><td>%s</td><td><code>%s</code></td></tr>\n' \
                    "$sport" "$sproto" "$sstat" "$sname" "$sver" >> "$raw_html_tmp"
                (( s_i += 1 ))
            done
            printf '      </tbody>\n    </table>\n' >> "$raw_html_tmp"
        fi

        # Subdomains
        local sub_count
        sub_count="$(jq -r ".targets[$t_idx].subdomains | length" "$results_file" 2>/dev/null || echo 0)"
        if (( sub_count > 0 )); then
            cat <<'HTML_SUB_HEAD' >> "$raw_html_tmp"
    <h3>Subdomains &amp; Hostnames</h3>
    <table>
      <thead><tr><th>Subdomain</th><th>Resolved IP</th></tr></thead>
      <tbody>
HTML_SUB_HEAD
            local sub_i=0
            while (( sub_i < sub_count )); do
                local sub_name sub_ip
                sub_name="$(jq -r ".targets[$t_idx].subdomains[$sub_i].subdomain // \"-\"" "$results_file")"
                sub_ip="$(jq -r ".targets[$t_idx].subdomains[$sub_i].ip // \"-\"" "$results_file")"
                printf '        <tr><td><code>%s</code></td><td>%s</td></tr>\n' "$sub_name" "$sub_ip" >> "$raw_html_tmp"
                (( sub_i += 1 ))
            done
            printf '      </tbody>\n    </table>\n' >> "$raw_html_tmp"
        fi

        # Web Content
        local dir_count file_count
        dir_count="$(jq -r ".targets[$t_idx].directories | length" "$results_file" 2>/dev/null || echo 0)"
        file_count="$(jq -r ".targets[$t_idx].files | length" "$results_file" 2>/dev/null || echo 0)"

        if (( dir_count > 0 || file_count > 0 )); then
            printf '    <h3>Discovered Web Paths</h3>\n' >> "$raw_html_tmp"
            if (( dir_count > 0 )); then
                cat <<'HTML_DIR_HEAD' >> "$raw_html_tmp"
    <h4>Directories</h4>
    <table>
      <thead><tr><th>Path</th><th>Status</th><th>Length</th><th>Redirect</th></tr></thead>
      <tbody>
HTML_DIR_HEAD
                local d_i=0
                while (( d_i < dir_count )); do
                    local dp dstat dlen dred
                    dp="$(jq -r ".targets[$t_idx].directories[$d_i].path // \"-\"" "$results_file")"
                    dstat="$(jq -r ".targets[$t_idx].directories[$d_i].status // 200" "$results_file")"
                    dlen="$(jq -r ".targets[$t_idx].directories[$d_i].length // \"-\"" "$results_file")"
                    dred="$(jq -r ".targets[$t_idx].directories[$d_i].redirect // \"-\"" "$results_file")"
                    printf '        <tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n' \
                        "$dp" "$dstat" "$dlen" "$dred" >> "$raw_html_tmp"
                    (( d_i += 1 ))
                done
                printf '      </tbody>\n    </table>\n' >> "$raw_html_tmp"
            fi
            if (( file_count > 0 )); then
                cat <<'HTML_FILE_HEAD' >> "$raw_html_tmp"
    <h4>Files</h4>
    <table>
      <thead><tr><th>Path</th><th>Status</th><th>Length</th><th>Classification</th></tr></thead>
      <tbody>
HTML_FILE_HEAD
                local f_i=0
                while (( f_i < file_count )); do
                    local fp fstat flen fclass
                    fp="$(jq -r ".targets[$t_idx].files[$f_i].path // \"-\"" "$results_file")"
                    fstat="$(jq -r ".targets[$t_idx].files[$f_i].status // 200" "$results_file")"
                    flen="$(jq -r ".targets[$t_idx].files[$f_i].length // \"-\"" "$results_file")"
                    fclass="$(jq -r ".targets[$t_idx].files[$f_i].classification // \"-\"" "$results_file")"
                    printf '        <tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><span class="badge badge-info">%s</span></td></tr>\n' \
                        "$fp" "$fstat" "$flen" "$fclass" >> "$raw_html_tmp"
                    (( f_i += 1 ))
                done
                printf '      </tbody>\n    </table>\n' >> "$raw_html_tmp"
            fi
        fi

        # Security Headers
        local hdr_count
        hdr_count="$(jq -r ".targets[$t_idx].http_analysis.headers | length" "$results_file" 2>/dev/null || echo 0)"
        if (( hdr_count > 0 )); then
            cat <<'HTML_HDR_HEAD' >> "$raw_html_tmp"
    <h3>HTTP Security Headers</h3>
    <table>
      <thead><tr><th>Header Name</th><th>Status</th><th>Configured Value</th></tr></thead>
      <tbody>
HTML_HDR_HEAD
            local h_i=0
            while (( h_i < hdr_count )); do
                local hname hstat hval b_class
                hname="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].header // \"-\"" "$results_file")"
                hstat="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].status // \"-\"" "$results_file")"
                hval="$(jq -r ".targets[$t_idx].http_analysis.headers[$h_i].value // \"-\"" "$results_file")"
                b_class="badge-present"
                [[ "$hstat" == "MISSING" ]] && b_class="badge-missing"
                printf '        <tr><td><code>%s</code></td><td><span class="badge %s">%s</span></td><td><code>%s</code></td></tr>\n' \
                    "$hname" "$b_class" "$hstat" "$hval" >> "$raw_html_tmp"
                (( h_i += 1 ))
            done
            printf '      </tbody>\n    </table>\n' >> "$raw_html_tmp"
        fi

        printf '  </article>\n' >> "$raw_html_tmp"
        (( t_idx += 1 ))
    done

    cat <<'HTML_TAIL' >> "$raw_html_tmp"
</div>
</body>
</html>
HTML_TAIL

    mv -f "$raw_html_tmp" "$out_file"
    chmod 0640 "$out_file" 2>/dev/null || true
    REPORTING_GENERATED_FILES+=("$out_file")
    return 0
}

# Generate reports across requested formats.
#
# Arguments:
#   $1 - root output directory of scan run
#   $2 - optional comma-separated or space-separated format list (e.g. "MD,TXT,HTML,JSON")
#   $3 - optional base file prefix (default: report)
#
# Returns:
#   0 on success, 1 on error
reporting_generate() {
    local output_dir="${1:-}"
    local formats_arg="${2:-}"
    local base_prefix="${3:-report}"

    reporting_init

    if [[ -z "$output_dir" || ! -d "$output_dir" ]]; then
        REPORTING_ERROR="Output directory does not exist or was not specified: $output_dir"
        printf 'Error: %s\n' "$REPORTING_ERROR" >&2
        return 1
    fi

    # Determine requested formats
    local -a requested_formats=()
    if [[ -n "$formats_arg" ]]; then
        local IFS=', '
        # shellcheck disable=SC2206
        requested_formats=($formats_arg)
    elif declare -p CONFIG_EFFECTIVE_FORMATS >/dev/null 2>&1 && (( ${#CONFIG_EFFECTIVE_FORMATS[@]} > 0 )); then
        requested_formats=("${CONFIG_EFFECTIVE_FORMATS[@]}")
    else
        # Default formats if none explicitly specified: Markdown and Text
        requested_formats=("MD" "TXT")
    fi

    local fmt
    for fmt in "${requested_formats[@]}"; do
        local u_fmt="${fmt^^}"
        case "$u_fmt" in
            JSON)
                local json_out="${output_dir}/results.json"
                if [[ ! -f "$json_out" ]]; then
                    results_generate_json "$output_dir" "$json_out" || true
                fi
                REPORTING_GENERATED_FILES+=("$json_out")
                ;;
            MD|MARKDOWN)
                reporting_export_markdown "$output_dir" "${output_dir}/${base_prefix}.md" || return 1
                ;;
            TXT|TEXT)
                reporting_export_text "$output_dir" "${output_dir}/${base_prefix}.txt" || return 1
                ;;
            HTML)
                reporting_export_html "$output_dir" "${output_dir}/${base_prefix}.html" || return 1
                ;;
            *)
                REPORTING_ERROR="Unsupported report format: $fmt"
                return 1
                ;;
        esac
    done

    return 0
}
