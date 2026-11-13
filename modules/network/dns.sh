#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# DNS Reconnaissance Module (modules/network/dns.sh)
#
# Performs forward and reverse DNS resolution, nameserver queries,
# mail exchanger enumeration, TXT/SPF records, and zone transfer testing.
#
# Supported target types:
#   domain, hostname
#
# External tools utilized:
#   - dig (standard comprehensive DNS interrogation)
#   - dnsx (multi-probe resolution toolkit)
#

set -o nounset

DNS_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/common.sh
if ! source "$DNS_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
DNS_DIG_BIN="${RECKON_MOCK_DIG_BIN:-dig}"
DNS_DNSX_BIN="${RECKON_MOCK_DNSX_BIN:-dnsx}"

# Query records for a specific type using dig or fallback.
_dns_query_record() {
    local qtype="$1"
    local domain="$2"
    local raw=""

    if net_mod_has_tool "$DNS_DIG_BIN"; then
        raw="$("$DNS_DIG_BIN" +short +time=3 +tries=2 "$qtype" "$domain" 2>/dev/null || true)"
    elif net_mod_has_tool "host"; then
        raw="$(host -t "$qtype" "$domain" 2>/dev/null | awk '{print $NF}' || true)"
    fi

    if [[ -n "$raw" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%$'\r'}"
            # Ignore dig comments or empty lines
            if [[ -n "$line" && "$line" != ";"* ]]; then
                printf '%s\n' "$line"
            fi
        done <<< "$raw"
    fi
}

# Perform reverse DNS lookup on an IP address.
_dns_reverse_lookup() {
    local ip="$1"
    local ptr=""

    if net_mod_has_tool "$DNS_DIG_BIN"; then
        ptr="$("$DNS_DIG_BIN" +short +time=3 +tries=1 -x "$ip" 2>/dev/null || true)"
    elif net_mod_has_tool "host"; then
        ptr="$(host "$ip" 2>/dev/null | awk '/domain name pointer/{print $NF}' || true)"
    fi

    ptr="${ptr%$'\r'}"
    ptr="${ptr#$'\n'}"
    ptr="${ptr%$'\n'}"
    printf '%s\n' "${ptr:-}"
}

# Attempt DNS zone transfer (AXFR) on a target nameserver.
_dns_test_axfr() {
    local ns="$1"
    local domain="$2"

    ns="${ns%.}"  # Strip trailing dot

    if net_mod_has_tool "$DNS_DIG_BIN"; then
        local out
        out="$("$DNS_DIG_BIN" +time=3 +tries=1 AXFR "@$ns" "$domain" 2>/dev/null || true)"
        # Check if zone transfer actually succeeded
        if [[ "$out" == *"IN SOA"* || "$out" == *"IN"$'\t'*"SOA"* ]] && \
           [[ "$out" != *";; Transfer failed"* && "$out" != *"Transfer failed"* && "$out" != *"connection timed out"* ]]; then
            printf '%s\n' "$out"
            return 0
        fi
    fi
    return 1
}

# Main module execution function.
dns_main() {
    # Initialize execution context using module common library.
    if ! net_mod_init "$@"; then
        return 1
    fi

    net_mod_write_header "dns" "DNS Reconnaissance"

    # Validate target type compatibility (domain, hostname, ipv4).
    if ! net_mod_is_domain && [[ "$NET_TARGET_TYPE" != "ipv4" ]]; then
        net_mod_write_section "Execution Notice"
        net_mod_write_raw "Error: Target '$NET_TARGET' ($NET_TARGET_TYPE) is not a domain, hostname, or IPv4 address."
        net_mod_write_footer "FAILED" "Incompatible target type for DNS reconnaissance."
        return 1
    fi

    local dig_available=false
    local dnsx_available=false
    local engines_used=()

    if net_mod_has_tool "$DNS_DIG_BIN"; then
        dig_available=true
        engines_used+=("dig")
    fi
    if net_mod_has_tool "$DNS_DNSX_BIN"; then
        dnsx_available=true
        engines_used+=("dnsx")
    fi

    if [[ "$dig_available" == false && "$dnsx_available" == false ]]; then
        if net_mod_has_tool "host"; then
            engines_used+=("host (fallback)")
        else
            net_mod_write_section "Execution Notice"
            net_mod_write_raw "Error: Neither 'dig' nor 'dnsx' is available in PATH."
            net_mod_write_footer "FAILED" "Missing required DNS reconnaissance tools (dig, dnsx)."
            return 1
        fi
    fi

    local engines_str="None"
    if (( ${#engines_used[@]} > 0 )); then
        local IFS=', '
        engines_str="${engines_used[*]}"
    fi

    net_mod_write_section "Target Information"
    local target_lbl="Target Domain"
    [[ "$NET_TARGET_TYPE" == "ipv4" ]] && target_lbl="Target IP"
    net_mod_write_kv "$target_lbl" "$NET_TARGET"
    net_mod_write_kv "Target Type" "$NET_TARGET_TYPE"
    net_mod_write_kv "DNS Engines Used" "$engines_str"

    # Structured records artifact
    local records_file="${NET_TASK_DIR}/dns_records.txt"
    : > "$records_file"

    # For IPv4 targets, perform dedicated reverse DNS (PTR) interrogation.
    if [[ "$NET_TARGET_TYPE" == "ipv4" ]]; then
        net_mod_write_section "Reverse DNS (PTR Lookup)"
        local ptr
        ptr="$(_dns_reverse_lookup "$NET_TARGET")"
        if [[ -n "$ptr" ]]; then
            net_mod_write_kv "PTR Record" "$ptr"
            printf 'PTR\t%s\n' "$ptr" >> "$records_file"
            net_mod_write_footer "COMPLETED" "Resolved reverse DNS PTR record for $NET_TARGET: $ptr"
        else
            net_mod_write_kv "PTR Record" "None"
            net_mod_write_footer "COMPLETED" "No reverse DNS PTR record found for $NET_TARGET."
        fi
        chmod 0640 "$records_file" 2>/dev/null || true
        net_mod_finish 0
        return 0
    fi

    local -a a_records=()
    local -a aaaa_records=()
    local -a ns_records=()
    local -a mx_records=()
    local -a txt_records=()
    local -a soa_records=()
    local -a cname_records=()

    # 1. Query A records
    while IFS= read -r line; do
        [[ -n "$line" ]] && a_records+=("$line")
    done < <(_dns_query_record "A" "$NET_TARGET")

    # 2. Query AAAA records
    while IFS= read -r line; do
        [[ -n "$line" ]] && aaaa_records+=("$line")
    done < <(_dns_query_record "AAAA" "$NET_TARGET")

    # 3. Query NS records
    while IFS= read -r line; do
        [[ -n "$line" ]] && ns_records+=("$line")
    done < <(_dns_query_record "NS" "$NET_TARGET")

    # 4. Query MX records
    while IFS= read -r line; do
        [[ -n "$line" ]] && mx_records+=("$line")
    done < <(_dns_query_record "MX" "$NET_TARGET")

    # 5. Query TXT records
    while IFS= read -r line; do
        [[ -n "$line" ]] && txt_records+=("$line")
    done < <(_dns_query_record "TXT" "$NET_TARGET")

    # 6. Query SOA record
    while IFS= read -r line; do
        [[ -n "$line" ]] && soa_records+=("$line")
    done < <(_dns_query_record "SOA" "$NET_TARGET")

    # 7. Query CNAME record
    while IFS= read -r line; do
        [[ -n "$line" ]] && cname_records+=("$line")
    done < <(_dns_query_record "CNAME" "$NET_TARGET")

    # Save structured records to dns_records.txt
    local r
    for r in "${a_records[@]}"; do printf 'A\t%s\n' "$r" >> "$records_file"; done
    for r in "${aaaa_records[@]}"; do printf 'AAAA\t%s\n' "$r" >> "$records_file"; done
    for r in "${ns_records[@]}"; do printf 'NS\t%s\n' "$r" >> "$records_file"; done
    for r in "${mx_records[@]}"; do printf 'MX\t%s\n' "$r" >> "$records_file"; done
    for r in "${txt_records[@]}"; do printf 'TXT\t%s\n' "$r" >> "$records_file"; done
    for r in "${soa_records[@]}"; do printf 'SOA\t%s\n' "$r" >> "$records_file"; done
    for r in "${cname_records[@]}"; do printf 'CNAME\t%s\n' "$r" >> "$records_file"; done
    chmod 0640 "$records_file" 2>/dev/null || true

    # Format output.txt sections

    # Section: Address Records (A / AAAA)
    net_mod_write_section "Address Records (A / AAAA)"
    if (( ${#a_records[@]} > 0 )); then
        net_mod_write_raw "  A Records (IPv4)         :"
        for r in "${a_records[@]}"; do
            local ptr
            ptr="$(_dns_reverse_lookup "$r")"
            if [[ -n "$ptr" ]]; then
                net_mod_write_raw "    - $r (PTR: $ptr)"
            else
                net_mod_write_raw "    - $r"
            fi
        done
    else
        net_mod_write_kv "A Records (IPv4)" "None"
    fi

    if (( ${#aaaa_records[@]} > 0 )); then
        net_mod_write_raw "  AAAA Records (IPv6)      :"
        for r in "${aaaa_records[@]}"; do
            net_mod_write_raw "    - $r"
        done
    else
        net_mod_write_kv "AAAA Records (IPv6)" "None"
    fi

    # Section: Name Servers (NS)
    net_mod_write_section "Name Servers (NS)"
    if (( ${#ns_records[@]} > 0 )); then
        net_mod_write_raw "  Name Servers             :"
        for r in "${ns_records[@]}"; do
            net_mod_write_raw "    - $r"
        done
    else
        net_mod_write_kv "Name Servers" "None"
    fi

    # Section: Mail Exchanger (MX)
    net_mod_write_section "Mail Exchanger (MX)"
    if (( ${#mx_records[@]} > 0 )); then
        net_mod_write_raw "  Mail Exchangers          :"
        for r in "${mx_records[@]}"; do
            net_mod_write_raw "    - $r"
        done
    else
        net_mod_write_kv "Mail Exchangers" "None"
    fi

    # Section: Text & Verification (TXT)
    net_mod_write_section "Text & Verification (TXT)"
    if (( ${#txt_records[@]} > 0 )); then
        net_mod_write_raw "  TXT Records              :"
        for r in "${txt_records[@]}"; do
            net_mod_write_raw "    - $r"
        done
    else
        net_mod_write_kv "TXT Records" "None"
    fi

    # Section: Authority & Aliases (SOA / CNAME)
    net_mod_write_section "Authority & Aliases (SOA / CNAME)"
    if (( ${#soa_records[@]} > 0 )); then
        net_mod_write_kv "SOA Record" "${soa_records[0]}"
    else
        net_mod_write_kv "SOA Record" "None"
    fi
    if (( ${#cname_records[@]} > 0 )); then
        net_mod_write_kv "CNAME Record" "${cname_records[0]}"
    else
        net_mod_write_kv "CNAME Record" "None"
    fi

    # Section: Zone Transfer Interrogation (AXFR)
    net_mod_write_section "Zone Transfer Interrogation (AXFR)"
    local -a vuln_ns=()
    if (( ${#ns_records[@]} > 0 )) && [[ "$dig_available" == true ]]; then
        local ns_item
        for ns_item in "${ns_records[@]}"; do
            local clean_ns="${ns_item%.}"
            local axfr_data
            if axfr_data="$(_dns_test_axfr "$clean_ns" "$NET_TARGET")"; then
                vuln_ns+=("$clean_ns")
                printf '%s\n' "$axfr_data" > "${NET_TASK_DIR}/zone_transfer_${clean_ns}.txt"
                chmod 0640 "${NET_TASK_DIR}/zone_transfer_${clean_ns}.txt" 2>/dev/null || true
            fi
        done
    fi

    if (( ${#vuln_ns[@]} > 0 )); then
        local IFS=', '
        net_mod_write_kv "Zone Transfer Status" "VULNERABLE (Zone transfer succeeded on: ${vuln_ns[*]})"
        net_mod_write_kv "Remediation" "Restrict AXFR queries to authorized secondary nameservers only."
    else
        net_mod_write_kv "Zone Transfer Status" "Secure (AXFR refused or unavailable on tested nameservers)"
    fi

    # Summary
    local total_resolved=$(( ${#a_records[@]} + ${#aaaa_records[@]} + ${#ns_records[@]} + ${#mx_records[@]} + ${#txt_records[@]} + ${#soa_records[@]} + ${#cname_records[@]} ))
    local summary_msg="Resolved ${total_resolved} DNS record(s) across target domain."
    if (( ${#vuln_ns[@]} > 0 )); then
        summary_msg="Resolved ${total_resolved} DNS record(s). VULNERABILITY: Zone transfer allowed on ${#vuln_ns[@]} nameserver(s)!"
    fi

    net_mod_write_footer "COMPLETED" "$summary_msg"
    net_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    dns_main "$@"
fi
