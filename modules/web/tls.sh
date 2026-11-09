#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web SSL/TLS Security Analysis Module (modules/web/tls.sh)
#
# Inspects SSL/TLS protocol support, obsolete cipher vulnerabilities, and
# X.509 certificate metadata (expiration, SANs, chain validity, key strength).
#
# Supported target types:
#   url_https, hostname, domain, ipv4
#
# Primary External Tool:
#   - testssl.sh (comprehensive TLS configuration and vulnerability tester)
#
# Fallback Engine:
#   - openssl (native s_client protocol negotiation and x509 certificate parsing)
#

set -o nounset

TLS_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$TLS_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
TLS_TESTSSL_BIN="${RECKON_MOCK_TESTSSL_BIN:-testssl.sh}"
TLS_OPENSSL_BIN="${RECKON_MOCK_OPENSSL_BIN:-openssl}"

# Main entry point for the SSL/TLS Security Analysis module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (url_https, hostname, domain, ipv4)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_tls_run() {
    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    # Initialize web execution context with supported target types (url_http is incompatible).
    local init_rc=0
    web_mod_init "$target" "$t_type" "$task_dir" url_https hostname domain ipv4 || init_rc=$?
    if (( init_rc == 2 )); then
        return 0
    elif (( init_rc != 0 )); then
        return 1
    fi

    web_mod_write_header "tls" "SSL/TLS Protocol and Certificate Analysis"

    local cert_file="${task_dir}/cert_info.txt"
    local audit_file="${task_dir}/tls_audit.txt"
    : > "$cert_file"
    : > "$audit_file"

    local testssl_bin="${RECKON_MOCK_TESTSSL_BIN:-${TLS_TESTSSL_BIN:-testssl.sh}}"
    local openssl_bin="${RECKON_MOCK_OPENSSL_BIN:-${TLS_OPENSSL_BIN:-openssl}}"

    local has_testssl=false
    if [[ "$testssl_bin" != "none" ]] && web_mod_has_tool "$testssl_bin"; then
        has_testssl=true
    fi

    # Resolve target host and port
    local target_host="${WEB_URL_HOST:-$WEB_TARGET}"
    target_host="${target_host%:*}"
    local target_port="${WEB_URL_PORT:-443}"
    [[ -z "$target_port" ]] && target_port="443"

    local engine_name="testssl.sh"
    [[ "$has_testssl" == false ]] && engine_name="openssl s_client and x509 parser"

    web_mod_write_section "TLS Configuration"
    web_mod_write_kv "Target Host" "$target_host"
    web_mod_write_kv "Target Port" "$target_port"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Analysis Engine" "$engine_name"

    # 1. Primary Engine: testssl.sh execution
    local testssl_executed=false
    if [[ "$has_testssl" == true ]]; then
        local raw_testssl="${task_dir}/.testssl_raw.tmp"
        "$testssl_bin" --fast --color 0 "${target_host}:${target_port}" > "$raw_testssl" 2>/dev/null || true

        if [[ -f "$raw_testssl" && -s "$raw_testssl" ]]; then
            testssl_executed=true
            # Parse testssl.sh output
            grep -i -E '(SSLv2|SSLv3|TLS 1|TLS 1.1|TLS 1.2|TLS 1.3)' "$raw_testssl" >> "$audit_file" || true
            grep -i -E '(Certificate|Common Name|Issuer|Valid until|Subject Alt Names)' "$raw_testssl" >> "$cert_file" || true
            rm -f "$raw_testssl"
        fi
    fi

    # 2. Fallback Engine: native openssl s_client and x509 parsing
    if [[ "$testssl_executed" == false ]] && web_mod_has_tool "$openssl_bin"; then
        # Phase A: Certificate metadata extraction
        local raw_cert="${task_dir}/.raw_cert.tmp"
        printf '' | "$openssl_bin" s_client -connect "${target_host}:${target_port}" \
                    -servername "$target_host" -showcerts 2>/dev/null | \
                    "$openssl_bin" x509 -text -noout > "$raw_cert" 2>/dev/null || true

        local cert_subject=""
        local cert_issuer=""
        local not_before=""
        local not_after=""
        local cert_sans=""
        local sig_alg=""
        local pubkey_alg=""

        if [[ -f "$raw_cert" && -s "$raw_cert" ]]; then
            cert_subject="$(grep -E '^[[:space:]]*Subject:' "$raw_cert" | tail -n 1 | sed 's/^[[:space:]]*Subject:[[:space:]]*//' || true)"
            cert_issuer="$(grep -E '^[[:space:]]*Issuer:' "$raw_cert" | tail -n 1 | sed 's/^[[:space:]]*Issuer:[[:space:]]*//' || true)"
            not_before="$(grep -E '^[[:space:]]*Not Before:' "$raw_cert" | tail -n 1 | sed 's/^[[:space:]]*Not Before:[[:space:]]*//' || true)"
            not_after="$(grep -E '^[[:space:]]*Not After[[:space:]]*:' "$raw_cert" | tail -n 1 | sed 's/^[[:space:]]*Not After[[:space:]]*:[[:space:]]*//' || true)"
            cert_sans="$(grep -A 1 'Subject Alternative Name:' "$raw_cert" | tail -n 1 | sed 's/^[[:space:]]*//' || true)"
            sig_alg="$(grep -E '^[[:space:]]*Signature Algorithm:' "$raw_cert" | head -n 1 | sed 's/^[[:space:]]*Signature Algorithm:[[:space:]]*//' || true)"
            pubkey_alg="$(grep -E '^[[:space:]]*Public Key Algorithm:' "$raw_cert" | head -n 1 | sed 's/^[[:space:]]*Public Key Algorithm:[[:space:]]*//' || true)"
        fi
        rm -f "$raw_cert"

        {
            printf 'Subject: %s\n' "${cert_subject:-Unknown}"
            printf 'Issuer: %s\n' "${cert_issuer:-Unknown}"
            printf 'Valid From: %s\n' "${not_before:-Unknown}"
            printf 'Valid Until: %s\n' "${not_after:-Unknown}"
            printf 'SANs: %s\n' "${cert_sans:-None}"
            printf 'Signature Algorithm: %s\n' "${sig_alg:-Unknown}"
            printf 'Public Key: %s\n' "${pubkey_alg:-Unknown}"
        } >> "$cert_file"

        # Phase B: Protocol version support audit
        local -a proto_flags=("ssl2" "ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")
        local -a proto_names=("SSLv2" "SSLv3" "TLSv1.0" "TLSv1.1" "TLSv1.2" "TLSv1.3")

        local idx
        for (( idx = 0; idx < ${#proto_flags[@]}; idx++ )); do
            local p_flag="${proto_flags[idx]}"
            local p_name="${proto_names[idx]}"

            local s_out
            s_out="$(printf '' | "$openssl_bin" s_client -connect "${target_host}:${target_port}" \
                    -servername "$target_host" "-${p_flag}" 2>&1 || true)"

            local supported=false
            if [[ "$s_out" =~ Cipher[[:space:]]+is[[:space:]]+[a-zA-Z0-9_-]+ ]] && ! [[ "$s_out" =~ Cipher[[:space:]]+is[[:space:]]+\(NONE\) ]]; then
                supported=true
            elif [[ "$s_out" =~ Protocol[[:space:]]*:[[:space:]]*(TLSv|SSLv) ]]; then
                supported=true
            fi

            local status="NOT_SUPPORTED"
            local assessment="SECURE"
            if [[ "$supported" == true ]]; then
                status="SUPPORTED"
                case "$p_name" in
                    SSLv2|SSLv3)
                        assessment="CRITICAL (Obsolete & Insecure)"
                        ;;
                    TLSv1.0|TLSv1.1)
                        assessment="DEPRECATED (Weak Protocol)"
                        ;;
                    TLSv1.2|TLSv1.3)
                        assessment="SECURE (Modern Standard)"
                        ;;
                esac
            fi

            printf '%s\t%s\t%s\n' "$p_name" "$status" "$assessment" >> "$audit_file"
        done
    fi

    # Format human-readable output report
    web_mod_write_section "Certificate Metadata"
    local c_line
    while IFS= read -r c_line || [[ -n "$c_line" ]]; do
        [[ -z "$c_line" ]] && continue
        local k="${c_line%%:*}"
        local v="${c_line#*: }"
        web_mod_write_kv "$k" "$v"
    done < "$cert_file"

    web_mod_write_section "Protocol Version Audit"
    local crit_count=0
    local dep_count=0
    while IFS=$'\t' read -r p_name status assessment || [[ -n "$p_name" ]]; do
        [[ -z "$p_name" ]] && continue
        web_mod_write_raw "    - $p_name: $status ($assessment)"
        if [[ "$status" == "SUPPORTED" ]]; then
            [[ "$assessment" =~ CRITICAL ]] && (( crit_count += 1 ))
            [[ "$assessment" =~ DEPRECATED ]] && (( dep_count += 1 ))
        fi
    done < "$audit_file"

    local footer_msg="TLS audit complete: 0 critical protocol vulnerabilities identified."
    if (( crit_count > 0 )); then
        footer_msg="TLS audit complete: ${crit_count} CRITICAL protocol vulnerability/vulnerabilities detected!"
    elif (( dep_count > 0 )); then
        footer_msg="TLS audit complete: ${dep_count} deprecated protocol(s) enabled."
    fi

    web_mod_write_footer "COMPLETED" "$footer_msg"

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_tls_run "$@"
fi
