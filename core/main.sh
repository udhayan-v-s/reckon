#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Main application bootstrap
#

set -o nounset

# Load command-line interface functions.
# shellcheck source=core/cli.sh
if ! source "$PROJECT_ROOT/core/cli.sh"; then
    printf 'Error: Failed to load the command-line interface.\n' >&2
    exit 1
fi

# Load configuration management functions.
# shellcheck source=core/config.sh
if ! source "$PROJECT_ROOT/core/config.sh"; then
    printf 'Error: Failed to load configuration management.\n' >&2
    exit 1
fi

# Load target processing functions.
# shellcheck source=core/targets.sh
if ! source "$PROJECT_ROOT/core/targets.sh"; then
    printf 'Error: Failed to load target processing.\n' >&2
    exit 1
fi

# Load execution engine functions.
# shellcheck source=core/engine.sh
if ! source "$PROJECT_ROOT/core/engine.sh"; then
    printf 'Error: Failed to load execution engine component.\n' >&2
    exit 1
fi

# Load shared libraries.
# shellcheck source=lib/term.sh
if ! source "$PROJECT_ROOT/lib/term.sh"; then
    printf 'Error: Failed to load terminal presentation library.\n' >&2
    exit 1
fi

# shellcheck source=lib/log.sh
if ! source "$PROJECT_ROOT/lib/log.sh"; then
    printf 'Error: Failed to load logging framework library.\n' >&2
    exit 1
fi

# shellcheck source=lib/fs.sh
if ! source "$PROJECT_ROOT/lib/fs.sh"; then
    printf 'Error: Failed to load filesystem library.\n' >&2
    exit 1
fi

# shellcheck source=lib/common.sh
if ! source "$PROJECT_ROOT/lib/common.sh"; then
    printf 'Error: Failed to load common utilities library.\n' >&2
    exit 1
fi

# shellcheck source=lib/exec.sh
if ! source "$PROJECT_ROOT/lib/exec.sh"; then
    printf 'Error: Failed to load execution wrapper library.\n' >&2
    exit 1
fi

# shellcheck source=lib/deps.sh
if ! source "$PROJECT_ROOT/lib/deps.sh"; then
    printf 'Error: Failed to load dependency management library.\n' >&2
    exit 1
fi

# shellcheck source=lib/results.sh
if ! source "$PROJECT_ROOT/lib/results.sh"; then
    printf 'Error: Failed to load result normalization library.\n' >&2
    exit 1
fi

# shellcheck source=lib/reporting.sh
if ! source "$PROJECT_ROOT/lib/reporting.sh"; then
    printf 'Error: Failed to load reporting engine library.\n' >&2
    exit 1
fi

# Main application function.
reckon_main() {

    local parse_status
    local validation_status
    local config_status
    local warning

    # Initialize CLI state.
    cli_init

    # Parse command-line arguments.
    if cli_parse_args "$@"; then
        :
    else
        parse_status=$?
        exit "$parse_status"
    fi

    # When no arguments are provided, display the startup banner and help.
    if (( $# == 0 )); then
        term_init "$CLI_COLOR_MODE"
        cli_show_banner
        cli_show_help
        return 0
    fi

    # Display help when requested.
    if [[ "$CLI_HELP" == true ]]; then
        cli_show_help
        return 0
    fi

    # Display version when requested.
    if [[ "$CLI_VERSION" == true ]]; then
        cli_show_version
        return 0
    fi

    # Validate command-line arguments.
    if cli_validate_args; then
        :
    else
        validation_status=$?
        exit "$validation_status"
    fi

    # Initialize configuration state.
    config_init

    # Set the configuration file selected through the CLI.
    # shellcheck disable=SC2034
    CONFIG_FILE="$CLI_CONFIG"

    # Load the configuration file.
    if config_load; then
        :
    else
        config_status=$?
        printf 'Error: %s\n' "$CONFIG_ERROR" >&2
        exit "$config_status"
    fi

    # Overlay CLI-supplied options onto the effective configuration.
    if config_apply_cli; then
        :
    else
        config_status=$?
        printf 'Error: %s\n' "$CONFIG_ERROR" >&2
        exit "$config_status"
    fi

    # Initialize terminal presentation and logging framework.
    term_init "$CONFIG_EFFECTIVE_COLOR"
    log_init "$CLI_VERBOSE" "$CLI_QUIET" "$CLI_DEBUG" "$CONFIG_EFFECTIVE_LOG_FILE"

    # Execute environment and dependency check when requested.
    if [[ "$CLI_CHECK" == true ]]; then
        local check_status=0
        deps_init
        if (( ${#CONFIG_EFFECTIVE_MODULES[@]} > 0 )); then
            deps_check_modules "${CONFIG_EFFECTIVE_MODULES[@]}" || true
        else
            deps_check_all || true
        fi
        deps_render_report || check_status=1
        if [[ -n "$CONFIG_EFFECTIVE_LOG_FILE" ]]; then
            _log_write_file "INFO" "Dependency check executed (exit code: $check_status)"
        fi
        exit "$check_status"
    fi

    # Prepare targets.
    if target_prepare; then
        :
    else
        printf 'Error: %s\n' "$TARGET_ERROR" >&2
        exit 2
    fi

    # Print any target warnings collected during preparation.
    if (( ${#TARGET_WARNINGS[@]} > 0 )); then
        for warning in "${TARGET_WARNINGS[@]}"; do
            printf 'Warning: %s\n' "$warning" >&2
        done
    fi

    # Application identity banner display.
    if [[ "$CLI_QUIET" == false ]]; then
        if [[ "$CLI_NO_BANNER" == false ]]; then
            cli_show_banner
        else
            printf '%s\n' "$APP_NAME"
            printf 'Version: %s\n' "$APP_VERSION"
            printf '%s\n\n' "$APP_DESCRIPTION"
        fi
    fi

    # Record initialization record to log file if configured.
    if [[ -n "$CONFIG_EFFECTIVE_LOG_FILE" ]]; then
        _log_write_file "INFO" "RECKON initialized (version: $APP_VERSION)"
    fi

    # Execute scan workflow if targets were prepared.
    if (( ${#TARGET_VALUE[@]} > 0 )); then
        engine_init

        if ! engine_resolve_modules; then
            printf 'Error: %s\n' "$ENGINE_ERROR" >&2
            exit 2
        fi

        if ! engine_plan_scan; then
            printf 'Error: %s\n' "$ENGINE_ERROR" >&2
            exit 2
        fi

        # Display Scan Session Header and Preparation cards
        if [[ "$CLI_QUIET" == false && "${CLI_DRY_RUN:-false}" != true ]]; then
            local mode_label="Network"
            local scan_scope="Network"
            if [[ "${CLI_NETWORK:-false}" == true && "${CLI_WEB:-false}" == true ]]; then
                if [[ "${CLI_MODE:-}" == "all" || "${CONFIG_EFFECTIVE_MODE:-}" == "all" ]]; then
                    mode_label="All"
                    scan_scope="All"
                else
                    mode_label="Network + Web"
                    scan_scope="Network + Web"
                fi
            elif [[ "${CLI_WEB:-false}" == true || "${CONFIG_EFFECTIVE_WEB:-false}" == true ]]; then
                mode_label="Web"
                scan_scope="Web"
            elif [[ "${CLI_NETWORK:-false}" == true || "${CONFIG_EFFECTIVE_NETWORK:-false}" == true ]]; then
                mode_label="Network"
                scan_scope="Network"
            elif [[ -n "${CONFIG_EFFECTIVE_MODE:-}" ]]; then
                mode_label="${CONFIG_EFFECTIVE_MODE^}"
                scan_scope="$mode_label"
            elif [[ -n "${CLI_MODE:-}" ]]; then
                mode_label="${CLI_MODE^}"
                scan_scope="$mode_label"
            elif declare -p ENGINE_RESOLVED_MODULES >/dev/null 2>&1 && (( ${#ENGINE_RESOLVED_MODULES[@]} > 0 )); then
                local has_net_mod=false has_web_mod=false
                local m_check
                for m_check in "${ENGINE_RESOLVED_MODULES[@]}"; do
                    if [[ "$(engine_get_module_category "$m_check")" == "network" ]]; then
                        has_net_mod=true
                    elif [[ "$(engine_get_module_category "$m_check")" == "web" ]]; then
                        has_web_mod=true
                    fi
                done
                if [[ "$has_net_mod" == true && "$has_web_mod" == true ]]; then
                    mode_label="Network + Web"
                    scan_scope="Network + Web"
                elif [[ "$has_web_mod" == true ]]; then
                    mode_label="Web"
                    scan_scope="Web"
                elif [[ "$has_net_mod" == true ]]; then
                    mode_label="Network"
                    scan_scope="Network"
                fi
            fi

            local num_targets=${#TARGET_VALUE[@]}
            local target_display="${TARGET_VALUE[0]}"
            if (( num_targets > 1 )); then
                target_display="${TARGET_VALUE[0]} (+ $(( num_targets - 1 )) more)"
            fi

            local target_type_str="Unknown"
            if (( num_targets == 1 )); then
                case "${TARGET_TYPE[0]:-unknown}" in
                    ipv4)                  target_type_str="IPv4 Address" ;;
                    ipv4_cidr)             target_type_str="IPv4 CIDR" ;;
                    ipv4_range)            target_type_str="IPv4 Range" ;;
                    domain)                target_type_str="Domain" ;;
                    hostname)              target_type_str="Hostname" ;;
                    url|url_http|url_https) target_type_str="URL" ;;
                    *)                     target_type_str="${TARGET_TYPE[0]}" ;;
                esac
            else
                local first_t_type="${TARGET_TYPE[0]:-unknown}"
                local all_same=true
                local tt_item
                for tt_item in "${TARGET_TYPE[@]}"; do
                    if [[ "$tt_item" != "$first_t_type" ]]; then
                        all_same=false
                        break
                    fi
                done
                if [[ "$all_same" == true ]]; then
                    case "$first_t_type" in
                        ipv4)                  target_type_str="IPv4 Address" ;;
                        ipv4_cidr)             target_type_str="IPv4 CIDR" ;;
                        ipv4_range)            target_type_str="IPv4 Range" ;;
                        domain)                target_type_str="Domain" ;;
                        hostname)              target_type_str="Hostname" ;;
                        url|url_http|url_https) target_type_str="URL" ;;
                        *)                     target_type_str="$first_t_type" ;;
                    esac
                else
                    target_type_str="Mixed"
                fi
            fi

            local profile_str="${CONFIG_EFFECTIVE_PROFILE:-${CLI_PROFILE:-Default}}"
            [[ -z "$profile_str" ]] && profile_str="Default"
            profile_str="${profile_str^}"

            local start_time_str
            printf -v start_time_str '%(%Y-%m-%d %H:%M:%S)T' -1

            local scan_id_date
            printf -v scan_id_date '%(%Y%m%d)T' -1
            RECKON_SCAN_ID="RECKON-${scan_id_date}-001"

            local base_out="${CONFIG_EFFECTIVE_OUTPUT_DIR:-results}"
            local out_display="$base_out"
            if (( num_targets == 1 )); then
                local single_slug
                single_slug="$(_engine_sanitize_target_dir "${TARGET_VALUE[0]}")"
                out_display="${base_out}/${single_slug}/"
            else
                [[ "$out_display" != */ ]] && out_display="${out_display}/"
            fi

            printf '%s\n' "================================================================================"
            if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                printf '                         %s\n' "$(term_bold "RECKON - RECONNAISSANCE SCAN")"
            else
                printf '                         RECKON - RECONNAISSANCE SCAN\n'
            fi
            printf '%s\n\n' "================================================================================"
            printf 'SCAN INFORMATION\n\n'
            printf '  %-22s: %s\n' "Scan ID" "$RECKON_SCAN_ID"
            printf '  %-22s: %s\n' "Started" "$start_time_str"
            printf '  %-22s: %s\n' "Scan Mode" "$mode_label"
            printf '  %-22s: %s\n' "Scan Profile" "$profile_str"
            printf '  %-22s: %s\n\n' "Total Targets" "$num_targets"
            printf 'TARGET INFORMATION\n\n'
            printf '  %-22s: %s\n' "Target" "$target_display"
            printf '  %-22s: %s\n' "Target Type" "$target_type_str"
            printf '  %-22s: %s\n' "Scan Scope" "$scan_scope"
            if [[ "$mode_label" =~ (Web|All) ]]; then
                local wl_display=""
                if [[ -n "${CONFIG_EFFECTIVE_WORDLIST:-${CLI_WORDLIST:-}}" ]]; then
                    wl_display="${CONFIG_EFFECTIVE_WORDLIST:-${CLI_WORDLIST:-}} (Custom)"
                elif [[ -f "/usr/share/wordlists/dirb/common.txt" ]]; then
                    wl_display="/usr/share/wordlists/dirb/common.txt (Default System Wordlist)"
                elif [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt" ]]; then
                    wl_display="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt (Default System Wordlist)"
                else
                    wl_display="Embedded Built-in Target List"
                fi
                printf '  %-22s: %s\n' "Wordlist" "$wl_display"
            fi
            printf '  %-22s: %s\n\n' "Output Directory" "$out_display"
            printf '%s\n\n' "================================================================================"

            # Phase 2: Preparation
            engine_render_preparation
        fi

        # In dry-run mode, render the simulated execution plan and exit.
        # Zero temporary workspace creation, zero reports, zero tool execution.
        if [[ "${CLI_DRY_RUN:-false}" == true ]]; then
            local dry_run_rc=0
            engine_render_dry_run
            dry_run_rc=$?
            exit "$dry_run_rc"
        fi

        # Create temporary execution workspace outside the final report structure.
        local temp_work_dir=""
        if declare -f fs_mktemp_dir >/dev/null 2>&1; then
            fs_mktemp_dir temp_work_dir "reckon_exec"
        else
            temp_work_dir="$(mktemp -d "${TMPDIR:-/tmp}/reckon_exec.XXXXXX" 2>/dev/null)"
        fi
        if [[ -z "$temp_work_dir" || ! -d "$temp_work_dir" ]]; then
            printf 'Error: Failed to create temporary execution directory\n' >&2
            exit 1
        fi
        chmod 0750 "$temp_work_dir" 2>/dev/null || true

        # Clean up temporary execution files on exit, interrupt or failure.
        _main_cleanup() {
            if [[ -n "${temp_work_dir:-}" && -d "${temp_work_dir:-}" ]]; then
                rm -rf "$temp_work_dir" 2>/dev/null || true
            fi
            if declare -f fs_cleanup_temp >/dev/null 2>&1; then
                fs_cleanup_temp
            fi
        }
        trap '_main_cleanup' EXIT INT TERM HUP

        local scan_start_time=$SECONDS
        local scan_status=0
        if engine_run "${CLI_DRY_RUN:-false}" "$temp_work_dir" "${CONFIG_EFFECTIVE_TIMEOUT:-0}" "${CONFIG_EFFECTIVE_RETRIES:-0}"; then
            :
        else
            scan_status=$?
        fi

        # Generate assessment reports unless --no-report is specified.
        local -a displayed_report_files=()
        local report_gen_failed=false

        if [[ "${CONFIG_EFFECTIVE_NO_REPORT:-false}" == true ]]; then
            if declare -f log_info >/dev/null 2>&1; then
                log_info "Report generation skipped (--no-report enabled)"
            fi
            if [[ -n "$CONFIG_EFFECTIVE_LOG_FILE" ]]; then
                _log_write_file "INFO" "Report generation skipped (--no-report enabled)"
            fi
            local t_val
            for t_val in "${TARGET_VALUE[@]}"; do
                local t_slug=""
                t_slug="$(_engine_sanitize_target_dir "$t_val")"
                local final_t_dir="${CONFIG_EFFECTIVE_OUTPUT_DIR:-results}/${t_slug}"
                rm -rf "$final_t_dir" && mkdir -p "$final_t_dir" && chmod 0750 "$final_t_dir"
            done
        else
            local format_str=""
            if declare -p CONFIG_EFFECTIVE_FORMATS >/dev/null 2>&1 && (( ${#CONFIG_EFFECTIVE_FORMATS[@]} > 0 )); then
                local IFS=','
                format_str="${CONFIG_EFFECTIVE_FORMATS[*]}"
            else
                format_str="JSON,MD,TXT"
            fi

            local t_idx
            for t_idx in "${!TARGET_VALUE[@]}"; do
                local t_val="${TARGET_VALUE[t_idx]}"
                local t_slug=""
                t_slug="$(_engine_sanitize_target_dir "$t_val")"
                local raw_t_dir="${temp_work_dir}/${t_slug}"
                local final_t_dir="${CONFIG_EFFECTIVE_OUTPUT_DIR:-results}/${t_slug}"

                # Clean prior run folder for target to prevent mixing old and new scan reports
                rm -rf "$final_t_dir" && mkdir -p "$final_t_dir" && chmod 0750 "$final_t_dir"

                if [[ -d "$raw_t_dir" ]]; then
                    local stage_dir="${temp_work_dir}/_stage_${t_slug}"
                    rm -rf "$stage_dir" && mkdir -p "$stage_dir" && chmod 0750 "$stage_dir"
                    ln -s "$raw_t_dir" "${stage_dir}/${t_slug}"

                    local -a _saved_tv=("${TARGET_VALUE[@]}")
                    local -a _saved_tt=("${TARGET_TYPE[@]}")
                    TARGET_VALUE=("$t_val")
                    TARGET_TYPE=("${_saved_tt[t_idx]:-}")

                    if reporting_generate "$stage_dir" "$format_str"; then
                        local gen_f
                        for gen_f in "${REPORTING_GENERATED_FILES[@]}"; do
                            local f_name
                            f_name="$(basename "$gen_f")"
                            if [[ -f "$gen_f" ]]; then
                                mv -f "$gen_f" "${final_t_dir}/${f_name}"
                                chmod 0640 "${final_t_dir}/${f_name}" 2>/dev/null || true
                                displayed_report_files+=("${final_t_dir}/${f_name}")
                                if [[ -n "$CONFIG_EFFECTIVE_LOG_FILE" ]]; then
                                    _log_write_file "INFO" "Generated assessment report: ${final_t_dir}/${f_name}"
                                fi
                            fi
                        done
                    else
                        report_gen_failed=true
                        local rep_err="${REPORTING_ERROR:-unknown error}"
                        if declare -f log_error >/dev/null 2>&1; then
                            log_error "Failed to generate assessment reports for $t_val: $rep_err"
                        fi
                        printf 'Error: Failed to generate assessment reports for %s: %s\n' "$t_val" "$rep_err" >&2
                    fi

                    TARGET_VALUE=("${_saved_tv[@]}")
                    TARGET_TYPE=("${_saved_tt[@]}")
                    rm -rf "$stage_dir" 2>/dev/null || true
                fi
            done

            if [[ "$report_gen_failed" == true ]]; then
                scan_status=1
            fi
        fi

        # Scan completion summary display: SCAN SUMMARY & REPORTS GENERATED
        if [[ "$CLI_QUIET" == false && "${CLI_DRY_RUN:-false}" != true ]]; then
            local scan_duration=$(( SECONDS - scan_start_time ))
            local h=$(( scan_duration / 3600 ))
            local m=$(( (scan_duration % 3600) / 60 ))
            local s=$(( scan_duration % 60 ))
            local dur_str
            printf -v dur_str '%02d:%02d:%02d' "$h" "$m" "$s"

            local hosts_disc=0
            local open_ports=0
            local svcs_disc=0
            local web_svcs=0

            local t_item
            for t_item in "${TARGET_VALUE[@]}"; do
                local t_slug_scan=""
                t_slug_scan="$(_engine_sanitize_target_dir "$t_item")"
                local t_dir_scan="${temp_work_dir}/${t_slug_scan}"
                if [[ -d "$t_dir_scan" ]]; then
                    local h_c=0 o_c=0 s_c=0 w_c=0
                    if [[ -f "$t_dir_scan/host/hosts_live.txt" ]]; then
                        h_c="$(grep -c -v '^[[:space:]]*$' "$t_dir_scan/host/hosts_live.txt" 2>/dev/null || true)"
                    fi
                    h_c="${h_c:-0}"
                    (( hosts_disc += h_c ))

                    if [[ -f "$t_dir_scan/port/open_ports.txt" ]]; then
                        o_c="$(grep -c -E '^[0-9]+' "$t_dir_scan/port/open_ports.txt" 2>/dev/null || true)"
                    fi
                    o_c="${o_c:-0}"
                    (( open_ports += o_c ))

                    if [[ -f "$t_dir_scan/service/services.txt" ]]; then
                        s_c="$(grep -c -v '^[[:space:]]*$' "$t_dir_scan/service/services.txt" 2>/dev/null || true)"
                    fi
                    s_c="${s_c:-0}"
                    (( svcs_disc += s_c ))

                    if [[ -f "$t_dir_scan/http-probe/live_web.txt" ]]; then
                        w_c="$(grep -c -v '^[[:space:]]*$' "$t_dir_scan/http-probe/live_web.txt" 2>/dev/null || true)"
                    elif [[ -f "$t_dir_scan/http-probe/live_endpoints.txt" ]]; then
                        w_c="$(grep -c -v '^[[:space:]]*$' "$t_dir_scan/http-probe/live_endpoints.txt" 2>/dev/null || true)"
                    fi
                    w_c="${w_c:-0}"
                    (( web_svcs += w_c ))
                fi
            done

            if (( hosts_disc == 0 )) && (( ${#TARGET_VALUE[@]} > 0 )); then
                hosts_disc="${#TARGET_VALUE[@]}"
            fi

            # Synchronize metrics from generated results.json inside target directories if available
            local t_item_sync
            for t_item_sync in "${TARGET_VALUE[@]}"; do
                local t_sub_dir=""
                t_sub_dir="$(_engine_sanitize_target_dir "$t_item_sync")"
                local check_json="${CONFIG_EFFECTIVE_OUTPUT_DIR:-results}/${t_sub_dir}/results.json"
                if [[ -f "$check_json" ]]; then
                    local json_hosts json_ports
                    json_hosts="$(jq -r '.summary.total_hosts_up // empty' "$check_json" 2>/dev/null || true)"
                    json_ports="$(jq -r '.summary.total_open_ports // empty' "$check_json" 2>/dev/null || true)"
                    [[ -n "$json_hosts" && "$json_hosts" =~ ^[0-9]+$ ]] && (( json_hosts > hosts_disc )) && hosts_disc="$json_hosts"
                    [[ -n "$json_ports" && "$json_ports" =~ ^[0-9]+$ ]] && (( json_ports > open_ports )) && open_ports="$json_ports"
                fi
            done

            # Clean up temporary execution files before printing summary
            _main_cleanup
            trap - EXIT INT TERM HUP

            local modules_skipped=$(( ENGINE_TOTAL_TASKS - ENGINE_COMPLETED_TASKS - ENGINE_FAILED_TASKS - ENGINE_TIMEOUT_TASKS ))
            (( modules_skipped < 0 )) && modules_skipped=0

            # Header
            printf '%s\n' "================================================================================"
            if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                printf '                         %s\n' "$(term_bold "RECKON - SCAN SUMMARY")"
            else
                printf '                         RECKON - SCAN SUMMARY\n'
            fi
            printf '%s\n\n' "================================================================================"

            local total_mods_all=$ENGINE_TOTAL_TASKS
            if (( total_mods_all == 0 )); then
                total_mods_all=$(( ENGINE_COMPLETED_TASKS + ENGINE_PARTIAL_TASKS + ENGINE_FAILED_TASKS + ENGINE_TIMEOUT_TASKS + ENGINE_SKIPPED_TASKS + ENGINE_NOT_APPLICABLE_TASKS + ENGINE_BLOCKED_TASKS ))
            fi
            local failed_all=$(( ENGINE_FAILED_TASKS + ENGINE_TIMEOUT_TASKS ))

            printf 'SCAN OVERVIEW\n\n'
            printf '  %-28s: %s\n' "Scan ID" "${RECKON_SCAN_ID:-RECKON-$(date +%Y%m%d)-001}"
            printf '  %-28s: %d\n' "Total Targets" "${#TARGET_VALUE[@]}"
            printf '  %-28s: %s\n\n' "Scan Duration" "$dur_str"

            printf 'MODULE EXECUTION\n\n'
            printf '  %-28s: %d\n' "Total Modules" "$total_mods_all"
            printf '  %-28s: %d\n' "Completed" "$ENGINE_COMPLETED_TASKS"
            printf '  %-28s: %d\n' "Partial" "$ENGINE_PARTIAL_TASKS"
            printf '  %-28s: %d\n' "Failed" "$failed_all"
            printf '  %-28s: %d\n' "Skipped" "$ENGINE_SKIPPED_TASKS"
            printf '  %-28s: %d\n' "Not Applicable" "$ENGINE_NOT_APPLICABLE_TASKS"
            printf '  %-28s: %d\n\n' "Blocked" "$ENGINE_BLOCKED_TASKS"

            printf 'RECONNAISSANCE RESULTS\n\n'
            printf '  %-28s: %d\n' "Total Findings" "$ENGINE_SCAN_TOTAL_FINDINGS"
            printf '  %-28s: %d\n' "Network Findings" "$ENGINE_SCAN_NET_FINDINGS"
            printf '  %-28s: %d\n' "Web Findings" "$ENGINE_SCAN_WEB_FINDINGS"
            printf '  %-28s: %d\n' "Warnings" "$ENGINE_SCAN_WARNINGS"
            printf '  %-28s: %d\n\n' "Errors" "$ENGINE_SCAN_ERRORS"

            printf 'REPORTS GENERATED\n\n'
            local -a reports_to_display=("${displayed_report_files[@]}")
            if (( ${#reports_to_display[@]} > 0 )); then
                local rpt_file
                for rpt_file in "${reports_to_display[@]}"; do
                    local rpt_base
                    rpt_base="$(basename "$rpt_file")"
                    printf '  [CREATED] %s\n' "$rpt_base"
                done
                printf '\n'
                local out_summary_dir="${CONFIG_EFFECTIVE_OUTPUT_DIR:-results}"
                if (( ${#TARGET_VALUE[@]} == 1 )); then
                    local s_slug
                    s_slug="$(_engine_sanitize_target_dir "${TARGET_VALUE[0]}")"
                    out_summary_dir="${out_summary_dir}/${s_slug}/"
                else
                    [[ "$out_summary_dir" != */ ]] && out_summary_dir="${out_summary_dir}/"
                fi
                printf '  %-28s: %s\n\n' "Output Directory" "$out_summary_dir"
            else
                printf '  None (report generation disabled)\n\n'
            fi

            printf '%s\n' "================================================================================"
            if (( scan_status == 0 && ENGINE_SCAN_WARNINGS == 0 && ENGINE_SCAN_ERRORS == 0 )); then
                if declare -f term_green >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    printf '  %s\n\n  %s\n' "$(term_green "SCAN STATUS: COMPLETED")" "$(term_green "Reconnaissance completed successfully.")"
                else
                    printf '  SCAN STATUS: COMPLETED\n\n  Reconnaissance completed successfully.\n'
                fi
            elif (( ENGINE_SCAN_ERRORS > 0 || scan_status != 0 )); then
                if declare -f term_red >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    printf '  %s\n\n  %s\n' "$(term_red "SCAN STATUS: COMPLETED WITH ERRORS")" "$(term_red "Reconnaissance completed, but some modules encountered errors.")"
                else
                    printf '  SCAN STATUS: COMPLETED WITH ERRORS\n\n  Reconnaissance completed, but some modules encountered errors.\n'
                fi
            else
                if declare -f term_yellow >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    printf '  %s\n\n  %s\n' "$(term_yellow "SCAN STATUS: COMPLETED WITH WARNINGS")" "$(term_yellow "Reconnaissance completed, but some modules produced non-critical warnings.")"
                else
                    printf '  SCAN STATUS: COMPLETED WITH WARNINGS\n\n  Reconnaissance completed, but some modules produced non-critical warnings.\n'
                fi
            fi
            printf '%s\n' "================================================================================"
        fi

        if [[ -n "$CONFIG_EFFECTIVE_LOG_FILE" ]]; then
            _log_write_file "INFO" "Scan execution finished (tasks: $ENGINE_TOTAL_TASKS, completed: $ENGINE_COMPLETED_TASKS, failed: $ENGINE_FAILED_TASKS, timeouts: $ENGINE_TIMEOUT_TASKS, exit code: $scan_status)"
        fi

        exit "$scan_status"
    else
        printf '\n'
        cli_show_help
        return 0
    fi

}

# Start the application.
reckon_main "$@"