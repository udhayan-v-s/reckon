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

# Execution plan and graph state arrays.
ENGINE_RESOLVED_MODULES=()
ENGINE_PLAN_TARGETS=()
ENGINE_PLAN_TARGET_TYPES=()
ENGINE_PLAN_MODULES=()
ENGINE_SKIPPED_TASKS_INFO=()

# Task execution outcomes.
ENGINE_TASK_STATUS=()
ENGINE_TASK_DURATION=()
ENGINE_TASK_EXIT_CODE=()
ENGINE_TASK_OUTPUT_DIR=()

# Testing/mock execution hook (array representing mock command wrapper).
ENGINE_MOCK_DISPATCH_CMD=()

# Reset the execution engine state.
engine_init() {
    ENGINE_TOTAL_TASKS=0
    ENGINE_COMPLETED_TASKS=0
    ENGINE_FAILED_TASKS=0
    ENGINE_SKIPPED_TASKS=0
    ENGINE_TIMEOUT_TASKS=0
    ENGINE_RESOLVED_MODULES=()
    ENGINE_PLAN_TARGETS=()
    ENGINE_PLAN_TARGET_TYPES=()
    ENGINE_PLAN_MODULES=()
    ENGINE_SKIPPED_TASKS_INFO=()
    ENGINE_TASK_STATUS=()
    ENGINE_TASK_DURATION=()
    ENGINE_TASK_EXIT_CODE=()
    ENGINE_TASK_OUTPUT_DIR=()
    ENGINE_MOCK_DISPATCH_CMD=()
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

# Resolve candidate modules based on scan mode, explicit selections, and exclusions.
#
# Arguments:
#   $1 - optional network mode ("true"/"false")
#   $2 - optional web mode ("true"/"false")
#   $3 - optional comma/space-separated list of selected modules
#   $4 - optional comma/space-separated list of excluded modules
#
# If arguments are omitted, defaults to global configuration state:
#   CONFIG_EFFECTIVE_NETWORK, CONFIG_EFFECTIVE_WEB,
#   CONFIG_EFFECTIVE_MODULES, CONFIG_EFFECTIVE_EXCLUDE_MODULES
#
# Sets:
#   ENGINE_RESOLVED_MODULES
#
# Returns:
#   0 on success (at least one module resolved), 1 on error (sets ENGINE_ERROR)
engine_resolve_modules() {
    local net_mode="${1:-}"
    local web_mode="${2:-}"
    local explicit_mods_str="${3:-}"
    local exclude_mods_str="${4:-}"

    local -a candidate_modules=()
    local -a exclude_modules=()
    local -a resolved=()
    local item
    local mod

    ENGINE_ERROR=""
    ENGINE_RESOLVED_MODULES=()

    # Determine explicit selected modules (parameter or global config).
    if [[ -n "$explicit_mods_str" ]]; then
        local IFS=', '
        # shellcheck disable=SC2206
        candidate_modules=($explicit_mods_str)
    elif declare -p CONFIG_EFFECTIVE_MODULES >/dev/null 2>&1 && (( ${#CONFIG_EFFECTIVE_MODULES[@]} > 0 )); then
        candidate_modules=("${CONFIG_EFFECTIVE_MODULES[@]}")
    fi

    # Determine excluded modules (parameter or global config).
    if [[ -n "$exclude_mods_str" ]]; then
        local IFS=', '
        # shellcheck disable=SC2206
        exclude_modules=($exclude_mods_str)
    elif declare -p CONFIG_EFFECTIVE_EXCLUDE_MODULES >/dev/null 2>&1 && (( ${#CONFIG_EFFECTIVE_EXCLUDE_MODULES[@]} > 0 )); then
        exclude_modules=("${CONFIG_EFFECTIVE_EXCLUDE_MODULES[@]}")
    fi

    # If no explicit modules provided, determine candidates from scan mode.
    if (( ${#candidate_modules[@]} == 0 )); then
        if [[ -z "$net_mode" ]] && [[ -v CONFIG_EFFECTIVE_NETWORK ]]; then
            net_mode="$CONFIG_EFFECTIVE_NETWORK"
        fi
        if [[ -z "$web_mode" ]] && [[ -v CONFIG_EFFECTIVE_WEB ]]; then
            web_mode="$CONFIG_EFFECTIVE_WEB"
        fi

        if [[ "$net_mode" == "true" && "$web_mode" == "true" ]]; then
            candidate_modules=("${_ENGINE_ALL_MODULES[@]}")
        elif [[ "$net_mode" == "true" ]]; then
            candidate_modules=("${_ENGINE_NETWORK_MODULES[@]}")
        elif [[ "$web_mode" == "true" ]]; then
            candidate_modules=("${_ENGINE_WEB_MODULES[@]}")
        else
            ENGINE_ERROR="No scan mode or reconnaissance modules selected."
            return 1
        fi
    fi

    # Validate each candidate module and filter out exclusions and duplicates.
    for mod in "${candidate_modules[@]}"; do
        [[ -z "$mod" ]] && continue

        if ! engine_is_valid_module "$mod"; then
            ENGINE_ERROR="Invalid module identifier: $mod"
            return 1
        fi

        # Check if module is in exclusion list.
        local is_excluded=false
        for item in "${exclude_modules[@]}"; do
            if [[ "$item" == "$mod" ]]; then
                is_excluded=true
                break
            fi
        done
        [[ "$is_excluded" == true ]] && continue

        # Check if already added (deduplication).
        local already_added=false
        for item in "${resolved[@]}"; do
            if [[ "$item" == "$mod" ]]; then
                already_added=true
                break
            fi
        done
        [[ "$already_added" == true ]] && continue

        resolved+=("$mod")
    done

    if (( ${#resolved[@]} == 0 )); then
        ENGINE_ERROR="No modules remaining after applying exclusion filters."
        return 1
    fi

    ENGINE_RESOLVED_MODULES=("${resolved[@]}")
    return 0
}

# Generate the execution graph mapping targets to compatible modules.
#
# Reads:
#   TARGET_VALUE, TARGET_TYPE (from core/targets.sh)
#   ENGINE_RESOLVED_MODULES (from engine_resolve_modules)
#
# Populates:
#   ENGINE_PLAN_TARGETS
#   ENGINE_PLAN_TARGET_TYPES
#   ENGINE_PLAN_MODULES
#   ENGINE_SKIPPED_TASKS_INFO
#   ENGINE_TOTAL_TASKS
#   ENGINE_SKIPPED_TASKS
#
# Returns:
#   0 on success (at least one task scheduled), 1 on error (sets ENGINE_ERROR)
# shellcheck disable=SC2153
engine_plan_scan() {
    local target
    local t_type
    local mod
    local i
    local num_targets=0

    ENGINE_ERROR=""
    ENGINE_PLAN_TARGETS=()
    ENGINE_PLAN_TARGET_TYPES=()
    ENGINE_PLAN_MODULES=()
    ENGINE_SKIPPED_TASKS_INFO=()
    ENGINE_TOTAL_TASKS=0
    ENGINE_SKIPPED_TASKS=0

    # Ensure modules have been resolved.
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 0 )); then
        if ! engine_resolve_modules; then
            return 1
        fi
    fi

    # Check for targets.
    if declare -p TARGET_VALUE >/dev/null 2>&1; then
        num_targets=${#TARGET_VALUE[@]}
    fi

    if (( num_targets == 0 )); then
        ENGINE_ERROR="No valid targets available for execution planning."
        return 1
    fi

    # Build the execution graph.
    for (( i = 0; i < num_targets; i++ )); do
        target="${TARGET_VALUE[i]}"
        t_type="${TARGET_TYPE[i]}"

        for mod in "${ENGINE_RESOLVED_MODULES[@]}"; do
            if engine_is_module_compatible "$mod" "$t_type"; then
                ENGINE_PLAN_TARGETS+=("$target")
                ENGINE_PLAN_TARGET_TYPES+=("$t_type")
                ENGINE_PLAN_MODULES+=("$mod")
            else
                (( ENGINE_SKIPPED_TASKS += 1 ))
                ENGINE_SKIPPED_TASKS_INFO+=("Target '$target' ($t_type) is incompatible with module '$mod'")
            fi
        done
    done

    ENGINE_TOTAL_TASKS=${#ENGINE_PLAN_MODULES[@]}

    if (( ENGINE_TOTAL_TASKS == 0 )); then
        ENGINE_ERROR="No compatible modules could be scheduled for the supplied targets."
        return 1
    fi

    return 0
}

# Render a human-readable summary of the execution plan.
#
# Outputs:
#   Formatted execution graph with task indices, targets, target types, and modules.
engine_format_plan() {
    local i
    local target
    local target_type
    local mod
    local mod_name
    local category
    local num_targets=0

    if declare -p TARGET_VALUE >/dev/null 2>&1; then
        num_targets=${#TARGET_VALUE[@]}
    fi

    if (( ENGINE_TOTAL_TASKS == 0 )); then
        printf 'No tasks scheduled in execution plan.\n'
        return 0
    fi

    printf 'Execution Plan (%d tasks scheduled across %d target%s):\n' \
        "$ENGINE_TOTAL_TASKS" "$num_targets" "$( (( num_targets == 1 )) && echo "" || echo "s" )"

    for (( i = 0; i < ENGINE_TOTAL_TASKS; i++ )); do
        target="${ENGINE_PLAN_TARGETS[i]}"
        target_type="${ENGINE_PLAN_TARGET_TYPES[i]}"
        mod="${ENGINE_PLAN_MODULES[i]}"
        mod_name="$(engine_get_module_name "$mod")"
        category="$(engine_get_module_category "$mod")"

        printf '  [%2d] Target: %-25s (%-10s) -> Module: %-15s (%s) [%s]\n' \
            "$(( i + 1 ))" "$target" "$target_type" "$mod" "$mod_name" "$category"
    done
}

# Convert a target value into a safe filesystem directory name.
#
# Arguments:
#   $1 - raw target string
#
# Outputs:
#   Sanitized alphanumeric slug
_engine_sanitize_target_dir() {
    local t="${1:-}"
    # Replace : / \ and whitespace with underscores.
    t="${t//[:\/\\ ]/_}"
    # Condense consecutive underscores.
    while [[ "$t" == *__* ]]; do
        t="${t//__/_}"
    done
    # Strip leading and trailing underscores.
    t="${t#_}"
    t="${t%_}"
    printf '%s' "${t:-unknown_target}"
}

# Dispatch a single module execution task with stdout/stderr redirection and timeout.
#
# Arguments:
#   $1 - module identifier
#   $2 - target string
#   $3 - target type
#   $4 - task output directory
#   $5 - stdout destination file
#   $6 - stderr destination file
#   $7 - timeout in seconds (0 for unlimited)
#
# Returns:
#   Exit code of the dispatched task (or 124 on timeout)
_engine_dispatch_task() {
    local mod="$1"
    local target="$2"
    local t_type="$3"
    local task_dir="$4"
    local stdout_file="$5"
    local stderr_file="$6"
    local timeout_sec="$7"

    local exit_code=0
    local category
    category="$(engine_get_module_category "$mod")"

    # 1. Custom mock dispatch command (used in automated unit testing).
    if (( ${#ENGINE_MOCK_DISPATCH_CMD[@]} > 0 )); then
        local -a mock_cmd=("${ENGINE_MOCK_DISPATCH_CMD[@]}" "$mod" "$target" "$t_type" "$task_dir")
        if declare -f exec_run >/dev/null 2>&1; then
            exec_run "$stdout_file" "$stderr_file" "$timeout_sec" "${mock_cmd[@]}"
            exit_code=$?
        else
            "${mock_cmd[@]}" >"$stdout_file" 2>"$stderr_file"
            exit_code=$?
        fi
        return "$exit_code"
    fi

    # 2. Check for modular script on disk (modules/<category>/<module>.sh).
    local script_path="${PROJECT_ROOT:-.}/modules/${category}/${mod}.sh"
    if [[ -f "$script_path" && -x "$script_path" ]]; then
        if declare -f exec_run >/dev/null 2>&1; then
            exec_run "$stdout_file" "$stderr_file" "$timeout_sec" "$script_path" "$target" "$t_type" "$task_dir"
            exit_code=$?
        else
            "$script_path" "$target" "$t_type" "$task_dir" >"$stdout_file" 2>"$stderr_file"
            exit_code=$?
        fi
        return "$exit_code"
    fi

    # 3. Check for in-memory module execution function: module_<id>_run.
    local func_name="module_${mod//-/_}_run"
    if declare -f "$func_name" >/dev/null 2>&1; then
        if declare -f exec_run >/dev/null 2>&1 && (( timeout_sec == 0 )); then
            exec_run "$stdout_file" "$stderr_file" 0 "$func_name" "$target" "$t_type" "$task_dir"
            exit_code=$?
        else
            "$func_name" "$target" "$t_type" "$task_dir" >"$stdout_file" 2>"$stderr_file"
            exit_code=$?
        fi
        return "$exit_code"
    fi

    # 4. Default framework stub: writes task record to output directory.
    printf 'Module: %s\nTarget: %s\nType: %s\nStatus: STUB\n' \
        "$mod" "$target" "$t_type" > "$task_dir/output.txt"
    printf 'Stub execution completed for %s\n' "$mod" > "$stdout_file"
    : > "$stderr_file"

    return 0
}

# Execute the planned scan sequentially across all scheduled tasks.
#
# Arguments:
#   $1 - optional dry_run flag ("true"/"false")
#   $2 - optional base output directory path
#   $3 - optional per-task timeout in seconds
#   $4 - optional retries count for failed tasks
#
# If arguments are omitted, defaults to effective configuration:
#   CLI_DRY_RUN, CONFIG_EFFECTIVE_OUTPUT_DIR,
#   CONFIG_EFFECTIVE_TIMEOUT, CONFIG_EFFECTIVE_RETRIES
#
# Returns:
#   0 if all tasks succeed (or in dry-run mode), 1 if any task fails or times out
engine_run() {
    local dry_run="${1:-}"
    local base_out="${2:-}"
    local timeout_sec="${3:-}"
    local max_retries="${4:-}"

    local i
    local target
    local t_type
    local mod
    local mod_name
    local target_slug
    local task_dir
    local stdout_file
    local stderr_file
    local task_status
    local exit_code
    local duration
    local start_time
    local attempt
    local overall_status=0

    # Read defaults from global configuration if not explicitly supplied.
    if [[ -z "$dry_run" ]] && [[ -v CLI_DRY_RUN ]]; then
        dry_run="$CLI_DRY_RUN"
    fi
    if [[ -z "$base_out" ]]; then
        base_out="${CONFIG_EFFECTIVE_OUTPUT_DIR:-results}"
    fi
    if [[ -z "$timeout_sec" ]] && [[ -v CONFIG_EFFECTIVE_TIMEOUT ]]; then
        timeout_sec="$CONFIG_EFFECTIVE_TIMEOUT"
    fi
    timeout_sec="${timeout_sec:-0}"
    if [[ -z "$max_retries" ]] && [[ -v CONFIG_EFFECTIVE_RETRIES ]]; then
        max_retries="$CONFIG_EFFECTIVE_RETRIES"
    fi
    max_retries="${max_retries:-0}"

    # Ensure plan is generated.
    if (( ENGINE_TOTAL_TASKS == 0 )); then
        if ! engine_plan_scan; then
            return 1
        fi
    fi

    # Handle dry-run mode: display plan and return cleanly without executing.
    if [[ "$dry_run" == "true" ]]; then
        engine_format_plan
        printf '[DRY-RUN] Execution plan simulated (%d tasks). No commands executed.\n' "$ENGINE_TOTAL_TASKS"
        return 0
    fi

    # Clear previous execution task results.
    ENGINE_TASK_STATUS=()
    ENGINE_TASK_DURATION=()
    ENGINE_TASK_EXIT_CODE=()
    ENGINE_TASK_OUTPUT_DIR=()
    ENGINE_COMPLETED_TASKS=0
    ENGINE_FAILED_TASKS=0
    ENGINE_TIMEOUT_TASKS=0

    # Ensure base output directory exists.
    if declare -f fs_ensure_dir >/dev/null 2>&1; then
        if ! fs_ensure_dir "$base_out" 0750; then
            ENGINE_ERROR="Failed to create or access base output directory: $base_out"
            return 1
        fi
    else
        { mkdir -p "$base_out" && chmod 0750 "$base_out"; } 2>/dev/null || {
            ENGINE_ERROR="Failed to create or access base output directory: $base_out"
            return 1
        }
    fi

    # Sequential execution loop.
    for (( i = 0; i < ENGINE_TOTAL_TASKS; i++ )); do
        target="${ENGINE_PLAN_TARGETS[i]}"
        t_type="${ENGINE_PLAN_TARGET_TYPES[i]}"
        mod="${ENGINE_PLAN_MODULES[i]}"
        mod_name="$(engine_get_module_name "$mod")"

        target_slug="$(_engine_sanitize_target_dir "$target")"
        task_dir="${base_out}/${target_slug}/${mod}"
        stdout_file="${task_dir}/stdout.log"
        stderr_file="${task_dir}/stderr.log"

        # Create task directory.
        if declare -f fs_ensure_dir >/dev/null 2>&1; then
            fs_ensure_dir "$task_dir" 0750 || true
        else
            { mkdir -p "$task_dir" && chmod 0750 "$task_dir"; } 2>/dev/null || true
        fi

        # Log task start.
        if declare -f log_info >/dev/null 2>&1; then
            log_info "Executing [$(( i + 1 ))/$ENGINE_TOTAL_TASKS] $mod ($mod_name) on target '$target'..."
        fi

        start_time=$SECONDS
        attempt=0
        exit_code=1

        # Execute task with optional retries.
        while (( attempt <= max_retries )); do
            _engine_dispatch_task "$mod" "$target" "$t_type" "$task_dir" "$stdout_file" "$stderr_file" "$timeout_sec"
            exit_code=$?

            # If task succeeded or timed out, do not retry.
            if (( exit_code == 0 || exit_code == 124 )); then
                break
            fi

            (( attempt += 1 ))
            if (( attempt <= max_retries )); then
                if declare -f log_warn >/dev/null 2>&1; then
                    log_warn "Task $mod on target '$target' failed (code $exit_code). Retrying ($attempt/$max_retries)..."
                fi
            fi
        done

        duration=$(( SECONDS - start_time ))

        # Determine task status and update metrics.
        if (( exit_code == 0 )); then
            task_status="COMPLETED"
            (( ENGINE_COMPLETED_TASKS += 1 ))
            if declare -f log_success >/dev/null 2>&1; then
                log_success "[$(( i + 1 ))/$ENGINE_TOTAL_TASKS] Module '$mod' completed for target '$target' (${duration}s)"
            fi
        elif (( exit_code == 124 )); then
            task_status="TIMEOUT"
            (( ENGINE_TIMEOUT_TASKS += 1 ))
            overall_status=1
            if declare -f log_warn >/dev/null 2>&1; then
                log_warn "[$(( i + 1 ))/$ENGINE_TOTAL_TASKS] Module '$mod' timed out after ${timeout_sec}s for target '$target'"
            fi
        else
            task_status="FAILED"
            (( ENGINE_FAILED_TASKS += 1 ))
            overall_status=1
            if declare -f log_error >/dev/null 2>&1; then
                log_error "[$(( i + 1 ))/$ENGINE_TOTAL_TASKS] Module '$mod' failed with exit code $exit_code for target '$target'"
            fi
        fi

        ENGINE_TASK_STATUS+=("$task_status")
        ENGINE_TASK_DURATION+=("$duration")
        ENGINE_TASK_EXIT_CODE+=("$exit_code")
        ENGINE_TASK_OUTPUT_DIR+=("$task_dir")
    done

    return "$overall_status"
}
