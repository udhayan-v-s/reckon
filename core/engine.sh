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
ENGINE_NOT_APPLICABLE_TASKS=0
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

# Signal handling and interruption state.
ENGINE_INTERRUPTED=false
_ENGINE_ACTIVE_PID=""
_ENGINE_TRAPS_INSTALLED=false

# Reset the execution engine state.
engine_init() {
    ENGINE_TOTAL_TASKS=0
    ENGINE_COMPLETED_TASKS=0
    ENGINE_NOT_APPLICABLE_TASKS=0
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
    ENGINE_INTERRUPTED=false
    _ENGINE_ACTIVE_PID=""
    _ENGINE_TRAPS_INSTALLED=false
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

# Handle POSIX termination signals (SIGINT, SIGTERM) gracefully.
#
# Arguments:
#   $1 - signal identifier ("INT", "TERM", "SIGINT", "SIGTERM", 2, 15)
_engine_handle_signal() {
    local sig="${1:-INT}"
    ENGINE_INTERRUPTED=true

    local exit_code=130
    case "$sig" in
        INT|SIGINT|2)
            exit_code=130
            ;;
        TERM|SIGTERM|15)
            exit_code=143
            ;;
        *)
            exit_code=1
            ;;
    esac

    local sig_display="${sig#SIG}"

    # Log graceful interruption notice to user.
    if declare -f log_warn >/dev/null 2>&1; then
        log_warn "Scan execution interrupted by SIG${sig_display}. Terminating active tasks and cleaning up..."
    else
        printf 'Warning: Scan execution interrupted by SIG%s. Terminating active tasks and cleaning up...\n' "$sig_display" >&2
    fi

    # Terminate recorded active task PID if set and running.
    if [[ -n "${_ENGINE_ACTIVE_PID:-}" ]] && kill -0 "$_ENGINE_ACTIVE_PID" 2>/dev/null; then
        kill -TERM "$_ENGINE_ACTIVE_PID" 2>/dev/null || true
    fi

    # Terminate all child processes of the current shell or subshell.
    if command -v pkill >/dev/null 2>&1; then
        local current_pid="${BASHPID:-$$}"
        pkill -P "$current_pid" 2>/dev/null || true
    fi

    # Clean up temporary files and directories tracked by filesystem library.
    if declare -f fs_cleanup_temp >/dev/null 2>&1; then
        fs_cleanup_temp
    fi

    # Teardown signal handlers.
    engine_teardown_traps

    exit "$exit_code"
}

# Install signal handlers for SIGINT and SIGTERM to guarantee clean teardown.
#
# Returns:
#   0 on success
engine_setup_traps() {
    trap '_engine_handle_signal INT' INT
    trap '_engine_handle_signal TERM' TERM
    _ENGINE_TRAPS_INSTALLED=true
    ENGINE_INTERRUPTED=false
    return 0
}

# Remove signal handlers and restore default signal behavior.
#
# Returns:
#   0 on success
engine_teardown_traps() {
    trap - INT TERM
    _ENGINE_TRAPS_INSTALLED=false
    return 0
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

    _ENGINE_ACTIVE_PID=""

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

    # 2. Check for in-memory module execution function: module_<id>_run (unit testing / mock hook).
    local func_name="module_${mod//-/_}_run"
    if declare -f "$func_name" >/dev/null 2>&1; then
        "$func_name" "$target" "$t_type" "$task_dir" >"$stdout_file" 2>"$stderr_file"
        exit_code=$?
        return "$exit_code"
    fi

    # 3. Check for modular script on disk (modules/<category>/<module>.sh or services subfolder).
    local script_path="${PROJECT_ROOT:-.}/modules/${category}/${mod}.sh"
    if [[ ! -f "$script_path" || ! -x "$script_path" ]]; then
        local service_script="${PROJECT_ROOT:-.}/modules/${category}/services/${mod}.sh"
        if [[ -f "$service_script" && -x "$service_script" ]]; then
            script_path="$service_script"
        fi
    fi
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
    ENGINE_NOT_APPLICABLE_TASKS=0
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

    # Display Reconnaissance section header
    if [[ "${CLI_QUIET:-false}" != true ]]; then
        printf '%s\n' "================================================================================"
        if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
            printf '  %s\n' "$(term_bold "RECONNAISSANCE")"
        else
            printf '  RECONNAISSANCE\n'
        fi
        printf '%s\n\n' "================================================================================"
    fi

    # Install signal handlers during active scan execution.
    engine_setup_traps

    # Sequential execution loop.
    for (( i = 0; i < ENGINE_TOTAL_TASKS; i++ )); do
        # Break immediately if scan execution was interrupted by signal.
        if [[ "$ENGINE_INTERRUPTED" == true ]]; then
            overall_status=130
            break
        fi

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

        # Log task start (audit log records start; terminal displays start when verbose/debug is active).
        if [[ "${CLI_VERBOSE:-false}" == true || "${LOG_VERBOSE:-false}" == true || "${CLI_DEBUG:-false}" == true ]]; then
            if declare -f log_info >/dev/null 2>&1; then
                log_info "Executing [$(( i + 1 ))/$ENGINE_TOTAL_TASKS] $mod ($mod_name) on target '$target'..."
            fi
        else
            _log_write_file "INFO" "Executing [$(( i + 1 ))/$ENGINE_TOTAL_TASKS] $mod ($mod_name) on target '$target'..."
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

        # Format task execution status card
        local task_idx_str
        printf -v task_idx_str '%02d/%02d' "$(( i + 1 ))" "$ENGINE_TOTAL_TASKS"

        # Determine finding summary for result line
        local result_detail=""
        case "$mod" in
            host)
                local host_cnt=0
                if [[ -f "$task_dir/hosts_live.txt" ]]; then
                    host_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/hosts_live.txt" 2>/dev/null || true)"
                elif [[ -f "$task_dir/hosts.txt" ]]; then
                    host_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/hosts.txt" 2>/dev/null || true)"
                fi
                host_cnt="${host_cnt:-0}"
                if (( host_cnt > 0 )); then
                    result_detail="${host_cnt} host(s) discovered"
                else
                    result_detail="No live hosts detected"
                fi
                ;;
            port)
                local port_cnt=0
                if [[ -f "$task_dir/open_ports.txt" ]]; then
                    port_cnt="$(grep -c -E '^[0-9]+' "$task_dir/open_ports.txt" 2>/dev/null || true)"
                elif [[ -f "$task_dir/ports_open.txt" ]]; then
                    port_cnt="$(grep -c -E '^[0-9]+' "$task_dir/ports_open.txt" 2>/dev/null || true)"
                fi
                port_cnt="${port_cnt:-0}"
                if (( port_cnt > 0 )); then
                    result_detail="${port_cnt} open port(s) identified"
                else
                    result_detail="No open ports identified"
                fi
                ;;
            service)
                local svc_cnt=0
                if [[ -f "$task_dir/services.txt" ]]; then
                    svc_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/services.txt" 2>/dev/null || true)"
                fi
                svc_cnt="${svc_cnt:-0}"
                if (( svc_cnt > 0 )); then
                    result_detail="${svc_cnt} service(s) identified"
                else
                    result_detail="Service scan complete"
                fi
                ;;
            os)
                if [[ -f "$task_dir/os.txt" && -s "$task_dir/os.txt" ]]; then
                    result_detail="$(head -n 1 "$task_dir/os.txt" 2>/dev/null || echo "OS detection complete")"
                else
                    result_detail="OS detection complete"
                fi
                ;;
            dns)
                local dns_cnt=0
                if [[ -f "$task_dir/dns_records.txt" ]]; then
                    dns_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/dns_records.txt" 2>/dev/null || true)"
                fi
                dns_cnt="${dns_cnt:-0}"
                if (( dns_cnt > 0 )); then
                    result_detail="${dns_cnt} DNS record(s) resolved"
                else
                    result_detail="DNS reconnaissance complete"
                fi
                ;;
            subdomain)
                local sub_cnt=0
                if [[ -f "$task_dir/subdomains.txt" ]]; then
                    sub_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/subdomains.txt" 2>/dev/null || true)"
                fi
                sub_cnt="${sub_cnt:-0}"
                if (( sub_cnt > 0 )); then
                    result_detail="${sub_cnt} subdomain(s) discovered"
                else
                    result_detail="No subdomains discovered"
                fi
                ;;
            directory)
                local dir_cnt=0
                if [[ -f "$task_dir/dirs_discovered.txt" ]]; then
                    dir_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/dirs_discovered.txt" 2>/dev/null || true)"
                fi
                dir_cnt="${dir_cnt:-0}"
                if (( dir_cnt > 0 )); then
                    result_detail="${dir_cnt} directories discovered"
                else
                    result_detail="No directories discovered"
                fi
                ;;
            file)
                local file_cnt=0
                if [[ -f "$task_dir/files_discovered.txt" ]]; then
                    file_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/files_discovered.txt" 2>/dev/null || true)"
                fi
                file_cnt="${file_cnt:-0}"
                if (( file_cnt > 0 )); then
                    result_detail="${file_cnt} files discovered"
                else
                    result_detail="No files discovered"
                fi
                ;;
            crawl)
                local crawl_cnt=0
                if [[ -f "$task_dir/crawled_urls.txt" ]]; then
                    crawl_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/crawled_urls.txt" 2>/dev/null || true)"
                fi
                crawl_cnt="${crawl_cnt:-0}"
                if (( crawl_cnt > 0 )); then
                    result_detail="${crawl_cnt} URLs crawled"
                else
                    result_detail="Web crawl complete"
                fi
                ;;
            endpoint)
                local ep_cnt=0
                if [[ -f "$task_dir/endpoints.txt" ]]; then
                    ep_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/endpoints.txt" 2>/dev/null || true)"
                fi
                ep_cnt="${ep_cnt:-0}"
                if (( ep_cnt > 0 )); then
                    result_detail="${ep_cnt} endpoints discovered"
                else
                    result_detail="Endpoint extraction complete"
                fi
                ;;
            *)
                result_detail="Scan complete"
                ;;
        esac

        # Determine if module is NOT APPLICABLE based on upstream prerequisites
        local is_not_applicable=false
        local skip_reason=""
        if [[ "$mod" =~ ^(ssh|ftp|http|https|smb|telnet)$ ]]; then
            local svc_out_file="$task_dir/output.txt"
            if [[ -f "$svc_out_file" ]] && grep -q -E '(Service not active|is not open|Skipping active interrogation)' "$svc_out_file" 2>/dev/null; then
                is_not_applicable=true
            elif [[ ! -s "$task_dir/open_ports.txt" && -f "$base_out/$target_slug/port/open_ports.txt" && ! -s "$base_out/$target_slug/port/open_ports.txt" ]]; then
                is_not_applicable=true
            fi
            if [[ "$is_not_applicable" == true ]]; then
                local svc_title="${mod^^}"
                [[ "$mod" == "telnet" ]] && svc_title="Telnet"
                skip_reason="No ${svc_title} service identified"
            fi
        elif [[ "$mod" =~ ^(technology|cms|waf|directory|file|vhost|crawl|endpoint|http-analysis|tls|resources|historical-urls)$ ]]; then
            local live_ep_file="$base_out/$target_slug/http-probe/live_endpoints.txt"
            if [[ -f "$live_ep_file" ]] && ! grep -q -v '^[[:space:]]*$' "$live_ep_file" 2>/dev/null; then
                is_not_applicable=true
                skip_reason="No active HTTP/HTTPS service identified"
            fi
        fi

        # Determine task status and update metrics.
        if (( exit_code == 0 )); then
            if [[ "$is_not_applicable" == true ]]; then
                task_status="NOT APPLICABLE"
                (( ENGINE_NOT_APPLICABLE_TASKS += 1 ))
            else
                task_status="COMPLETED"
                (( ENGINE_COMPLETED_TASKS += 1 ))
            fi
            if [[ "${CLI_QUIET:-false}" != true ]]; then
                local mod_title_upper="${mod_name^^}"
                if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    printf '  [%s] %s\n' "$task_idx_str" "$(term_bold "$mod_title_upper")"
                else
                    printf '  [%s] %s\n' "$task_idx_str" "$mod_title_upper"
                fi

                if [[ "$task_status" == "NOT APPLICABLE" ]]; then
                    if declare -f term_yellow >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                        printf '  %-20s: %s\n' "Status" "$(term_yellow "NOT APPLICABLE")"
                    else
                        printf '  %-20s: %s\n' "Status" "NOT APPLICABLE"
                    fi
                    printf '  %-20s: %s\n\n' "Reason" "$skip_reason"
                else
                    if declare -f term_green >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                        printf '  %-20s: %s\n' "Status" "$(term_green "COMPLETED")"
                    else
                        printf '  %-20s: %s\n' "Status" "COMPLETED"
                    fi
                    case "$mod" in
                        host)
                            local host_cnt=0
                            if [[ -f "$task_dir/hosts_live.txt" ]]; then
                                host_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/hosts_live.txt" 2>/dev/null || true)"
                            elif [[ -f "$task_dir/hosts.txt" ]]; then
                                host_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/hosts.txt" 2>/dev/null || true)"
                            fi
                            host_cnt="${host_cnt:-0}"
                            if (( host_cnt == 0 )); then
                                if [[ -f "$task_dir/output.txt" ]] && grep -q "Host is UP" "$task_dir/output.txt" 2>/dev/null; then
                                    host_cnt=1
                                elif [[ ! -f "$task_dir/hosts_live.txt" && ! -f "$task_dir/hosts.txt" ]]; then
                                    host_cnt=1
                                fi
                            fi
                            printf '  %-20s: %d\n\n' "Hosts Discovered" "$host_cnt"
                            ;;
                        port)
                            local open_cnt=0 closed_cnt=0 filtered_cnt=0 ports_scanned=0
                            if [[ -f "$task_dir/open_ports.txt" ]]; then
                                open_cnt="$(grep -c -E '^[0-9]+' "$task_dir/open_ports.txt" 2>/dev/null || true)"
                            fi
                            open_cnt="${open_cnt:-0}"
                            if [[ -f "$task_dir/nmap_port.nmap" ]]; then
                                local c_val f_val
                                c_val="$(grep -o -E '[0-9]+ closed' "$task_dir/nmap_port.nmap" 2>/dev/null | awk '{print $1}' | head -n 1 || true)"
                                f_val="$(grep -o -E '[0-9]+ filtered' "$task_dir/nmap_port.nmap" 2>/dev/null | awk '{print $1}' | head -n 1 || true)"
                                if [[ -z "$c_val" ]]; then
                                    c_val="$(grep -o -E 'All [0-9]+ scanned ports .* \(closed\)' "$task_dir/nmap_port.nmap" 2>/dev/null | awk '{print $2}' | head -n 1 || true)"
                                fi
                                if [[ -z "$f_val" ]]; then
                                    f_val="$(grep -o -E 'All [0-9]+ scanned ports .* \(filtered\)' "$task_dir/nmap_port.nmap" 2>/dev/null | awk '{print $2}' | head -n 1 || true)"
                                fi
                                closed_cnt="${c_val:-0}"
                                filtered_cnt="${f_val:-0}"
                            fi
                            ports_scanned=$(( open_cnt + closed_cnt + filtered_cnt ))
                            if (( ports_scanned == 0 )); then
                                local ports_val="${CONFIG_EFFECTIVE_PORTS:-}"
                                case "$ports_val" in
                                    full|all|all-ports|all_ports|1-65535|65535|-p-)
                                        ports_scanned=65535
                                        closed_cnt=$(( ports_scanned - open_cnt ))
                                        ;;
                                    top-100|top100|100)
                                        ports_scanned=100
                                        closed_cnt=$(( ports_scanned - open_cnt ))
                                        ;;
                                    top-1000|top1000|1000)
                                        ports_scanned=1000
                                        closed_cnt=$(( ports_scanned - open_cnt ))
                                        ;;
                                    "")
                                        if [[ "${CONFIG_EFFECTIVE_PROFILE:-}" =~ ^(full|all)$ ]]; then
                                            ports_scanned=65535
                                            closed_cnt=$(( ports_scanned - open_cnt ))
                                        elif [[ "${CONFIG_EFFECTIVE_PROFILE:-}" =~ ^(fast|quick)$ ]]; then
                                            ports_scanned=100
                                            closed_cnt=$(( ports_scanned - open_cnt ))
                                        else
                                            ports_scanned=1000
                                            closed_cnt=$(( ports_scanned - open_cnt ))
                                        fi
                                        ;;
                                    *)
                                        ports_scanned="$(tr ',' '\n' <<< "$ports_val" | grep -c -v '^[[:space:]]*$' || true)"
                                        closed_cnt=$(( ports_scanned - open_cnt ))
                                        ;;
                                esac
                            fi
                            printf '  %-20s: %d\n' "Ports Scanned" "$ports_scanned"
                            printf '  %-20s: %d\n' "Open" "$open_cnt"
                            if (( open_cnt > 0 )) && [[ -f "$task_dir/open_ports.txt" ]]; then
                                local o_ports
                                o_ports="$(grep -E '^[0-9]+' "$task_dir/open_ports.txt" 2>/dev/null | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')"
                                [[ -n "$o_ports" ]] && printf '  %-20s: %s\n' "Open Ports" "$o_ports"
                            fi
                            printf '  %-20s: %d\n' "Closed" "$closed_cnt"
                            printf '  %-20s: %d\n\n' "Filtered" "$filtered_cnt"
                            ;;
                        service)
                            local svc_cnt=0
                            if [[ -f "$task_dir/services.txt" ]]; then
                                svc_cnt="$(grep -c -v '^[[:space:]]*$' "$task_dir/services.txt" 2>/dev/null || true)"
                            fi
                            svc_cnt="${svc_cnt:-0}"
                            printf '  %-20s: %d\n' "Services Identified" "$svc_cnt"
                            if (( svc_cnt > 0 )) && [[ -f "$task_dir/services.txt" ]]; then
                                local s_line
                                while IFS= read -r s_line || [[ -n "$s_line" ]]; do
                                    [[ -z "$s_line" ]] && continue
                                    local s_p s_st s_name s_ver
                                    read -r s_p s_st s_name s_ver <<< "$s_line"
                                    local s_desc="${s_p} (${s_name}${s_ver:+ - $s_ver})"
                                    printf '    - %s\n' "$s_desc"
                                done < "$task_dir/services.txt"
                            fi
                            printf '\n'
                            ;;
                        os)
                            local os_res="No OS match identified"
                            if [[ -f "$task_dir/os.txt" && -s "$task_dir/os.txt" ]]; then
                                os_res="$(head -n 1 "$task_dir/os.txt" 2>/dev/null || echo "No OS match identified")"
                            elif [[ -f "$task_dir/os_info.txt" && -s "$task_dir/os_info.txt" ]]; then
                                os_res="$(head -n 1 "$task_dir/os_info.txt" 2>/dev/null || echo "No OS match identified")"
                            elif [[ -f "$task_dir/os_detection.txt" && -s "$task_dir/os_detection.txt" ]]; then
                                os_res="$(head -n 1 "$task_dir/os_detection.txt" 2>/dev/null || echo "No OS match identified")"
                            fi
                            printf '  %-20s: %s\n\n' "Result" "$os_res"
                            ;;
                        ssh)
                            local ssh_b=""
                            if [[ -f "$task_dir/ssh_banner.txt" && -s "$task_dir/ssh_banner.txt" ]]; then
                                ssh_b="$(head -n 1 "$task_dir/ssh_banner.txt" 2>/dev/null || true)"
                            elif [[ -f "$task_dir/output.txt" ]]; then
                                ssh_b="$(grep -E '(Identification Banner|Software Identity)' "$task_dir/output.txt" 2>/dev/null | head -n 1 | sed 's/.*: //' || true)"
                            fi
                            if [[ -n "$ssh_b" ]]; then
                                printf '  %-20s: %s\n\n' "Banner" "$ssh_b"
                            else
                                printf '  %-20s: %s\n\n' "Result" "SSH enumeration complete"
                            fi
                            ;;
                        http|https)
                            local h_srv="" h_title=""
                            if [[ -f "$task_dir/output.txt" ]]; then
                                h_srv="$(grep 'Server Banner' "$task_dir/output.txt" 2>/dev/null | head -n 1 | sed 's/.*: //' || true)"
                                h_title="$(grep 'HTML Page Title' "$task_dir/output.txt" 2>/dev/null | head -n 1 | sed 's/.*: //' || true)"
                            fi
                            if [[ -n "$h_srv" ]]; then
                                printf '  %-20s: %s\n' "Server" "$h_srv"
                            fi
                            if [[ -n "$h_title" ]]; then
                                printf '  %-20s: %s\n' "Page Title" "$h_title"
                            fi
                            if [[ -z "$h_srv" && -z "$h_title" ]]; then
                                printf '  %-20s: %s\n' "Result" "${mod^^} enumeration complete"
                            fi
                            printf '\n'
                            ;;
                        ftp)
                            local ftp_b=""
                            if [[ -f "$task_dir/ftp_banner.txt" && -s "$task_dir/ftp_banner.txt" ]]; then
                                ftp_b="$(head -n 1 "$task_dir/ftp_banner.txt" 2>/dev/null || true)"
                            elif [[ -f "$task_dir/output.txt" ]]; then
                                ftp_b="$(grep -E '(Banner|FTP Server)' "$task_dir/output.txt" 2>/dev/null | head -n 1 | sed 's/.*: //' || true)"
                            fi
                            if [[ -n "$ftp_b" ]]; then
                                printf '  %-20s: %s\n\n' "Banner" "$ftp_b"
                            else
                                printf '  %-20s: %s\n\n' "Result" "FTP enumeration complete"
                            fi
                            ;;
                        smb)
                            local smb_res=""
                            if [[ -f "$task_dir/output.txt" ]]; then
                                smb_res="$(grep -E '(OS|Dialect|Workgroup)' "$task_dir/output.txt" 2>/dev/null | head -n 1 | sed 's/.*: //' || true)"
                            fi
                            if [[ -n "$smb_res" ]]; then
                                printf '  %-20s: %s\n\n' "SMB Details" "$smb_res"
                            else
                                printf '  %-20s: %s\n\n' "Result" "SMB enumeration complete"
                            fi
                            ;;
                        telnet)
                            local telnet_b=""
                            if [[ -f "$task_dir/telnet_banner.txt" && -s "$task_dir/telnet_banner.txt" ]]; then
                                telnet_b="$(head -n 1 "$task_dir/telnet_banner.txt" 2>/dev/null || true)"
                            fi
                            if [[ -n "$telnet_b" ]]; then
                                printf '  %-20s: %s\n\n' "Banner" "$telnet_b"
                            else
                                printf '  %-20s: %s\n\n' "Result" "Telnet enumeration complete"
                            fi
                            ;;
                        http-probe)
                            local p_urls=""
                            if [[ -f "$task_dir/live_web.txt" ]]; then
                                p_urls="$(grep -v '^[[:space:]]*$' "$task_dir/live_web.txt" 2>/dev/null | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')"
                            fi
                            if [[ -n "$p_urls" ]]; then
                                printf '  %-20s: %s\n\n' "Live Web Services" "$p_urls"
                            else
                                printf '  %-20s: %s\n\n' "Result" "No active web services discovered"
                            fi
                            ;;
                        technology)
                            local tech_str=""
                            if [[ -f "$task_dir/technologies.txt" && -s "$task_dir/technologies.txt" ]]; then
                                tech_str="$(awk -F'\t' '{print $1}' "$task_dir/technologies.txt" 2>/dev/null | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')"
                            fi
                            if [[ -n "$tech_str" ]]; then
                                printf '  %-20s: %s\n\n' "Technologies" "$tech_str"
                            else
                                printf '  %-20s: %s\n\n' "Technologies" "None detected"
                            fi
                            ;;
                        cms)
                            local cms_str="None"
                            if [[ -f "$task_dir/cms_detected.txt" && -s "$task_dir/cms_detected.txt" ]]; then
                                cms_str="$(head -n 1 "$task_dir/cms_detected.txt" 2>/dev/null || echo "None")"
                            fi
                            printf '  %-20s: %s\n\n' "CMS Detected" "$cms_str"
                            ;;
                        waf)
                            local waf_str="None (Direct origin)"
                            if [[ -f "$task_dir/waf_detected.txt" && -s "$task_dir/waf_detected.txt" ]]; then
                                waf_str="$(head -n 1 "$task_dir/waf_detected.txt" 2>/dev/null || echo "None (Direct origin)")"
                            fi
                            printf '  %-20s: %s\n\n' "WAF Detected" "$waf_str"
                            ;;
                        http-analysis)
                            local mis_cnt=0
                            if [[ -f "$task_dir/output.txt" ]]; then
                                mis_cnt="$(grep -c 'Missing Header:' "$task_dir/output.txt" 2>/dev/null || true)"
                            fi
                            mis_cnt="${mis_cnt:-0}"
                            if (( mis_cnt > 0 )); then
                                printf '  %-20s: %d missing security header(s)\n\n' "Security Posture" "$mis_cnt"
                            else
                                printf '  %-20s: %s\n\n' "Security Posture" "Analysis complete"
                            fi
                            ;;
                        tls)
                            local c_subj=""
                            if [[ -f "$task_dir/cert_info.txt" ]]; then
                                c_subj="$(grep -E '(Common Name|Subject:)' "$task_dir/cert_info.txt" 2>/dev/null | head -n 1 | sed 's/.*: //' || true)"
                            fi
                            if [[ -n "$c_subj" ]]; then
                                printf '  %-20s: %s\n\n' "Certificate" "$c_subj"
                            else
                                printf '  %-20s: %s\n\n' "Result" "TLS audit complete"
                            fi
                            ;;
                        *)
                            printf '  %-20s: %s\n\n' "Result" "$result_detail"
                            ;;
                    esac
                fi
            fi
            if declare -f _log_write_file >/dev/null 2>&1; then
                _log_write_file "INFO" "Module '$mod' completed for target '$target' (${duration}s)"
            fi
        elif (( exit_code == 124 )); then
            task_status="TIMEOUT"
            (( ENGINE_TIMEOUT_TASKS += 1 ))
            overall_status=1
            if [[ "${CLI_QUIET:-false}" != true ]]; then
                local mod_title_upper="${mod_name^^}"
                if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    printf '  [%s] %s\n' "$task_idx_str" "$(term_bold "$mod_title_upper")"
                    printf '  %-20s: %s\n' "Status" "$(term_yellow "TIMEOUT")"
                else
                    printf '  [%s] %s\n' "$task_idx_str" "$mod_title_upper"
                    printf '  %-20s: %s\n' "Status" "TIMEOUT"
                fi
                printf '  %-20s: %s\n\n' "Reason" "Execution timed out after ${timeout_sec}s"
            fi
            if declare -f _log_write_file >/dev/null 2>&1; then
                _log_write_file "WARN" "Module '$mod' timed out after ${timeout_sec}s for target '$target'"
            fi
        else
            task_status="FAILED"
            (( ENGINE_FAILED_TASKS += 1 ))
            overall_status=1
            if [[ "${CLI_QUIET:-false}" != true ]]; then
                local mod_title_upper="${mod_name^^}"
                if declare -f term_bold >/dev/null 2>&1 && declare -f term_is_color_enabled >/dev/null 2>&1 && term_is_color_enabled; then
                    printf '  [%s] %s\n' "$task_idx_str" "$(term_bold "$mod_title_upper")"
                    printf '  %-20s: %s\n' "Status" "$(term_red "FAILED")"
                else
                    printf '  [%s] %s\n' "$task_idx_str" "$mod_title_upper"
                    printf '  %-20s: %s\n' "Status" "FAILED"
                fi
                printf '  %-20s: %s\n\n' "Reason" "Module execution failed with exit code $exit_code"
            fi
            if declare -f _log_write_file >/dev/null 2>&1; then
                _log_write_file "ERROR" "Module '$mod' failed with exit code $exit_code for target '$target'"
            fi
        fi

        ENGINE_TASK_STATUS+=("$task_status")
        ENGINE_TASK_DURATION+=("$duration")
        ENGINE_TASK_EXIT_CODE+=("$exit_code")
        ENGINE_TASK_OUTPUT_DIR+=("$task_dir")
    done

    # Teardown signal handlers upon execution completion.
    engine_teardown_traps

    return "$overall_status"
}
