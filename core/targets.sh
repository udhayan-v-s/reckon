#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Target processing
#

# ShellCheck marker: TARGET_* variables and TARGET_*_ERROR are consumed
# by target_prepare (called from core/main.sh) and by downstream
# execution phases (M6+).
# shellcheck disable=SC2034

# Initialize target-processing state.
target_init() {

    TARGET_VALUE=()
    TARGET_TYPE=()
    TARGET_MODE=()

    TARGET_ERROR=""
    TARGET_WARNINGS=()

    TARGET_PREPARED=false

    return 0
}

# Validate a single candidate target string.
#
# Arguments:
#   $1 - candidate target string
#   $2 - selected scan mode: "network", "web", or "both"
#
# On success:
#   TARGET_VALIDATED_VALUE  = normalized target
#   TARGET_VALIDATED_TYPE   = one of: ipv4 ipv4_cidr ipv4_range hostname domain url_http url_https
#   TARGET_VALIDATED_MODE   = "network", "web", or "both"
#   returns 0
#
# On failure:
#   TARGET_ERROR = reason (no target prefix; caller adds context)
#   returns 1
target_validate() {

    local input="$1"
    local scan_mode="$2"
    local normalized
    local type

    TARGET_VALIDATED_VALUE=""
    TARGET_VALIDATED_TYPE=""
    TARGET_VALIDATED_MODE=""
    TARGET_ERROR=""

    # Reject empty input early.
    if [[ -z "$input" ]]; then
        TARGET_ERROR="empty target"
        return 1
    fi

    # Reject IPv6 early (unsupported in v1.0).
    if [[ "$input" == *:* && "$input" != *"://"* ]]; then
        TARGET_ERROR="IPv6 is not supported: $input"
        return 1
    fi

    # --- URL branch ---
    # Detect URL by scheme presence, case-insensitively. Extract the scheme
    # prefix up to "://" and lowercase it before comparing.
    local scheme_prefix=""
    if [[ "$input" == *"://"* ]]; then
        scheme_prefix="${input%%://*}"
        scheme_prefix="${scheme_prefix,,}"
    fi

    if [[ "$scheme_prefix" == "http" || "$scheme_prefix" == "https" ]]; then
        if ! target_validate_url "$input"; then
            return 1
        fi

        type="$TARGET_URL_TYPE"
        normalized="$TARGET_URL_VALUE"

        # URLs are web-only.
        if [[ "$scan_mode" == "network" ]]; then
            TARGET_ERROR="URL is incompatible with network scan mode: $normalized"
            return 1
        fi

        TARGET_VALIDATED_VALUE="$normalized"
        TARGET_VALIDATED_TYPE="$type"
        TARGET_VALIDATED_MODE="web"
        return 0
    fi

    # Reject bare schemes without // (e.g. http:example.com).
    if [[ "$input" == *"://"* ]]; then
        TARGET_ERROR="unsupported URL scheme: $input"
        return 1
    fi

    # --- IPv4 range branch ---
    if [[ "$input" == *-* ]]; then
        if ! target_validate_range "$input"; then
            return 1
        fi

        # Ranges are network-only.
        if [[ "$scan_mode" == "web" ]]; then
            TARGET_ERROR="IPv4 range is incompatible with web scan mode: $TARGET_RANGE_VALUE"
            return 1
        fi

        TARGET_VALIDATED_VALUE="$TARGET_RANGE_VALUE"
        TARGET_VALIDATED_TYPE="ipv4_range"
        TARGET_VALIDATED_MODE="network"
        return 0
    fi

    # --- IPv4 CIDR branch ---
    if [[ "$input" == */* ]]; then
        if ! target_validate_cidr "$input"; then
            return 1
        fi

        # CIDR is network-only.
        if [[ "$scan_mode" == "web" ]]; then
            TARGET_ERROR="IPv4 CIDR is incompatible with web scan mode: $TARGET_CIDR_VALUE"
            return 1
        fi

        TARGET_VALIDATED_VALUE="$TARGET_CIDR_VALUE"
        TARGET_VALIDATED_TYPE="ipv4_cidr"
        TARGET_VALIDATED_MODE="network"
        return 0
    fi

    # --- IPv4 address branch ---
    if target_is_ipv4 "$input"; then
        if ! target_validate_ipv4 "$input"; then
            return 1
        fi

        # Bare IPv4 is compatible with both modes.
        TARGET_VALIDATED_VALUE="$TARGET_IPV4_VALUE"
        TARGET_VALIDATED_TYPE="ipv4"
        TARGET_VALIDATED_MODE="both"
        return 0
    fi

    # --- Hostname / domain branch ---
    if ! target_validate_name "$input"; then
        return 1
    fi

    TARGET_VALIDATED_VALUE="$TARGET_NAME_VALUE"
    TARGET_VALIDATED_TYPE="$TARGET_NAME_TYPE"
    TARGET_VALIDATED_MODE="both"
    return 0
}

# Return 0 if the string looks like a dotted-quad candidate (four
# dot-separated segments, all characters digits). Does not validate ranges.
target_is_ipv4() {

    local input="$1"
    local IFS='.'
    local -a segments

    # Reject if any non-digit, non-dot character is present.
    if [[ ! "$input" =~ ^[0-9.]+$ ]]; then
        return 1
    fi

    # Split into segments.
    read -ra segments <<< "$input"

    if [[ ${#segments[@]} -ne 4 ]]; then
        return 1
    fi

    return 0
}

# Validate a strict dotted-quad IPv4 address. Rejects leading zeros.
target_validate_ipv4() {

    local input="$1"
    local IFS='.'
    local -a segments
    local segment

    read -ra segments <<< "$input"

    for segment in "${segments[@]}"; do

        # Reject empty segment (e.g. "1..2.3").
        if [[ -z "$segment" ]]; then
            TARGET_ERROR="invalid IPv4 address: $input"
            return 1
        fi

        # Reject leading zeros (except the single-character "0").
        if [[ ${#segment} -gt 1 && "$segment" == 0* ]]; then
            TARGET_ERROR="IPv4 segment has leading zeros: $input"
            return 1
        fi

        # Range check 0-255.
        if (( segment > 255 )); then
            TARGET_ERROR="IPv4 segment out of range: $input"
            return 1
        fi
    done

    TARGET_IPV4_VALUE="$input"
    return 0
}

# Validate a CIDR string a.b.c.d/N with N in 0-32.
target_validate_cidr() {

    local input="$1"
    local ip="${input%/*}"
    local prefix="${input#*/}"

    if [[ -z "$prefix" ]] || [[ ! "$prefix" =~ ^[0-9]+$ ]]; then
        TARGET_ERROR="invalid CIDR prefix: $input"
        return 1
    fi

    if (( prefix > 32 )); then
        TARGET_ERROR="CIDR prefix out of range (0-32): $input"
        return 1
    fi

    if ! target_is_ipv4 "$ip" || ! target_validate_ipv4 "$ip" 2>/dev/null; then
        TARGET_ERROR="invalid CIDR address: $input"
        return 1
    fi

    TARGET_CIDR_VALUE="$input"
    return 0
}

# Validate a strict A.B.C.D-A.B.C.D range.
target_validate_range() {

    local input="$1"
    local start="${input%-*}"
    local end="${input#*-}"

    # Reject if start or end is empty.
    if [[ -z "$start" ]] || [[ -z "$end" ]]; then
        TARGET_ERROR="invalid range (empty endpoint): $input"
        return 1
    fi

    # Reject if either endpoint is not IPv4.
    if ! target_is_ipv4 "$start"; then
        TARGET_ERROR="invalid range start: $input"
        return 1
    fi

    if ! target_is_ipv4 "$end"; then
        TARGET_ERROR="invalid range end: $input"
        return 1
    fi

    if ! target_validate_ipv4 "$start" 2>/dev/null; then
        TARGET_ERROR="invalid range start: $input"
        return 1
    fi

    if ! target_validate_ipv4 "$end" 2>/dev/null; then
        TARGET_ERROR="invalid range end: $input"
        return 1
    fi

    TARGET_RANGE_VALUE="$input"
    return 0
}

# Validate a hostname or domain. Normalizes to lowercase.
target_validate_name() {

    local input="$1"
    local normalized="${input,,}"
    local label
    local IFS='.'
    local -a labels
    local label_count

    # Reject trailing dot (FQDN root).
    if [[ "$normalized" == *. ]]; then
        TARGET_ERROR="trailing dot not permitted: $input"
        return 1
    fi

    # Reject empty.
    if [[ -z "$normalized" ]]; then
        TARGET_ERROR="empty hostname"
        return 1
    fi

    # Reject if it contains characters not valid in hostnames.
    # Allowed: a-z 0-9 . - (labels may contain hyphens internally).
    if [[ ! "$normalized" =~ ^[a-z0-9.-]+$ ]]; then
        TARGET_ERROR="invalid hostname characters: $input"
        return 1
    fi

    # Reject leading or trailing hyphen in any label.
    read -ra labels <<< "$normalized"
    label_count=${#labels[@]}

    for label in "${labels[@]}"; do

        if [[ -z "$label" ]]; then
            TARGET_ERROR="empty hostname label: $input"
            return 1
        fi

        if [[ "$label" == -* || "$label" == *- ]]; then
            TARGET_ERROR="hostname label may not begin or end with a hyphen: $input"
            return 1
        fi

        if [[ ${#label} -gt 63 ]]; then
            TARGET_ERROR="hostname label exceeds 63 characters: $input"
            return 1
        fi
    done

    # Very small heuristic to distinguish "hostname" from "domain":
    # a name is treated as a domain if it contains at least one dot.
    if [[ "$normalized" == *.* ]]; then
        TARGET_NAME_TYPE="domain"
    else
        TARGET_NAME_TYPE="hostname"
    fi

    TARGET_NAME_VALUE="$normalized"
    return 0
}

# Validate a URL. Preserves path and query case; normalizes scheme and host.
target_validate_url() {

    local input="$1"
    local scheme
    local rest
    local authority
    local host_port
    local host
    local port
    local path
    local normalized
    local scheme_part

    # Normalize the scheme case before branching.
    scheme_part="${input%%://*}"
    scheme_part="${scheme_part,,}"

    if [[ "$scheme_part" == "http" ]]; then
        scheme="http"
        rest="${input#*://}"
    elif [[ "$scheme_part" == "https" ]]; then
        scheme="https"
        rest="${input#*://}"
    else
        TARGET_ERROR="URL must start with http:// or https://: $input"
        return 1
    fi

    # Reject fragment.
    if [[ "$rest" == *"#"* ]]; then
        TARGET_ERROR="URL fragments are not permitted: $input"
        return 1
    fi

    # Split authority from path/query.
    if [[ "$rest" == */* ]]; then
        authority="${rest%%/*}"
        path="/${rest#*/}"
    elif [[ "$rest" == *\?* ]]; then
        authority="${rest%%\?*}"
        path="?${rest#*\?}"
    else
        authority="$rest"
        path=""
    fi

    # Split host from port.
    if [[ "$authority" == *:* ]]; then
        host="${authority%:*}"
        port="${authority##*:}"

        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            TARGET_ERROR="invalid port in URL: $input"
            return 1
        fi

        if (( port < 1 || port > 65535 )); then
            TARGET_ERROR="URL port out of range: $input"
            return 1
        fi
    else
        host="$authority"
        port=""
    fi

    if [[ -z "$host" ]]; then
        TARGET_ERROR="URL host is empty: $input"
        return 1
    fi

    # Lowercase the host.
    host="${host,,}"

    # Validate the host portion as a name or IPv4.
    if target_is_ipv4 "$host"; then
        if ! target_validate_ipv4 "$host" 2>/dev/null; then
            TARGET_ERROR="invalid IPv4 host in URL: $input"
            return 1
        fi
    else
        if ! target_validate_name "$host" 2>/dev/null; then
            TARGET_ERROR="invalid host in URL: $input"
            return 1
        fi
    fi

    # Rebuild host_port from the lowercased host.
    if [[ -n "$port" ]]; then
        host_port="${host}:${port}"
    else
        host_port="$host"
    fi

    # Rebuild normalized URL.
    normalized="${scheme}://${host_port}${path}"

    TARGET_URL_VALUE="$normalized"
    if [[ "$scheme" == "http" ]]; then
        TARGET_URL_TYPE="url_http"
    else
        TARGET_URL_TYPE="url_https"
    fi

    return 0
}

# Process a targets file per the frozen specification (section 10.6).
#
# Rules:
#   - One target per line.
#   - Blank lines ignored.
#   - Full-line comments (# at start of trimmed line) ignored.
#   - Whitespace trimmed from each line.
#   - Invalid targets skipped with per-line warnings.
#   - Duplicates skipped (post-normalization).
#   - Inline comments NOT supported (a line with "#" mid-line is treated
#     as-is and will typically fail validation).
#
# Arguments:
#   $1 - path to targets file
#   $2 - scan mode ("network", "web", or "both")
#
# On success:
#   TARGET_VALUE, TARGET_TYPE, TARGET_MODE extended.
#   TARGET_WARNINGS receives per-line messages (line numbers + reason).
#   returns 0 (even if some lines were skipped, as long as ≥1 usable target).
#
# On failure:
#   TARGET_ERROR = reason
#   returns 1
target_process_file() {

    local file="$1"
    local scan_mode="$2"
    local line
    local line_number=0
    local trimmed
    local valid_count=0
    local existing
    local duplicate
    local idx

    # File must exist and be readable.
    if [[ ! -f "$file" ]]; then
        TARGET_ERROR="targets file does not exist or is not a regular file: $file"
        return 1
    fi

    if [[ ! -r "$file" ]]; then
        TARGET_ERROR="targets file is not readable: $file"
        return 1
    fi

    # Read the file line by line.
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_number++))

        # Trim leading and trailing whitespace.
        trimmed="$line"
        trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"

        # Skip blank lines.
        if [[ -z "$trimmed" ]]; then
            continue
        fi

        # Skip full-line comments.
        if [[ "$trimmed" == "#"* ]]; then
            continue
        fi

        # Validate the line.
        if ! target_validate "$trimmed" "$scan_mode"; then
            TARGET_WARNINGS+=("$file:$line_number: $TARGET_ERROR (input: $trimmed)")
            continue
        fi

        # Check for duplicate after normalization.
        duplicate=false
        for idx in "${!TARGET_VALUE[@]}"; do
            if [[ "${TARGET_VALUE[$idx]}" == "$TARGET_VALIDATED_VALUE" ]]; then
                duplicate=true
                break
            fi
        done

        if [[ "$duplicate" == true ]]; then
            # Silent skip; duplicate of an already-accepted target.
            continue
        fi

        TARGET_VALUE+=("$TARGET_VALIDATED_VALUE")
        TARGET_TYPE+=("$TARGET_VALIDATED_TYPE")
        TARGET_MODE+=("$TARGET_VALIDATED_MODE")

        ((valid_count++))
    done < "$file"

    # Require at least one usable target.
    if (( valid_count == 0 )); then
        TARGET_ERROR="targets file contains no usable targets: $file"
        return 1
    fi

    return 0
}

# Prepare the target-processing pipeline. Called from core/main.sh
# after config_apply_cli. Populates TARGET_VALUE, TARGET_TYPE, TARGET_MODE.
#
# Reads:  CONFIG_EFFECTIVE_TARGET, CONFIG_EFFECTIVE_TARGETS_FILE,
#         CONFIG_EFFECTIVE_NETWORK, CONFIG_EFFECTIVE_WEB
# Sets:   TARGET_VALUE, TARGET_TYPE, TARGET_MODE, TARGET_WARNINGS, TARGET_ERROR
# Returns: 0 on success (all valid targets collected), 1 on fatal error.
target_prepare() {

    local scan_mode
    local candidate

    target_init

    # Determine selected scan mode.
    if [[ "$CONFIG_EFFECTIVE_NETWORK" == "true" && "$CONFIG_EFFECTIVE_WEB" == "true" ]]; then
        scan_mode="both"
    elif [[ "$CONFIG_EFFECTIVE_NETWORK" == "true" ]]; then
        scan_mode="network"
    elif [[ "$CONFIG_EFFECTIVE_WEB" == "true" ]]; then
        scan_mode="web"
    elif declare -p CONFIG_EFFECTIVE_MODULES >/dev/null 2>&1 && (( ${#CONFIG_EFFECTIVE_MODULES[@]} > 0 )); then
        scan_mode="both"
    else
        # No scan mode selected — nothing to prepare. Not an error;
        # the CLI layer already requires a target when scanning.
        TARGET_PREPARED=true
        return 0
    fi

    # Single target path.
    if [[ -n "$CONFIG_EFFECTIVE_TARGET" ]]; then
        candidate="$CONFIG_EFFECTIVE_TARGET"

        if ! target_validate "$candidate" "$scan_mode"; then
            TARGET_ERROR="Target '$candidate': $TARGET_ERROR"
            return 1
        fi

        TARGET_VALUE+=("$TARGET_VALIDATED_VALUE")
        TARGET_TYPE+=("$TARGET_VALIDATED_TYPE")
        TARGET_MODE+=("$TARGET_VALIDATED_MODE")

        TARGET_PREPARED=true
        return 0
    fi

    # Targets-file path.
    if [[ -n "$CONFIG_EFFECTIVE_TARGETS_FILE" ]]; then
        if ! target_process_file "$CONFIG_EFFECTIVE_TARGETS_FILE" "$scan_mode"; then
            return 1
        fi

        TARGET_PREPARED=true
        return 0
    fi
}