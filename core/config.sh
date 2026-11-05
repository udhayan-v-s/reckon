#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Configuration management
#

# Configuration state is consumed by other application components
# (config_apply, config_apply_cli, execution phases) and by core/main.sh.
# shellcheck disable=SC2034

# Initialize configuration state.
config_init() {

    CONFIG_FILE=""
    CONFIG_JSON=""
    CONFIG_LOADED=false
    CONFIG_ERROR=""

    # Effective configuration state. Populated by config_apply.
    CONFIG_EFFECTIVE_OUTPUT_DIR=""
    CONFIG_EFFECTIVE_COLOR=""
    CONFIG_EFFECTIVE_MODULES=()
    CONFIG_EFFECTIVE_EXCLUDE_MODULES=()
    CONFIG_EFFECTIVE_PROFILE=""
    CONFIG_EFFECTIVE_PORTS=""
    CONFIG_EFFECTIVE_WORDLIST=""
    CONFIG_EFFECTIVE_TIMEOUT=""
    CONFIG_EFFECTIVE_THREADS=""
    CONFIG_EFFECTIVE_RATE_LIMIT=""
    CONFIG_EFFECTIVE_RETRIES=""
    CONFIG_EFFECTIVE_FORMATS=()
    CONFIG_EFFECTIVE_NO_REPORT=""
    CONFIG_EFFECTIVE_LOG_FILE=""
    CONFIG_EFFECTIVE_TARGET=""
    CONFIG_EFFECTIVE_TARGETS_FILE=""
    CONFIG_EFFECTIVE_NETWORK=false
    CONFIG_EFFECTIVE_WEB=false

    return 0
}

# Check dependencies required for configuration loading.
config_check_dependencies() {

    # A configuration file is optional.
    # No config file means jq is not required.
    if [[ -z "$CONFIG_FILE" ]]; then
        return 0
    fi

    # Check whether jq is available.
    if ! command -v jq >/dev/null 2>&1; then
        CONFIG_ERROR="jq is required to load the configuration file."
        return 1
    fi

    return 0
}

# Validate the configuration file.
config_validate_file() {

    # Configuration is optional.
    if [[ -z "$CONFIG_FILE" ]]; then
        return 0
    fi

    # Check whether the file exists.
    if [[ ! -f "$CONFIG_FILE" ]]; then
        CONFIG_ERROR="Configuration file does not exist: $CONFIG_FILE"
        return 1
    fi

    # Check whether the file is readable.
    if [[ ! -r "$CONFIG_FILE" ]]; then
        CONFIG_ERROR="Configuration file is not readable: $CONFIG_FILE"
        return 1
    fi

    return 0
}

# Load the configuration file into memory.
config_load() {

    local parsed_config

    # Reset the previous loading state.
    CONFIG_JSON=""
    CONFIG_LOADED=false
    CONFIG_ERROR=""

    # Configuration is optional. Apply schema defaults when no file is supplied.
    if [[ -z "$CONFIG_FILE" ]]; then
        if ! config_apply; then
            return 1
        fi
        return 0
    fi

    # Validate the configuration file.
    if ! config_validate_file; then
        return 1
    fi

    # Check required dependencies.
    if ! config_check_dependencies; then
        return 1
    fi

    # Parse exactly one JSON document.
    if ! parsed_config=$(jq -c -s '
        if length == 1 then
            .[0]
        else
            error("Expected exactly one JSON document")
        end
    ' "$CONFIG_FILE" 2>/dev/null); then
        CONFIG_ERROR="Invalid JSON configuration file: $CONFIG_FILE"
        return 1
    fi

    # Store the parsed configuration so validation can inspect it.
    CONFIG_JSON="$parsed_config"

    # Validate the parsed configuration against the frozen schema.
    if ! config_validate_schema; then
        CONFIG_JSON=""
        return 1
    fi

    # Validate configuration values and normalize formats.
    if ! config_validate_values; then
        CONFIG_JSON=""
        return 1
    fi

    # Mark the configuration as loaded before applying it, so that
    # config_apply sees CONFIG_LOADED=true and applies the file values.
    CONFIG_LOADED=true

    # Apply effective values.
    if ! config_apply; then
        CONFIG_LOADED=false
        CONFIG_JSON=""
        return 1
    fi

    return 0
}

# Validate the parsed configuration against the frozen schema.
# Structural validation only. Semantic validation belongs to M3.4.
config_validate_schema() {

    local violations
    local first_violation

    # Configuration is optional. Nothing to validate.
    if [[ "$CONFIG_LOADED" == false && -z "$CONFIG_JSON" ]]; then
        return 0
    fi

    # A loaded schema cannot be validated without a JSON body.
    if [[ -z "$CONFIG_JSON" ]]; then
        CONFIG_ERROR="Configuration schema error: configuration is empty"
        return 1
    fi

    # Collect all structural violations. jq returns an array of
    # {"path": "...", "reason": "..."} objects. An empty array means valid.
    if ! violations=$(jq -c '
        # Record a violation in the accumulator.
        def record($path; $reason):
            . + [{"path": $path, "reason": $reason}];

        # Return the JSON type name of the value as a string.
        def json_type:
            if . == null then "null"
            elif type == "boolean" then "boolean"
            elif type == "number" then
                (if (. == floor) then "integer" else "number" end)
            else type
            end;

        # Check an object for unexpected keys against an allowed list.
        # The accumulator (.) is preserved; the object to inspect is $obj.
        def check_unknown_keys($obj; $section; $allowed):
            ($obj | keys | map(select(. as $k | $allowed | index($k) | not))) as $extra
            | if ($extra | length) > 0
              then record($section + "." + $extra[0]; "unknown key")
              else .
              end;

        . as $root
        | ([])

        # Top-level must be an object.
        | if ($root | type) != "object"
          then record("$"; "expected object, received " + ($root | json_type))
          else .
          end

        # schema_version check (only if root is an object).
        | if ($root | type) == "object" then
              if ($root | has("schema_version") | not)
              then record("schema_version"; "missing")
              elif ($root.schema_version | json_type) != "integer"
              then record("schema_version"; "expected integer, received " + ($root.schema_version | json_type))
              elif $root.schema_version != 1
              then record("schema_version"; "expected 1, received " + ($root.schema_version | tostring))
              else .
              end
          else .
          end

        # Top-level unknown keys.
        | if ($root | type) == "object" then
              check_unknown_keys($root; "$top"; ["schema_version", "general", "scanning", "execution", "reporting"])
          else .
          end

        # general section.
        | if ($root | type) == "object" and ($root | has("general")) then
              if ($root.general | type) != "object"
              then record("general"; "expected object, received " + ($root.general | json_type))
              else
                  check_unknown_keys($root.general; "general"; ["output_dir", "color"])
                  | if ($root.general | has("output_dir")) and ($root.general.output_dir | type) != "string"
                    then record("general.output_dir"; "expected string, received " + ($root.general.output_dir | json_type))
                    else .
                    end
                  | if ($root.general | has("color")) then
                        if ($root.general.color | type) != "string"
                        then record("general.color"; "expected string, received " + ($root.general.color | json_type))
                        elif (["auto", "always", "never"] | index($root.general.color)) == null
                        then record("general.color"; "expected one of auto, always, never; received " + ($root.general.color | tostring))
                        else .
                        end
                    else .
                    end
              end
          else .
          end

        # scanning section.
        | if ($root | type) == "object" and ($root | has("scanning")) then
              if ($root.scanning | type) != "object"
              then record("scanning"; "expected object, received " + ($root.scanning | json_type))
              else
                  check_unknown_keys($root.scanning; "scanning"; ["modules", "exclude_modules", "profile", "ports", "wordlist"])
                  | if ($root.scanning | has("modules")) then
                        if ($root.scanning.modules | type) != "array"
                        then record("scanning.modules"; "expected array, received " + ($root.scanning.modules | json_type))
                        elif ($root.scanning.modules | map(type) | map(select(. != "string")) | length) > 0
                        then record("scanning.modules"; "array elements must be strings")
                        else .
                        end
                    else .
                    end
                  | if ($root.scanning | has("exclude_modules")) then
                        if ($root.scanning.exclude_modules | type) != "array"
                        then record("scanning.exclude_modules"; "expected array, received " + ($root.scanning.exclude_modules | json_type))
                        elif ($root.scanning.exclude_modules | map(type) | map(select(. != "string")) | length) > 0
                        then record("scanning.exclude_modules"; "array elements must be strings")
                        else .
                        end
                    else .
                    end
                  | if ($root.scanning | has("profile")) and ($root.scanning.profile | type) != "string"
                    then record("scanning.profile"; "expected string, received " + ($root.scanning.profile | json_type))
                    else .
                    end
                  | if ($root.scanning | has("ports")) and ($root.scanning.ports | type) != "string"
                    then record("scanning.ports"; "expected string, received " + ($root.scanning.ports | json_type))
                    else .
                    end
                  | if ($root.scanning | has("wordlist")) and ($root.scanning.wordlist | type) != "string"
                    then record("scanning.wordlist"; "expected string, received " + ($root.scanning.wordlist | json_type))
                    else .
                    end
              end
          else .
          end

        # execution section.
        | if ($root | type) == "object" and ($root | has("execution")) then
              if ($root.execution | type) != "object"
              then record("execution"; "expected object, received " + ($root.execution | json_type))
              else
                  check_unknown_keys($root.execution; "execution"; ["timeout", "threads", "rate_limit", "retries"])
                  | if ($root.execution | has("timeout")) and ($root.execution.timeout | json_type) != "integer"
                    then record("execution.timeout"; "expected integer, received " + ($root.execution.timeout | json_type))
                    else .
                    end
                  | if ($root.execution | has("threads")) and ($root.execution.threads | json_type) != "integer"
                    then record("execution.threads"; "expected integer, received " + ($root.execution.threads | json_type))
                    else .
                    end
                  | if ($root.execution | has("rate_limit")) and ($root.execution.rate_limit | json_type) != "integer"
                    then record("execution.rate_limit"; "expected integer, received " + ($root.execution.rate_limit | json_type))
                    else .
                    end
                  | if ($root.execution | has("retries")) and ($root.execution.retries | json_type) != "integer"
                    then record("execution.retries"; "expected integer, received " + ($root.execution.retries | json_type))
                    else .
                    end
              end
          else .
          end

        # reporting section.
        | if ($root | type) == "object" and ($root | has("reporting")) then
              if ($root.reporting | type) != "object"
              then record("reporting"; "expected object, received " + ($root.reporting | json_type))
              else
                  check_unknown_keys($root.reporting; "reporting"; ["formats", "no_report", "log_file"])
                  | if ($root.reporting | has("formats")) then
                        if ($root.reporting.formats | type) != "array"
                        then record("reporting.formats"; "expected array, received " + ($root.reporting.formats | json_type))
                        elif ($root.reporting.formats | map(type) | map(select(. != "string")) | length) > 0
                        then record("reporting.formats"; "array elements must be strings")
                        elif (
                            $root.reporting.formats
                            | map(ascii_upcase)
                            | map(select(. != "JSON" and . != "TXT" and . != "MD"))
                            | length
                        ) > 0
                        then record("reporting.formats"; "unsupported format; expected JSON, TXT or MD")
                        else .
                        end
                    else .
                    end
                  | if ($root.reporting | has("no_report")) and ($root.reporting.no_report | type) != "boolean"
                    then record("reporting.no_report"; "expected boolean, received " + ($root.reporting.no_report | json_type))
                    else .
                    end
                  | if ($root.reporting | has("log_file")) and ($root.reporting.log_file | type) != "string"
                    then record("reporting.log_file"; "expected string, received " + ($root.reporting.log_file | json_type))
                    else .
                    end
              end
          else .
          end
    ' <<<"$CONFIG_JSON" 2>/dev/null); then
        CONFIG_ERROR="Configuration schema error: unable to parse configuration"
        return 1
    fi

    # No violations means the schema is valid.
    if [[ "$violations" == "[]" ]]; then
        return 0
    fi

    # Extract the first violation's path and reason.
    if ! first_violation=$(jq -r '.[0] | "\(.path): \(.reason)"' <<<"$violations" 2>/dev/null); then
        CONFIG_ERROR="Configuration schema error: validation failed"
        return 1
    fi

    if [[ -z "$first_violation" || "$first_violation" == "null" ]]; then
        CONFIG_ERROR="Configuration schema error: validation failed"
        return 1
    fi

    CONFIG_ERROR="Configuration schema error: $first_violation"
    return 1
}

# Load the canonical module identifier list into an array.
# Mirrors _cli_valid_modules so configuration validation and CLI
# validation use the same source of truth.
config_valid_modules() {
    local module_id

    CONFIG_VALID_MODULES=()

    while IFS= read -r module_id; do
        CONFIG_VALID_MODULES+=("$module_id")
    done < <(_cli_valid_modules)
}

# Validate configuration values and normalize reporting formats.
# Semantic validation. Structure and types are handled by
# config_validate_schema.
config_validate_values() {

    local timeout threads rate_limit retries
    local wordlist
    local no_report formats_count
    local normalized_json
    local module_entry
    local is_valid

    # Configuration is optional. Nothing to validate.
    if [[ "$CONFIG_LOADED" == false && -z "$CONFIG_JSON" ]]; then
        return 0
    fi

    if [[ -z "$CONFIG_JSON" ]]; then
        CONFIG_ERROR="Configuration value error: configuration is empty"
        return 1
    fi

    # --- Numeric range checks ---
    timeout=$(jq -r '.execution.timeout // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    threads=$(jq -r '.execution.threads // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    rate_limit=$(jq -r '.execution.rate_limit // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    retries=$(jq -r '.execution.retries // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    if [[ -n "$timeout" && "$timeout" -lt 1 ]]; then
        CONFIG_ERROR="Configuration value error: execution.timeout: must be at least 1"
        return 1
    fi

    if [[ -n "$threads" && "$threads" -lt 1 ]]; then
        CONFIG_ERROR="Configuration value error: execution.threads: must be at least 1"
        return 1
    fi

    if [[ -n "$rate_limit" && "$rate_limit" -lt 1 ]]; then
        CONFIG_ERROR="Configuration value error: execution.rate_limit: must be at least 1"
        return 1
    fi

    if [[ -n "$retries" && "$retries" -lt 0 ]]; then
        CONFIG_ERROR="Configuration value error: execution.retries: must be at least 0"
        return 1
    fi

    # --- Wordlist file check ---
    wordlist=$(jq -r '.scanning.wordlist // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    if [[ -n "$wordlist" ]]; then
        if [[ ! -f "$wordlist" ]]; then
            CONFIG_ERROR="Configuration value error: scanning.wordlist: file does not exist or is not a regular file: $wordlist"
            return 1
        fi
        if [[ ! -r "$wordlist" ]]; then
            CONFIG_ERROR="Configuration value error: scanning.wordlist: file is not readable: $wordlist"
            return 1
        fi
    fi

    # --- Module identifier validation ---
    config_valid_modules

    while IFS= read -r module_entry; do
        [[ -z "$module_entry" ]] && continue

        is_valid=false
        for valid_module in "${CONFIG_VALID_MODULES[@]}"; do
            if [[ "$module_entry" == "$valid_module" ]]; then
                is_valid=true
                break
            fi
        done

        if [[ "$is_valid" == false ]]; then
            CONFIG_ERROR="Configuration value error: scanning.modules: invalid module identifier: $module_entry"
            return 1
        fi
    done < <(jq -r '.scanning.modules[]? // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    while IFS= read -r module_entry; do
        [[ -z "$module_entry" ]] && continue

        is_valid=false
        for valid_module in "${CONFIG_VALID_MODULES[@]}"; do
            if [[ "$module_entry" == "$valid_module" ]]; then
                is_valid=true
                break
            fi
        done

        if [[ "$is_valid" == false ]]; then
            CONFIG_ERROR="Configuration value error: scanning.exclude_modules: invalid module identifier: $module_entry"
            return 1
        fi
    done < <(jq -r '.scanning.exclude_modules[]? // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    # --- Reporting conflict ---
    no_report=$(jq -r '.reporting.no_report // false' <<<"$CONFIG_JSON" 2>/dev/null)
    formats_count=$(jq -r '.reporting.formats // [] | length' <<<"$CONFIG_JSON" 2>/dev/null)

    if [[ "$no_report" == "true" && "$formats_count" -gt 0 ]]; then
        CONFIG_ERROR="Configuration value error: reporting.no_report: cannot be combined with non-empty reporting.formats"
        return 1
    fi

    # --- Format normalization ---
    if [[ "$formats_count" -gt 0 ]]; then
        if ! normalized_json=$(jq -c '
            .reporting.formats |= map(ascii_upcase)
        ' <<<"$CONFIG_JSON" 2>/dev/null); then
            CONFIG_ERROR="Configuration value error: unable to normalize reporting.formats"
            return 1
        fi

        CONFIG_JSON="$normalized_json"
    fi

    return 0
}

# Populate effective configuration state from CONFIG_JSON.
# Applies schema defaults for absent values. Does not apply CLI overrides;
# that is handled by config_apply_cli (M3.6).
config_apply() {

    local value
    local array_entry

    # Start from schema defaults. Each default matches section 8 of the
    # frozen configuration specification.
    CONFIG_EFFECTIVE_OUTPUT_DIR="results"
    CONFIG_EFFECTIVE_COLOR="auto"
    CONFIG_EFFECTIVE_MODULES=()
    CONFIG_EFFECTIVE_EXCLUDE_MODULES=()
    CONFIG_EFFECTIVE_PROFILE=""
    CONFIG_EFFECTIVE_PORTS=""
    CONFIG_EFFECTIVE_WORDLIST=""
    CONFIG_EFFECTIVE_TIMEOUT=300
    CONFIG_EFFECTIVE_THREADS=10
    CONFIG_EFFECTIVE_RATE_LIMIT=5
    CONFIG_EFFECTIVE_RETRIES=2
    CONFIG_EFFECTIVE_FORMATS=()
    CONFIG_EFFECTIVE_NO_REPORT=false
    CONFIG_EFFECTIVE_LOG_FILE=""

    # If no configuration file was loaded, defaults are the final result.
    if [[ "$CONFIG_LOADED" == false ]]; then
        return 0
    fi

    if [[ -z "$CONFIG_JSON" ]]; then
        CONFIG_ERROR="Configuration apply error: CONFIG_JSON is empty while CONFIG_LOADED is true"
        return 1
    fi

    # general.output_dir
    value=$(jq -r '.general.output_dir // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_OUTPUT_DIR="$value"
    fi

    # general.color
    value=$(jq -r '.general.color // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_COLOR="$value"
    fi

    # scanning.modules
    CONFIG_EFFECTIVE_MODULES=()
    while IFS= read -r array_entry; do
        [[ -z "$array_entry" ]] && continue
        CONFIG_EFFECTIVE_MODULES+=("$array_entry")
    done < <(jq -r '.scanning.modules[]? // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    # scanning.exclude_modules
    CONFIG_EFFECTIVE_EXCLUDE_MODULES=()
    while IFS= read -r array_entry; do
        [[ -z "$array_entry" ]] && continue
        CONFIG_EFFECTIVE_EXCLUDE_MODULES+=("$array_entry")
    done < <(jq -r '.scanning.exclude_modules[]? // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    # scanning.profile
    value=$(jq -r '.scanning.profile // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_PROFILE="$value"
    fi

    # scanning.ports
    value=$(jq -r '.scanning.ports // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_PORTS="$value"
    fi

    # scanning.wordlist
    value=$(jq -r '.scanning.wordlist // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_WORDLIST="$value"
    fi

    # execution.timeout
    value=$(jq -r '.execution.timeout // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_TIMEOUT="$value"
    fi

    # execution.threads
    value=$(jq -r '.execution.threads // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_THREADS="$value"
    fi

    # execution.rate_limit
    value=$(jq -r '.execution.rate_limit // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_RATE_LIMIT="$value"
    fi

    # execution.retries
    value=$(jq -r '.execution.retries // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_RETRIES="$value"
    fi

    # reporting.formats
    CONFIG_EFFECTIVE_FORMATS=()
    while IFS= read -r array_entry; do
        [[ -z "$array_entry" ]] && continue
        CONFIG_EFFECTIVE_FORMATS+=("$array_entry")
    done < <(jq -r '.reporting.formats[]? // empty' <<<"$CONFIG_JSON" 2>/dev/null)

    # reporting.no_report
    value=$(jq -r '.reporting.no_report // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_NO_REPORT="$value"
    fi

    # reporting.log_file
    value=$(jq -r '.reporting.log_file // empty' <<<"$CONFIG_JSON" 2>/dev/null)
    if [[ -n "$value" ]]; then
        CONFIG_EFFECTIVE_LOG_FILE="$value"
    fi

    return 0
}

# Overlay CLI-supplied values onto the effective configuration state.
# Must be called after config_apply, which populates the effective state
# from the config file (or from schema defaults). CLI values replace
# config/default values for options that were explicitly supplied.
#
# Array precedence: a supplied CLI array REPLACES the corresponding
# effective array; it does not merge with the config array.
config_apply_cli() {

    local entry

    # --- target / targets_file ---
    if [[ -n "${CLI_EXPLICIT[target]+x}" ]]; then
        CONFIG_EFFECTIVE_TARGET="$CLI_TARGET"
    fi

    if [[ -n "${CLI_EXPLICIT[targets_file]+x}" ]]; then
        CONFIG_EFFECTIVE_TARGETS_FILE="$CLI_TARGETS_FILE"
    fi

    # --- scan selection flags ---
    if [[ "$CLI_NETWORK" == true ]]; then
        CONFIG_EFFECTIVE_NETWORK=true
    fi

    if [[ "$CLI_WEB" == true ]]; then
        CONFIG_EFFECTIVE_WEB=true
    fi

    # --- module arrays (replace, not merge) ---
    if [[ -n "${CLI_EXPLICIT[modules]+x}" ]]; then
        CONFIG_EFFECTIVE_MODULES=()
        for entry in "${CLI_MODULES[@]}"; do
            CONFIG_EFFECTIVE_MODULES+=("$entry")
        done
    fi

    if [[ -n "${CLI_EXPLICIT[exclude_modules]+x}" ]]; then
        CONFIG_EFFECTIVE_EXCLUDE_MODULES=()
        for entry in "${CLI_EXCLUDE_MODULES[@]}"; do
            CONFIG_EFFECTIVE_EXCLUDE_MODULES+=("$entry")
        done
    fi

    # --- profile / ports / wordlist ---
    if [[ -n "${CLI_EXPLICIT[profile]+x}" ]]; then
        CONFIG_EFFECTIVE_PROFILE="$CLI_PROFILE"
    fi

    if [[ -n "${CLI_EXPLICIT[ports]+x}" ]]; then
        CONFIG_EFFECTIVE_PORTS="$CLI_PORTS"
    fi

    if [[ -n "${CLI_EXPLICIT[wordlist]+x}" ]]; then
        CONFIG_EFFECTIVE_WORDLIST="$CLI_WORDLIST"
    fi

    # --- execution numeric options ---
    if [[ -n "${CLI_EXPLICIT[timeout]+x}" ]]; then
        CONFIG_EFFECTIVE_TIMEOUT="$CLI_TIMEOUT"
    fi

    if [[ -n "${CLI_EXPLICIT[threads]+x}" ]]; then
        CONFIG_EFFECTIVE_THREADS="$CLI_THREADS"
    fi

    if [[ -n "${CLI_EXPLICIT[rate_limit]+x}" ]]; then
        CONFIG_EFFECTIVE_RATE_LIMIT="$CLI_RATE_LIMIT"
    fi

    if [[ -n "${CLI_EXPLICIT[retries]+x}" ]]; then
        CONFIG_EFFECTIVE_RETRIES="$CLI_RETRIES"
    fi

    # --- output / reporting ---
    if [[ -n "${CLI_EXPLICIT[output_dir]+x}" ]]; then
        CONFIG_EFFECTIVE_OUTPUT_DIR="$CLI_OUTPUT_DIR"
    fi

    if [[ -n "${CLI_EXPLICIT[formats]+x}" ]]; then
        CONFIG_EFFECTIVE_FORMATS=()
        for entry in "${CLI_FORMATS[@]}"; do
            CONFIG_EFFECTIVE_FORMATS+=("$entry")
        done
    fi

    if [[ -n "${CLI_EXPLICIT[no_report]+x}" ]]; then
        CONFIG_EFFECTIVE_NO_REPORT="$CLI_NO_REPORT"
    fi

    if [[ -n "${CLI_EXPLICIT[log_file]+x}" ]]; then
        CONFIG_EFFECTIVE_LOG_FILE="$CLI_LOG_FILE"
    fi

    # --- color ---
    if [[ -n "${CLI_EXPLICIT[color]+x}" ]]; then
        CONFIG_EFFECTIVE_COLOR="$CLI_COLOR_MODE"
    fi

    return 0
}