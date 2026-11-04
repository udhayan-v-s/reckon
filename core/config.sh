#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Configuration management
#

# Initialize configuration state.
config_init() {

    CONFIG_FILE=""
    CONFIG_JSON=""
    CONFIG_LOADED=false
    CONFIG_ERROR=""

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

    # Configuration is optional.
    if [[ -z "$CONFIG_FILE" ]]; then
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

    CONFIG_LOADED=true

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
