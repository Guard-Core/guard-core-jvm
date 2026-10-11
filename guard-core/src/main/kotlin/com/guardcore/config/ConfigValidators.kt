package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import com.guardcore.util.PathMatching
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress
import java.nio.file.InvalidPathException
import java.nio.file.Paths

/**
 * Port of the SecurityConfig field validators:
 * - guard_core/_security_config_field_validators.py
 * - guard_core/_config_field_revalidators.py
 * - guard_core/_security_config_typed_validators.py
 * - guard_core/_security_config_geo_validators.py (country parts)
 * - guard_core/models.py field validators
 *
 * Error messages are the Python validators' own messages (the observable rejection surface asserted
 * by the test suites).
 */
public object ConfigValidators {
  // ------------------------------------------------------ typed helpers

  /** Port of `_validate_int_field_value` (_config_field_revalidators.py:10). */
  internal fun validateIntFieldValue(value: Any?, fieldName: String): Int {
    if (value !is Int) {
      throw ConfigValidationError("$fieldName must be an int, got ${typeName(value)}")
    }
    return value
  }

  /** Port of `_validate_positive_int_field_value` (_config_field_revalidators.py:16). */
  internal fun validatePositiveIntFieldValue(value: Any?, fieldName: String): Int {
    val intValue = validateIntFieldValue(value, fieldName)
    if (intValue < 1) {
      throw ConfigValidationError("$fieldName must be >= 1, got $intValue")
    }
    return intValue
  }

  /** Port of `_validate_bool_field_value` (_config_field_revalidators.py:4). */
  internal fun validateBoolFieldValue(value: Any?, fieldName: String): Boolean {
    if (value !is Boolean) {
      throw ConfigValidationError("$fieldName must be a bool, got ${typeName(value)}")
    }
    return value
  }

  /** Port of `_validate_str_list_field_value` (_config_field_revalidators.py:23). */
  internal fun validateStrListFieldValue(value: Any?, fieldName: String): List<String> {
    if (value !is List<*> || value.any { it !is String }) {
      throw ConfigValidationError("$fieldName must be a list of str")
    }
    @Suppress("UNCHECKED_CAST")
    return value as List<String>
  }

  /** Port of `_validate_endpoint_rate_limits_value` (_config_field_revalidators.py:29). */
  internal fun validateEndpointRateLimitsValue(value: Any?): Map<String, Pair<Int, Int>> {
    if (value !is Map<*, *>) {
      throw ConfigValidationError(
          "endpoint_rate_limits must be a dict, got ${typeName(value)}",
      )
    }
    for ((key, entry) in value) {
      if (key !is String) {
        throw ConfigValidationError(
            "endpoint_rate_limits keys must be str, got ${typeName(key)}",
        )
      }
      if (entry !is Pair<*, *> || entry.first !is Int || entry.second !is Int) {
        throw ConfigValidationError(
            "endpoint_rate_limits['$key'] must be a (int, int) tuple, got ${entryToString(entry)}",
        )
      }
    }
    @Suppress("UNCHECKED_CAST")
    return value as Map<String, Pair<Int, Int>>
  }

  // ------------------------------------------------- IP / CIDR validation

  /** Port of `_validate_ip_or_cidr_list` (_security_config_field_validators.py:153-170). */
  internal fun validateIpOrCidrList(
      value: Any?,
      invalidMessage: String,
      allowUnix: Boolean = false,
  ): List<String>? {
    if (value == null) return null
    if (value !is List<*>) {
      // Python iterates `for entry in v`; non-iterables raise TypeError
      // which pydantic surfaces. The JVM builders only pass lists.
      throw ConfigValidationError("$invalidMessage: $value")
    }
    val validated = ArrayList<String>(value.size)
    for (entry in value) {
      val entryText = entry as? String
      if (entryText == null) {
        throw ConfigValidationError("$invalidMessage: $entry")
      }
      if (allowUnix && entryText == "unix") {
        validated.add("unix")
        continue
      }
      try {
        if ("/" in entryText) {
          validated.add(IpNetwork.parse(entryText).text)
        } else {
          validated.add(parseAddress(entryText).text)
        }
      } catch (_: ConfigValidationError) {
        throw ConfigValidationError("$invalidMessage: $entryText")
      }
    }
    return validated
  }

  /** Port of `_validate_whitelist_value` (_security_config_field_validators.py:173). */
  internal fun validateWhitelistValue(value: Any?): List<String>? =
      validateIpOrCidrList(value, invalidMessage = "Invalid IP or CIDR range")

  /** Port of `_validate_blacklist_value` (_security_config_field_validators.py:177). */
  internal fun validateBlacklistValue(value: Any?): List<String> =
      validateIpOrCidrList(value, invalidMessage = "Invalid IP or CIDR range").orEmpty()

  /** Port of `_validate_trusted_proxies_value` (_security_config_field_validators.py:181). */
  internal fun validateTrustedProxiesValue(value: Any?): List<String> =
      validateIpOrCidrList(
              value,
              invalidMessage = "Invalid proxy IP or CIDR range",
              allowUnix = true,
          )
          .orEmpty()

  /** Port of `_is_prefix_zero_network_entry` (_security_config_field_validators.py:187). */
  internal fun isPrefixZeroNetworkEntry(entry: String): Boolean =
      try {
        IpNetwork.parse(entry).prefixLen == 0
      } catch (_: ConfigValidationError) {
        false
      }

  // ---------------------------------------------------- country validation

  /** Port of `_validate_country_set_value` (_security_config_geo_validators.py:28). */
  internal fun validateCountrySetValue(value: Any?): Set<String> {
    if (value == null) return emptySet()
    return when (value) {
      is List<*>,
      is Set<*> -> value.map { it.toString().uppercase() }.toSet()
      else ->
          throw ConfigValidationError(
              "Country list must be list/tuple/set/frozenset of country codes",
          )
    }
  }

  /** Port of `_normalized_country_value` (_security_config_geo_validators.py:24). */
  internal fun normalizedCountryValue(value: Any?): Set<String> =
      when (value) {
        is Collection<*> -> value.map { it.toString().uppercase() }.toSet()
        else -> emptySet()
      }

  // -------------------------------------------------- membership validators

  /** Port of `_validate_threat_ban_config_value` (_security_config_field_validators.py:233). */
  internal fun validateThreatBanConfigValue(value: Any?): Map<String, ThreatBanConfig> {
    if (value !is Map<*, *>) {
      throw ConfigValidationError("threat_ban_config must be a mapping")
    }
    val mapping = LinkedHashMap<String, ThreatBanConfig>()
    for ((key, entry) in value) {
      val category =
          key as? String ?: throw ConfigValidationError("threat_ban_config keys must be str")
      mapping[category] =
          when (entry) {
            is ThreatBanConfig -> entry
            is Map<*, *> -> {
              val threshold = entry["threshold"] as? Int
              val duration = entry["duration"] as? Int
              try {
                ThreatBanConfig(
                    threshold
                        ?: throw ConfigValidationError(
                            "threat_ban_config['$category'] missing threshold",
                        ),
                    duration
                        ?: throw ConfigValidationError(
                            "threat_ban_config['$category'] missing duration",
                        ),
                )
              } catch (e: ConfigValidationError) {
                throw ConfigValidationError("threat_ban_config['$category']: ${e.message}")
              }
            }
            else ->
                throw ConfigValidationError(
                    "threat_ban_config['$category'] must be a ThreatBanConfig or mapping",
                )
          }
    }
    val unknown = mapping.keys.filter { it !in DetectionCategories.THREAT_BAN_CONFIG_CATEGORIES }
    if (unknown.isNotEmpty()) {
      throw ConfigValidationError(
          "Unknown threat categories in threat_ban_config: ${sortedLiteral(unknown)}. " +
              "Valid: ${sortedLiteral(DetectionCategories.THREAT_BAN_CONFIG_CATEGORIES)}",
      )
    }
    return mapping
  }

  /** Port of `_validate_enabled_detection_categories_value` (:247). */
  internal fun validateEnabledDetectionCategoriesValue(value: Any?): Set<String> {
    val result = stringSetOf(value)
    val unknown = result.filter { it !in DetectionCategories.ALL_DETECTION_CATEGORIES }
    if (unknown.isNotEmpty()) {
      throw ConfigValidationError(
          "Unknown detection categories: ${sortedLiteral(unknown)}. " +
              "Valid: ${sortedLiteral(DetectionCategories.ALL_DETECTION_CATEGORIES)}",
      )
    }
    return result
  }

  /** Port of `_validate_muted_event_types_value` (:258). */
  internal fun validateMutedEventTypesValue(value: Any?): Set<String> {
    val result = stringSetOf(value)
    val invalid = result.filter { it !in EventTypes.EVENT_TYPE_VALUES }
    if (invalid.isNotEmpty()) {
      throw ConfigValidationError(
          "Unknown event types in muted_event_types: ${sortedLiteral(invalid)}. " +
              "Valid: ${sortedLiteral(EventTypes.EVENT_TYPE_VALUES)}",
      )
    }
    return result
  }

  /** Port of `_validate_muted_metric_types_value` (:271). */
  internal fun validateMutedMetricTypesValue(value: Any?): Set<String> {
    val result = stringSetOf(value)
    val invalid = result.filter { it !in EventTypes.METRIC_TYPE_VALUES }
    if (invalid.isNotEmpty()) {
      throw ConfigValidationError(
          "Unknown metric types in muted_metric_types: ${sortedLiteral(invalid)}. " +
              "Valid: ${sortedLiteral(EventTypes.METRIC_TYPE_VALUES)}",
      )
    }
    return result
  }

  /** Port of `_validate_muted_check_logs_value` (:284). */
  internal fun validateMutedCheckLogsValue(value: Any?): Set<String> {
    val result = stringSetOf(value)
    val invalid = result.filter { it !in EventTypes.CHECK_NAME_VALUES }
    if (invalid.isNotEmpty()) {
      throw ConfigValidationError(
          "Unknown check names in muted_check_logs: ${sortedLiteral(invalid)}. " +
              "Valid: ${sortedLiteral(EventTypes.CHECK_NAME_VALUES)}",
      )
    }
    return result
  }

  /** Port of `_validate_sensitive_name_set_value` (:297). */
  internal fun validateSensitiveNameSetValue(value: Any?, fieldName: String): Set<String> {
    if (value is String) {
      throw ConfigValidationError(
          "$fieldName must be a collection of names, not a bare string",
      )
    }
    val result =
        when (value) {
          is Collection<*> -> value.toSet()
          null -> emptySet()
          else -> throw ConfigValidationError("$fieldName items must be strings")
        }
    if (result.any { it !is String }) {
      throw ConfigValidationError("$fieldName items must be strings")
    }
    @Suppress("UNCHECKED_CAST")
    return result as Set<String>
  }

  /** Port of `_validate_block_cloud_providers_value` (:308). */
  internal fun validateBlockCloudProvidersValue(value: Any?): Set<String>? {
    if (value == null) return null
    val result = stringSetOf(value)
    val invalid = result.filter { sel ->
      val providerPart = sel.substringBefore(":!")
      providerPart !in CloudProviders.VALID_CLOUD_PROVIDERS
    }
    if (invalid.isNotEmpty()) {
      throw ConfigValidationError(
          "Unknown cloud providers in block_cloud_providers: ${sortedLiteral(invalid)}. " +
              "Valid: ${sortedLiteral(CloudProviders.VALID_CLOUD_PROVIDERS)} (a bare name blocks the whole " +
              "provider; suffix ':!region' to carve out a region exception)",
      )
    }
    return result
  }

  // ------------------------------------------------------- other validators

  /** Port of `_validate_exclude_paths_value` (:45). */
  internal fun validateExcludePathsValue(value: Any?): List<String> {
    if (value !is List<*> || value.any { it !is String }) {
      throw ConfigValidationError("exclude_paths must be a list of str")
    }
    val entries = value.filterIsInstance<String>()
    for (entry in entries) {
      val normalized = PathMatching.normalizeUrlPath(entry)
      if (normalized == null) {
        throw ConfigValidationError(
            "exclude_paths entry '$entry' could not be normalized " +
                "(malformed percent-encoding or invalid UTF-8); it would " +
                "silently exclude nothing at request time. Fix or remove it.",
        )
      }
      if (normalized != "/") continue
      if (entry != "/") {
        throw ConfigValidationError(
            "exclude_paths entry '$entry' normalizes to the root " +
                "path '/', which would exclude the entire application " +
                "from all security checks. Remove it, or configure the " +
                "literal '/' if you really intend to exclude everything.",
        )
      }
      ConfigWarnings.warn(
          "exclude_paths contains the literal '/' entry, which " +
              "excludes the entire application from all security checks " +
              "(IP banning, rate limiting, penetration detection, " +
              "everything). Confirm this is intentional.",
      )
    }
    return entries
  }

  /** Port of `_validate_dynamic_rules_cache_path_value` (:343). */
  internal fun validateDynamicRulesCachePathValue(value: Any?): java.nio.file.Path? {
    if (value == null) return null
    val text =
        when (value) {
          is String -> value
          is java.nio.file.Path -> value.toString()
          else ->
              throw ConfigValidationError(
                  "dynamic_rules_cache_path must be a non-empty filesystem path " +
                      "string or None, got ${typeName(value)}",
              )
        }
    if (text.isBlank()) {
      throw ConfigValidationError(
          "dynamic_rules_cache_path must not be empty or whitespace-only; " +
              "leave it unset (None) to disable the local snapshot fallback",
      )
    }
    return try {
      Paths.get(text)
    } catch (_: InvalidPathException) {
      throw ConfigValidationError(
          "dynamic_rules_cache_path must be a non-empty filesystem path " +
              "string or None, got ${typeName(value)}",
      )
    }
  }

  /**
   * Port of `_validate_blocked_user_agents_value` (_security_config_field_validators.py:324-340).
   * The str-list half runs here; the ReDoS gate needs the W2 PatternCompiler
   * (`ConfigSeams.blockedUserAgentsPatternGate`).
   */
  internal fun validateBlockedUserAgentsValue(value: Any?): List<String> {
    val patterns = validateStrListFieldValue(value, fieldName = "blocked_user_agents")
    ConfigSeams.blockedUserAgentsPatternGate?.invoke(patterns)
        ?: run {
          // Engine absent: gate is a no-op until W2 registers it, mirroring
          // the compiler always succeeding for benign lists. Recorded in
          // docs/w1-config-parity.md and KNOWN_GAPS.md.
        }
    return patterns
  }

  // ------------------------------------------------- return_pattern rules

  /** Port of `_validate_return_pattern_requires_scan` (:103). */
  internal fun validateReturnPatternRequiresScan(pattern: String, scanResponseBody: Boolean) {
    if (!returnPatternRequiresResponseBody(pattern)) return
    if (scanResponseBody) return
    throw ConfigValidationError(
        "return_pattern rule with pattern '${redactPatternSource(pattern)}' requires reading the " +
            "response body, but behavior_scan_response_body is False. This rule " +
            "would never match: set behavior_scan_response_body=True to enable " +
            "response-body inspection, or use a status: pattern instead.",
    )
  }

  /** Port of `_validate_return_pattern_body_scan` (:121). */
  internal fun validateReturnPatternBodyScan(pattern: String, config: SecurityConfig) {
    validateReturnPatternRequiresScan(pattern, scanResponseBody = config.behaviorScanResponseBody)
  }

  /** Port of `_validate_global_behavior_rule_assignment` (:127). */
  internal fun validateGlobalBehaviorRuleAssignment(
      config: SecurityConfig,
      name: String,
      value: Any?,
  ) {
    @Suppress("UNCHECKED_CAST")
    val candidateRules: List<BehaviorRuleConfig> =
        if (name == "global_behavior_rules") {
          (value as? List<BehaviorRuleConfig>).orEmpty()
        } else {
          config.globalBehaviorRules
        }
    val candidateScanFlag =
        if (name == "behavior_scan_response_body") {
          value as? Boolean ?: false
        } else {
          config.behaviorScanResponseBody
        }
    for (rule in candidateRules) {
      if (rule.ruleType != RuleType.RETURN_PATTERN || rule.pattern == null) continue
      validateReturnPatternRequiresScan(rule.pattern, scanResponseBody = candidateScanFlag)
    }
  }

  /** Port of `_revalidate_global_behavior_rules` (:146). */
  internal fun revalidateGlobalBehaviorRules(config: SecurityConfig) {
    for (rule in config.globalBehaviorRules) {
      if (rule.ruleType != RuleType.RETURN_PATTERN || rule.pattern == null) continue
      validateReturnPatternBodyScan(rule.pattern, config)
    }
  }

  // ------------------------------------------------------------- warnings

  /** Port of `_warn_trusted_proxies_prefix_zero` (:194). */
  internal fun warnTrustedProxiesPrefixZero() {
    ConfigWarnings.warn(
        "trusted_proxies contains a /0 network (0.0.0.0/0 or ::/0): every " +
            "peer is trusted to set X-Forwarded-For, which lets any client " +
            "spoof its IP for rate limiting, IP banning and detection " +
            "attribution. Restrict trusted_proxies to your actual reverse " +
            "proxy addresses.",
    )
  }

  /** Port of `_warn_whitelist_prefix_zero` (:204). */
  internal fun warnWhitelistPrefixZero() {
    ConfigWarnings.warn(
        "whitelist contains a /0 network (0.0.0.0/0 or ::/0): every " +
            "address is whitelisted, so blacklist, blocked_countries and IP " +
            "bans cannot block anyone. Remove the /0 entry or list the " +
            "specific networks you trust.",
    )
  }

  /** Port of `_warn_exempt_ips_prefix_zero` (:213). */
  internal fun warnExemptIpsPrefixZero(entries: List<String>) {
    if (entries.none { isPrefixZeroNetworkEntry(it) }) return
    ConfigWarnings.warn(
        "exempt_ips contains a /0 network (0.0.0.0/0 or ::/0): every " +
            "address skips rate limiting and the user-agent and cloud-provider " +
            "checks. Remove the /0 entry or list the specific networks you trust.",
    )
  }

  /** Port of `_warn_empty_enabled_detection_categories` (:223). */
  internal fun warnEmptyEnabledDetectionCategories() {
    ConfigWarnings.warn(
        "enabled_detection_categories is empty while " +
            "enable_penetration_detection is True: penetration detection is " +
            "enabled but will never match any category. Set " +
            "enabled_detection_categories to a non-empty subset, or set " +
            "enable_penetration_detection=False.",
    )
  }

  // ------------------------------------------------- typed collection
  // validators (port of _security_config_typed_validators.py).

  /** Port of `_INT_KEYED_STR_DICT_ADAPTER` validation. */
  internal fun validateIntKeyedStrDict(value: Map<*, *>, fieldName: String): Map<Int, String> {
    val out = LinkedHashMap<Int, String>()
    for ((key, entry) in value) {
      if (key !is Int) {
        throw ConfigValidationError(
            "$fieldName is invalid: $fieldName keys must be int, got ${typeName(key)}",
        )
      }
      if (entry !is String) {
        throw ConfigValidationError(
            "$fieldName is invalid: $fieldName values must be str, got ${typeName(entry)}",
        )
      }
      out[key] = entry
    }
    return out
  }

  /** Port of `_STR_KEYED_STR_DICT_ADAPTER` validation. */
  internal fun validateStrKeyedStrDict(value: Map<*, *>, fieldName: String): Map<String, String> {
    val out = LinkedHashMap<String, String>()
    for ((key, entry) in value) {
      if (key !is String || entry !is String) {
        throw ConfigValidationError(
            "$fieldName is invalid: $fieldName must be a dict of str keys and str values",
        )
      }
      out[key] = entry
    }
    return out
  }

  /** Port of `_STR_LIST_ADAPTER` validation. */
  internal fun validateStrList(value: List<String>, fieldName: String): List<String> =
      validateStrListFieldValue(value, fieldName)

  /** Port of `_OPTIONAL_STR_LIST_ADAPTER` validation. */
  internal fun validateOptionalStrList(value: List<String>?, fieldName: String): List<String>? {
    if (value == null) return null
    return validateStrListFieldValue(value, fieldName)
  }

  /** Port of `_STR_SET_ADAPTER` validation. */
  internal fun validateStrSet(value: Set<String>, fieldName: String): Set<String> = value

  /** Port of `_OPTIONAL_STR_ANY_DICT_ADAPTER` validation. */
  internal fun validateOptionalStrAnyDict(
      value: Map<String, Any?>?,
      fieldName: String,
  ): Map<String, Any?>? {
    if (value == null) return null
    return value
  }

  // -------------------------------------------------------------- helpers

  /**
   * Port of `_validate_typed_collection_field_value` with `_GLOBAL_BEHAVIOR_RULES_ADAPTER`
   * (_security_config_typed_validators.py:6-12): the assignment-time revalidator coerces dict
   * entries to BehaviorRuleConfig exactly like pydantic's TypeAdapter (the construction-time
   * map applier shares the same semantics); anything else rejects with the python-shaped message.
   */
  internal fun validateGlobalBehaviorRulesFieldValue(
      value: Any?,
      fieldName: String,
  ): List<BehaviorRuleConfig> {
    if (value !is List<*>) {
      throw ConfigValidationError(
          "$fieldName is invalid: Input should be a valid list " +
              "[type=list_type, input_value=$value, input_type=${typeName(value)}]",
      )
    }
    val out = ArrayList<BehaviorRuleConfig>(value.size)
    for (item in value) {
      out.add(
          when (item) {
            is BehaviorRuleConfig -> item
            is Map<*, *> -> behaviorRuleConfigFromMap(item, fieldName)
            else ->
                throw ConfigValidationError(
                    "$fieldName is invalid: Input should be a valid dictionary or instance " +
                        "of BehaviorRuleConfig [type=model_type, input_value=$item, " +
                        "input_type=${typeName(item)}]",
                )
          },
      )
    }
    return out
  }

  private fun behaviorRuleConfigFromMap(map: Map<*, *>, fieldName: String): BehaviorRuleConfig {
    fun require(key: String): Any? =
        map[key]
            ?: throw ConfigValidationError(
                "$fieldName is invalid: $key is required " +
                    "[type=missing, input_value=$map, input_type=dict]",
            )
    val ruleTypeRaw = require("rule_type") as? String
        ?: throw ConfigValidationError(
            "$fieldName is invalid: Input should be a valid string " +
                "[type=string_type, input_value=${map["rule_type"]}]",
        )
    val ruleType =
        RuleType.entries.firstOrNull { it.pythonName == ruleTypeRaw }
            ?: throw ConfigValidationError(
                "$fieldName is invalid: Input should be 'usage', 'return_pattern' or " +
                    "'frequency' [type=enum, input_value=$ruleTypeRaw]",
            )
    val actionRaw = (map["action"] as? String) ?: "log"
    val action =
        RuleAction.entries.firstOrNull { it.pythonName == actionRaw }
            ?: throw ConfigValidationError(
                "$fieldName is invalid: Input should be 'ban', 'log', 'throttle' or " +
                    "'alert' [type=enum, input_value=$actionRaw]",
            )
    return BehaviorRuleConfig(
        ruleType = ruleType,
        threshold = require("threshold") as Int,
        window = (map["window"] as? Int) ?: 3600,
        pattern = map["pattern"] as? String,
        action = action,
        banDuration = map["ban_duration"] as? Int,
        correlateWithDetection = (map["correlate_with_detection"] as? Boolean) ?: false,
    )
  }

  private fun stringSetOf(value: Any?): Set<String> =
      when (value) {
        null -> emptySet()
        is Set<*> -> value.map { it.toString() }.toSet()
        is Collection<*> -> value.map { it.toString() }.toSet()
        is Array<*> -> value.map { it.toString() }.toSet()
        else -> throw ConfigValidationError("Expected a collection, got ${typeName(value)}")
      }

  /** Python sorted(list) repr format: ['a', 'b']. */
  internal fun sortedLiteral(values: Collection<String>): String =
      values.sorted().joinToString(prefix = "[", postfix = "]", separator = ", ") { "'$it'" }

  private fun entryToString(entry: Any?): String =
      when (entry) {
        is Pair<*, *> -> "(${entry.first}, ${entry.second})"
        is Map<*, *> -> entry.toString()
        is List<*> -> entry.toString()
        else -> entry?.toString() ?: "None"
      }

  internal fun typeName(value: Any?): String =
      when (value) {
        null -> "NoneType"
        is Int -> "int"
        is Long -> "int"
        is Boolean -> "bool"
        is String -> "str"
        is Float,
        is Double -> "float"
        is List<*> -> "list"
        is Map<*, *> -> "dict"
        is Set<*> -> "set"
        else -> value::class.simpleName ?: "object"
      }

  /**
   * Port of `_redact_pattern_source` for the return_pattern rejection message. The Python version
   * also scans for sensitive-field names through the pattern compiler's redaction
   * (detection_scan.py:154); the W1 port keeps the sensitive-name scan and defers the
   * compiled-pattern branch to W2.
   */
  internal fun redactPatternSource(patternSource: String): String {
    val sensitiveNames =
        RequestLoggingDefaults.DEFAULT_SENSITIVE_LOG_FIELDS +
            RequestLoggingDefaults.DEFAULT_SENSITIVE_LOG_HEADERS.map { it.replace("-", "_") }
    val normalized =
        patternSource
            .replace(
                Regex(
                    "\\\\(?:[xX]([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([0-7]{1,3}))",
                ),
            ) {
              val hexBody =
                  it.groupValues[1].ifEmpty { it.groupValues[2].ifEmpty { it.groupValues[3] } }
              val code =
                  if (hexBody.isNotEmpty()) {
                    hexBody.toInt(16)
                  } else {
                    it.groupValues[4].toInt(8)
                  }
              if (code <= 0x10FFFF) code.toChar().toString() else it.value
            }
            .lowercase()
            .replace(Regex("[^a-z0-9_-]+"), "")
    val namesSensitiveField = sensitiveNames.any { it in normalized }
    if (namesSensitiveField) return "[REDACTED_PATTERN]"
    return patternSource
  }

  /** Defaults shared by the pattern-source redaction (request_logging.py:22-38). */
  internal object RequestLoggingDefaults {
    val DEFAULT_SENSITIVE_LOG_FIELDS: Set<String> =
        setOf(
            "access_token",
            "refresh_token",
            "api_key",
            "apikey",
            "token",
            "password",
            "secret",
            "client_secret",
            "signature",
        )

    val DEFAULT_SENSITIVE_LOG_HEADERS: Set<String> =
        setOf("authorization", "proxy-authorization", "cookie", "x-api-key")
  }

  /** Range check helper mirroring pydantic Field(ge=...) rejection text. */
  internal fun checkGe(value: Int, bound: Int, fieldName: String) {
    if (value < bound) {
      throw ConfigValidationError(
          "$fieldName: Input should be greater than or equal to $bound " +
              "[type=greater_than_equal, input_value=$value]",
      )
    }
  }

  internal fun checkLe(value: Int, bound: Int, fieldName: String) {
    if (value > bound) {
      throw ConfigValidationError(
          "$fieldName: Input should be less than or equal to $bound " +
              "[type=less_than_equal, input_value=$value]",
      )
    }
  }

  internal fun checkGe(value: Double, bound: Double, fieldName: String) {
    if (value < bound) {
      throw ConfigValidationError(
          "$fieldName: Input should be greater than or equal to $bound " +
              "[type=greater_than_equal, input_value=$value]",
      )
    }
  }

  internal fun checkLe(value: Double, bound: Double, fieldName: String) {
    if (value > bound) {
      throw ConfigValidationError(
          "$fieldName: Input should be less than or equal to $bound " +
              "[type=less_than_equal, input_value=$value]",
      )
    }
  }

  internal fun checkGt(value: Double, bound: Double, fieldName: String) {
    if (value <= bound) {
      throw ConfigValidationError(
          "$fieldName: Input should be greater than $bound " +
              "[type=greater_than, input_value=$value]",
      )
    }
  }
}
