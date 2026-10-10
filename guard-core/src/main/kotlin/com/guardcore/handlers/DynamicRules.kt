package com.guardcore.handlers

import java.time.OffsetDateTime
import java.util.Locale
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

/**
 * Port of `guard_core/_dynamic_rules.py` DynamicRules (models surface for the agent's dynamic
 * rules), field-for-field with the same defaults (_dynamic_rules.py:6-87).
 */
public class DynamicRules(
    public val ruleId: String,
    public val version: Int,
    public val timestamp: OffsetDateTime,
    public val expiresAt: OffsetDateTime? = null,
    public val ttl: Int = 300,
    public val ipBlacklist: List<String> = emptyList(),
    public val ipWhitelist: List<String> = emptyList(),
    public val ipBanDuration: Int = 3600,
    public val blockedCountries: List<String> = emptyList(),
    public val whitelistCountries: List<String> = emptyList(),
    public val globalRateLimit: Int? = null,
    public val globalRateWindow: Int? = null,
    public val endpointRateLimits: Map<String, Pair<Int, Int>> = linkedMapOf(),
    public val blockedCloudProviders: Set<String> = linkedSetOf(),
    public val blockedUserAgents: List<String> = emptyList(),
    public val suspiciousPatterns: List<String> = emptyList(),
    public val enablePenetrationDetection: Boolean? = null,
    public val enableIpBanning: Boolean? = null,
    public val enableRateLimiting: Boolean? = null,
    public val autoBanThreshold: Int? = null,
    public val autoBanDuration: Int? = null,
    public val enableRateLimitAutoBan: Boolean? = null,
    public val emergencyMode: Boolean = false,
    public val emergencyWhitelist: List<String> = emptyList(),
)

/** Python `LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION` (_dynamic_rules.py:91). */
public const val LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION: Int = 1

/**
 * Pydantic v2 datetime JSON encoding (speedate): UTC renders with a `Z` suffix, other offsets as
 * `+HH:MM`. `OffsetDateTime.toString` matches for both when seconds are present; the conversion
 * normalizes `+00:00` to `Z`.
 */
public fun pydanticDatetimeJson(value: OffsetDateTime): String {
  val base =
      String.format(
          Locale.ROOT,
          "%04d-%02d-%02dT%02d:%02d:%02d",
          value.year,
          value.monthValue,
          value.dayOfMonth,
          value.hour,
          value.minute,
          value.second,
      )
  val nano = value.nano
  val fraction =
      when {
        nano == 0 -> ""
        else -> {
          // pydantic (speedate) renders microseconds, trimming trailing zeros.
          var frac = String.format(Locale.ROOT, "%09d", nano)
          while (frac.endsWith("000")) {
            frac = frac.removeSuffix("000")
          }
          ".$frac"
        }
      }
  val offset = value.offset
  val offsetText =
      if (offset.totalSeconds == 0) {
        "Z"
      } else {
        val abs = kotlin.math.abs(offset.totalSeconds)
        val sign = if (offset.totalSeconds < 0) "-" else "+"
        String.format(Locale.ROOT, "%s%02d:%02d", sign, abs / 3600, (abs % 3600) / 60)
      }
  return base + fraction + offsetText
}

/** Port of `dump_last_known_rules_snapshot` (_dynamic_rules.py:106): pinned field order. */
public fun dumpLastKnownRulesSnapshot(rules: DynamicRules): String {
  val obj =
      JsonObject(
          linkedMapOf(
              "schema_version" to JsonPrimitive(LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION),
              "rules" to dynamicRulesJson(rules),
          ),
      )
  return PyJsonDumps.dumpsCompact(obj)
}

/** The `rules` object with pydantic model_dump_json field order and shapes. */
private fun dynamicRulesJson(rules: DynamicRules): JsonObject =
    JsonObject(
        linkedMapOf(
            "rule_id" to JsonPrimitive(rules.ruleId),
            "version" to JsonPrimitive(rules.version),
            "timestamp" to JsonPrimitive(pydanticDatetimeJson(rules.timestamp)),
            "expires_at" to
                (rules.expiresAt?.let { JsonPrimitive(pydanticDatetimeJson(it)) } ?: JsonNull),
            "ttl" to JsonPrimitive(rules.ttl),
            "ip_blacklist" to stringListJson(rules.ipBlacklist),
            "ip_whitelist" to stringListJson(rules.ipWhitelist),
            "ip_ban_duration" to JsonPrimitive(rules.ipBanDuration),
            "blocked_countries" to stringListJson(rules.blockedCountries),
            "whitelist_countries" to stringListJson(rules.whitelistCountries),
            "global_rate_limit" to (rules.globalRateLimit?.let { JsonPrimitive(it) } ?: JsonNull),
            "global_rate_window" to (rules.globalRateWindow?.let { JsonPrimitive(it) } ?: JsonNull),
            "endpoint_rate_limits" to
                JsonObject(
                    rules.endpointRateLimits.mapValues { (_, pair) ->
                      JsonArray(
                          listOf(
                              JsonPrimitive(pair.first),
                              JsonPrimitive(pair.second),
                          ),
                      )
                    },
                ),
            "blocked_cloud_providers" to stringListJson(rules.blockedCloudProviders.toList()),
            "blocked_user_agents" to stringListJson(rules.blockedUserAgents),
            "suspicious_patterns" to stringListJson(rules.suspiciousPatterns),
            "enable_penetration_detection" to
                (rules.enablePenetrationDetection?.let { JsonPrimitive(it) } ?: JsonNull),
            "enable_ip_banning" to (rules.enableIpBanning?.let { JsonPrimitive(it) } ?: JsonNull),
            "enable_rate_limiting" to
                (rules.enableRateLimiting?.let { JsonPrimitive(it) } ?: JsonNull),
            "auto_ban_threshold" to (rules.autoBanThreshold?.let { JsonPrimitive(it) } ?: JsonNull),
            "auto_ban_duration" to (rules.autoBanDuration?.let { JsonPrimitive(it) } ?: JsonNull),
            "enable_rate_limit_auto_ban" to
                (rules.enableRateLimitAutoBan?.let { JsonPrimitive(it) } ?: JsonNull),
            "emergency_mode" to JsonPrimitive(rules.emergencyMode),
            "emergency_whitelist" to stringListJson(rules.emergencyWhitelist),
        ),
    )

private fun stringListJson(values: List<String>): JsonArray =
    JsonArray(values.map { JsonPrimitive(it) })

private val jsonParser = Json

/**
 * Port of `load_last_known_rules_snapshot` (_dynamic_rules.py:116): parse, verify the schema
 * version, and materialize DynamicRules. Unknown keys are forbidden (LastKnownDynamicRules
 * extra="forbid", _dynamic_rules.py:88).
 */
public fun loadLastKnownRulesSnapshot(payload: String): DynamicRules {
  val root = jsonParser.parseToJsonElement(payload).jsonObject
  val rulesObj =
      (root["rules"] as? JsonObject)?.jsonObject
          ?: throw IllegalArgumentException("Invalid last-known dynamic rules snapshot payload")

  val knownKeys =
      setOf(
          "rule_id",
          "version",
          "timestamp",
          "expires_at",
          "ttl",
          "ip_blacklist",
          "ip_whitelist",
          "ip_ban_duration",
          "blocked_countries",
          "whitelist_countries",
          "global_rate_limit",
          "global_rate_window",
          "endpoint_rate_limits",
          "blocked_cloud_providers",
          "blocked_user_agents",
          "suspicious_patterns",
          "enable_penetration_detection",
          "enable_ip_banning",
          "enable_rate_limiting",
          "auto_ban_threshold",
          "auto_ban_duration",
          "enable_rate_limit_auto_ban",
          "emergency_mode",
          "emergency_whitelist",
      )
  val unknown = rulesObj.keys.filter { it !in knownKeys }
  if (unknown.isNotEmpty()) {
    throw IllegalArgumentException("Extra inputs are not permitted [$unknown]")
  }

  val schemaVersion = (root["schema_version"] as? JsonPrimitive)?.intOrNull
  if (schemaVersion != LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION) {
    throw IllegalArgumentException(
        "Unsupported last-known dynamic rules snapshot schema version: $schemaVersion",
    )
  }

  fun str(name: String): String? {
    val v = rulesObj[name]
    return when (v) {
      null,
      is JsonNull -> null
      is JsonPrimitive -> v.content
      else -> throw IllegalArgumentException("$name must be a string")
    }
  }

  fun intOf(name: String): Int? {
    val v = rulesObj[name]
    return when (v) {
      null,
      is JsonNull -> null
      is JsonPrimitive -> v.intOrNull ?: throw IllegalArgumentException("$name must be an int")
      else -> throw IllegalArgumentException("$name must be an int")
    }
  }

  fun boolOf(name: String): Boolean? {
    val v = rulesObj[name]
    return when (v) {
      null,
      is JsonNull -> null
      is JsonPrimitive -> v.booleanOrNull ?: throw IllegalArgumentException("$name must be a bool")
      else -> throw IllegalArgumentException("$name must be a bool")
    }
  }

  fun strListOf(name: String): List<String> {
    val v = rulesObj[name]
    return when (v) {
      null,
      is JsonNull -> emptyList()
      is JsonArray -> v.map { (it as JsonPrimitive).content }
      else -> throw IllegalArgumentException("$name must be a list")
    }
  }

  val ruleId = str("rule_id") ?: throw IllegalArgumentException("rule_id Field required")
  val version = intOf("version") ?: throw IllegalArgumentException("version Field required")
  val timestamp = str("timestamp") ?: throw IllegalArgumentException("timestamp Field required")

  val endpointLimits =
      (rulesObj["endpoint_rate_limits"] as? JsonObject)?.entries?.associate { (k, v) ->
        val arr =
            v as? JsonArray
                ?: throw IllegalArgumentException("endpoint_rate_limits must map to pairs")
        val first =
            ((arr.getOrNull(0) as? JsonPrimitive)?.intOrNull
                ?: throw IllegalArgumentException("endpoint_rate_limits pair must be ints"))
        val second =
            ((arr.getOrNull(1) as? JsonPrimitive)?.intOrNull
                ?: throw IllegalArgumentException("endpoint_rate_limits pair must be ints"))
        k to Pair(first, second)
      } ?: linkedMapOf()

  return DynamicRules(
      ruleId = ruleId,
      version = version,
      timestamp = OffsetDateTime.parse(timestamp.replace("Z", "+00:00")),
      expiresAt = str("expires_at")?.let { OffsetDateTime.parse(it.replace("Z", "+00:00")) },
      ttl = intOf("ttl") ?: 300,
      ipBlacklist = strListOf("ip_blacklist"),
      ipWhitelist = strListOf("ip_whitelist"),
      ipBanDuration = intOf("ip_ban_duration") ?: 3600,
      blockedCountries = strListOf("blocked_countries"),
      whitelistCountries = strListOf("whitelist_countries"),
      globalRateLimit = intOf("global_rate_limit"),
      globalRateWindow = intOf("global_rate_window"),
      endpointRateLimits = endpointLimits,
      blockedCloudProviders = strListOf("blocked_cloud_providers").toSet(),
      blockedUserAgents = strListOf("blocked_user_agents"),
      suspiciousPatterns = strListOf("suspicious_patterns"),
      enablePenetrationDetection = boolOf("enable_penetration_detection"),
      enableIpBanning = boolOf("enable_ip_banning"),
      enableRateLimiting = boolOf("enable_rate_limiting"),
      autoBanThreshold = intOf("auto_ban_threshold"),
      autoBanDuration = intOf("auto_ban_duration"),
      enableRateLimitAutoBan = boolOf("enable_rate_limit_auto_ban"),
      emergencyMode = boolOf("emergency_mode") ?: false,
      emergencyWhitelist = strListOf("emergency_whitelist"),
  )
}
