package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.config.SecurityConfig

/**
 * Port of `guard_core/handlers/_dynamic_rule_events.py` (DynamicRuleEventSenderMixin) as extensions
 * over [DynamicRuleManager].
 */

/** Python `_DYNAMIC_RULES_HANDLER_NAME` (_dynamic_rule_events.py:7). */
public const val DYNAMIC_RULES_HANDLER_NAME: String = "dynamic_rules"

/** Port of `_send_rule_received_event` (_dynamic_rule_events.py:15). */
public suspend fun DynamicRuleManager.sendRuleReceivedEvent(rules: DynamicRules) {
  val handler = agentHandler ?: return
  try {
    handler.sendEvent(
        com.guardcore.core.events.securityEventEnvelope(
            eventType = EventTypes.EVENT_DYNAMIC_RULE_UPDATED,
            ipAddress = "system",
            actionTaken = "rules_received",
            reason = "Received updated rules ${rules.ruleId} v${rules.version}",
            handlerName = DYNAMIC_RULES_HANDLER_NAME,
            metadata =
                mapOf(
                    "rule_id" to rules.ruleId,
                    "version" to rules.version,
                    "previous_version" to (currentRules?.version ?: 0),
                ),
        ),
    )
  } catch (e: Exception) {
    logger.severe("Failed to send rule updated event: $e")
  }
}

/** Port of `_send_rule_applied_event` (_dynamic_rule_events.py:47). */
public suspend fun DynamicRuleManager.sendRuleAppliedEvent(rules: DynamicRules) {
  val handler = agentHandler ?: return
  try {
    handler.sendEvent(
        com.guardcore.core.events.securityEventEnvelope(
            eventType = EventTypes.EVENT_DYNAMIC_RULE_APPLIED,
            ipAddress = "system",
            actionTaken = "rules_updated",
            reason = "Applied dynamic rules ${rules.ruleId} v${rules.version}",
            handlerName = DYNAMIC_RULES_HANDLER_NAME,
            metadata =
                mapOf(
                    "rule_id" to rules.ruleId,
                    "version" to rules.version,
                    "ip_bans" to rules.ipBlacklist.size,
                    "country_blocks" to rules.blockedCountries.size,
                    "emergency_mode" to rules.emergencyMode,
                ),
        ),
    )
  } catch (e: Exception) {
    logger.severe("Failed to send rule applied event: $e")
  }
}

/** Port of `_send_emergency_event` (_dynamic_rule_events.py:77). */
public suspend fun DynamicRuleManager.sendEmergencyEvent(whitelist: List<String>) {
  val handler = agentHandler ?: return
  try {
    handler.sendEvent(
        com.guardcore.core.events.securityEventEnvelope(
            eventType = EventTypes.EVENT_EMERGENCY_MODE,
            ipAddress = "system",
            actionTaken = "emergency_lockdown",
            reason = "[EMERGENCY MODE] activated via dynamic rules",
            handlerName = DYNAMIC_RULES_HANDLER_NAME,
            metadata =
                mapOf(
                    "whitelist_count" to whitelist.size,
                    "whitelist" to whitelist.take(10),
                ),
        ),
    )
  } catch (e: Exception) {
    logger.severe("Failed to send emergency event: $e")
  }
}

/** The SecurityConfig property surface the application mixin writes through. */
public val DYNAMIC_RULE_SNAPSHOT_FIELDS: List<String> =
    listOf(
        "blocked_countries",
        "whitelist_countries",
        "rate_limit",
        "rate_limit_window",
        "endpoint_rate_limits",
        "block_cloud_providers",
        "blocked_user_agents",
        "enable_penetration_detection",
        "enable_ip_banning",
        "enable_rate_limiting",
        "emergency_mode",
        "emergency_whitelist",
        "auto_ban_threshold",
        "auto_ban_duration",
        "enable_rate_limit_auto_ban",
    )

/** Python `VALID_CLOUD_PROVIDERS` (models.py): providers usable in block_cloud_providers. */
public val VALID_CLOUD_PROVIDERS: Set<String> =
    setOf("AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr")

/** Python `deepcopy` of a snapshot value: collections are copied, scalars are immutable. */
private fun deepCopy(value: Any?): Any? =
    when (value) {
      is Set<*> -> value.mapTo(LinkedHashSet()) { deepCopy(it) }
      is List<*> -> value.map { deepCopy(it) }
      is Map<*, *> -> value.entries.associateTo(LinkedHashMap()) { it.key to deepCopy(it.value) }
      else -> value
    }

/** Port of `_snapshot_config` (dynamic_rule_handler.py:219): deepcopy per snapshot field. */
public fun snapshotConfig(config: SecurityConfig): Map<String, Any?> {
  val live: Map<String, Any?> =
      linkedMapOf(
          "blocked_countries" to config.blockedCountries,
          "whitelist_countries" to config.whitelistCountries,
          "rate_limit" to config.rateLimit,
          "rate_limit_window" to config.rateLimitWindow,
          "endpoint_rate_limits" to config.endpointRateLimits,
          "block_cloud_providers" to config.blockCloudProviders,
          "blocked_user_agents" to config.blockedUserAgents,
          "enable_penetration_detection" to config.enablePenetrationDetection,
          "enable_ip_banning" to config.enableIpBanning,
          "enable_rate_limiting" to config.enableRateLimiting,
          "emergency_mode" to config.emergencyMode,
          "emergency_whitelist" to config.emergencyWhitelist,
          "auto_ban_threshold" to config.autoBanThreshold,
          "auto_ban_duration" to config.autoBanDuration,
          "enable_rate_limit_auto_ban" to config.enableRateLimitAutoBan,
      )
  val snapshot = linkedMapOf<String, Any?>()
  for (field in DYNAMIC_RULE_SNAPSHOT_FIELDS) {
    if (live.containsKey(field)) {
      snapshot[field] = deepCopy(live[field])
    }
  }
  return snapshot
}

/** Port of `_restore_config` (dynamic_rule_handler.py:226). */
public fun restoreConfig(config: SecurityConfig, snapshot: Map<String, Any?>) {
  for ((field, value) in snapshot) {
    config.setPrevalidated(field, deepCopy(value))
  }
}

/** Port of `_capture_active_base_snapshot` (dynamic_rule_handler.py:230). */
public fun captureActiveBaseSnapshot(
    manager: DynamicRuleManager,
    snapshot: Map<String, Any?>,
) {
  if (manager.currentRules == null && manager.activeBaseSnapshot == null) {
    manager.activeBaseSnapshot = snapshot
  }
}
