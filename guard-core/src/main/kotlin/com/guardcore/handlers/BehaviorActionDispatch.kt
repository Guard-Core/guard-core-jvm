package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.util.LoggingUtils

/**
 * Port of `guard_core/handlers/_behavior_action_dispatch.py` (BehaviorActionDispatchMixin) as
 * extensions over [BehaviorTracker].
 */

/** Python `_BEHAVIOR_HANDLER_NAME` (_behavior_action_dispatch.py:12). */
public const val BEHAVIOR_HANDLER_NAME: String = "behavior"

/** Port of `_log_passive_mode_action` (_behavior_action_dispatch.py:20). */
public fun BehaviorTracker.logPassiveModeAction(
    rule: BehaviorRule,
    clientIp: String,
    details: String,
) {
  val prefix = "[PASSIVE MODE] "

  if (rule.action == "alert") {
    logger.severe("$prefix" + "ALERT - Behavioral anomaly: $details")
    return
  }

  val level = config.logSuspiciousLevel ?: return

  when (rule.action) {
    "ban" ->
        LoggingUtils.logAtLevel(
            logger,
            level.pythonName,
            "$prefix" + "Would ban IP $clientIp for behavioral violation: $details",
        )
    "log" ->
        LoggingUtils.logAtLevel(
            logger,
            level.pythonName,
            "$prefix" + "Behavioral anomaly detected: $details",
        )
    "throttle" ->
        LoggingUtils.logAtLevel(
            logger,
            level.pythonName,
            "$prefix" + "Would throttle IP $clientIp: $details",
        )
  }
}

/** Port of `_execute_ban_action` (_behavior_action_dispatch.py:48). */
public suspend fun BehaviorTracker.executeBanAction(
    clientIp: String,
    details: String,
    rule: BehaviorRule? = null,
): String {
  val ipBanManager = IpBanManager.getInstance()

  val duration = rule?.banDuration ?: 3600
  val applied = ipBanManager.banIp(clientIp, duration, "behavioral_violation")
  if (!applied) {
    return "tracked"
  }
  config.logSuspiciousLevel?.let { level ->
    LoggingUtils.logAtLevel(
        logger,
        level.pythonName,
        "IP $clientIp banned for behavioral violation: $details",
    )
  }
  return "ban"
}

/** Port of `_execute_active_mode_action` (_behavior_action_dispatch.py:75). */
public suspend fun BehaviorTracker.executeActiveModeAction(
    rule: BehaviorRule,
    clientIp: String,
    endpointId: String,
    details: String,
): String {
  rule.customAction?.let { custom ->
    custom(clientIp, endpointId, details)
    return rule.action
  }

  if (rule.action == "ban") {
    return executeBanAction(clientIp, details, rule)
  }

  if (rule.action == "alert") {
    logger.severe("ALERT - Behavioral anomaly: $details")
    return rule.action
  }

  val level = config.logSuspiciousLevel ?: return rule.action

  when (rule.action) {
    "log" ->
        LoggingUtils.logAtLevel(logger, level.pythonName, "Behavioral anomaly detected: $details")
    "throttle" ->
        LoggingUtils.logAtLevel(logger, level.pythonName, "Throttling IP $clientIp: $details")
  }
  return rule.action
}

/** Port of `apply_action` (_behavior_action_dispatch.py:99). */
public suspend fun BehaviorTracker.applyAction(
    rule: BehaviorRule,
    clientIp: String,
    endpointId: String,
    details: String,
) {
  val actionTaken: String =
      if (config.passiveMode) {
        val passive = "logged_only"
        logPassiveModeAction(rule, clientIp, details)
        passive
      } else {
        executeActiveModeAction(rule, clientIp, endpointId, details)
      }

  if (agentHandler != null) {
    sendBehaviorEvent(
        eventType = EventTypes.EVENT_BEHAVIOR_VIOLATION,
        ipAddress = clientIp,
        actionTaken = actionTaken,
        reason = "Behavioral rule violated: $details",
        metadata =
            mapOf(
                "endpoint" to endpointId,
                "rule_type" to rule.ruleType,
                "threshold" to rule.threshold,
                "window" to rule.window,
            ),
    )
  }
}

/** Port of `_send_behavior_event` (_behavior_action_dispatch.py:124). */
public suspend fun BehaviorTracker.sendBehaviorEvent(
    eventType: String,
    ipAddress: String,
    actionTaken: String,
    reason: String,
    metadata: Map<String, Any?> = emptyMap(),
) {
  val handler = agentHandler ?: return
  try {
    handler.sendEvent(
        com.guardcore.core.events.securityEventEnvelope(
            eventType = eventType,
            ipAddress = ipAddress,
            actionTaken = actionTaken,
            reason = reason,
            ruleType = metadata["rule_type"] as? String,
            handlerName = BEHAVIOR_HANDLER_NAME,
            metadata = metadata,
        ),
    )
  } catch (e: Exception) {
    logger.severe("Failed to send behavior event to agent: $e")
  }
}
