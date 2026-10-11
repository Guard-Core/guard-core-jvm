package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/**
 * Port of `guard_core/core/checks/implementations/suspicious_activity.py`: SuspiciousActivityCheck
 * (suspicious_activity.py:25).
 */
public class SuspiciousActivityCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  /** Python `__init__` (suspicious_activity.py:26). */
  private val ipBanManager: IpBanManager = IpBanManager.getInstance()

  override val checkName: String = "suspicious_activity"

  /** Python `_total_count_for_ip` (suspicious_activity.py:50). */
  private fun totalCountForIp(clientIp: String): Int =
      middleware.suspiciousRequestCounts[clientIp]?.values?.sum() ?: 0

  /** Python async `_handle_suspicious_passive_mode` (suspicious_activity.py:55). */
  private suspend fun handleSuspiciousPassiveMode(
      request: GuardRequest,
      clientIp: String,
      triggerInfo: String,
  ) {
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Suspicious activity detected: $clientIp",
        passiveMode = true,
        triggerInfo = triggerInfo,
        level = config.logSuspiciousLevel?.pythonName,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    val message = "Suspicious pattern detected (passive mode)"

    middleware.eventBus?.sendMiddlewareEvent(
        EventTypes.EVENT_PENETRATION_ATTEMPT,
        request,
        "logged_only",
        "$message: $triggerInfo",
        linkedMapOf(
            "request_count" to totalCountForIp(clientIp),
            "passive_mode" to true,
            "trigger_info" to triggerInfo,
        ),
    )
  }

  /** Python async `_handle_suspicious_active_mode` (suspicious_activity.py:86). */
  private suspend fun handleSuspiciousActiveMode(
      request: GuardRequest,
      clientIp: String,
      triggerInfo: String,
      threatCategories: List<String>,
  ): GuardResponse {
    val banned =
        ChecksHelpers.tryThresholdBan(
            request,
            config,
            ipBanManager,
            middleware,
            clientIp,
            triggerInfo,
            logger,
            checkName,
            config.mutedCheckLogs,
            threatCategories,
        )
    if (banned) {
      return middleware.createErrorResponse(403, "IP has been banned")
    }

    val susSpecs = "$clientIp - $triggerInfo"
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Suspicious activity detected for IP: $susSpecs",
        level = config.logSuspiciousLevel?.pythonName,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    middleware.eventBus?.sendMiddlewareEvent(
        EventTypes.EVENT_PENETRATION_ATTEMPT,
        request,
        "request_blocked",
        "Penetration attempt detected: $triggerInfo",
        linkedMapOf(
            "request_count" to totalCountForIp(clientIp),
            "trigger_info" to triggerInfo,
        ),
    )

    return middleware.createErrorResponse(400, "Suspicious activity detected")
  }

  /** Python async `check` (suspicious_activity.py:140). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    if (request.state.getAttr("is_whitelisted") == true) {
      return null
    }

    val clientIp = request.state.getAttr("client_ip") as? String
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig

    if (clientIp.isNullOrEmpty()) {
      return null
    }

    val result =
        ChecksHelpers.getCachedDetectionResult(
            request,
            routeConfig,
            config,
        ) { name, rc ->
          middleware.routeResolver?.shouldBypassCheck(name, rc) ?: false
        }

    if (result.triggerInfo == "disabled_by_decorator") {
      middleware.eventBus?.sendMiddlewareEvent(
          EventTypes.EVENT_DECORATOR_VIOLATION,
          request,
          "detection_disabled",
          "Suspicious pattern detection disabled by route decorator",
          linkedMapOf(
              "decorator_type" to "advanced",
              "violation_type" to "suspicious_detection_disabled",
          ),
      )
      return null
    }

    if (!result.isThreat) {
      return null
    }

    val triggerInfo = result.triggerInfo
    val threatCategories = result.threatCategories.toList()

    ChecksHelpers.incrementSuspiciousCounts(middleware, clientIp, threatCategories)

    if (config.passiveMode) {
      handleSuspiciousPassiveMode(request, clientIp, triggerInfo)
      return null
    }

    return handleSuspiciousActiveMode(request, clientIp, triggerInfo, threatCategories)
  }

  public companion object : CheckCompanion<SuspiciousActivityCheck>() {
    /** Python classmethod `applies_to` (suspicious_activity.py:36). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        config.enablePenetrationDetection ||
            ChecksHelpers.routeConfigApplies(routeConfigs) { rc -> rc.enableSuspiciousDetection } ||
            config.enableDynamicRules

    override fun create(middleware: GuardMiddlewareProtocol): SuspiciousActivityCheck =
        SuspiciousActivityCheck(middleware)
  }
}
