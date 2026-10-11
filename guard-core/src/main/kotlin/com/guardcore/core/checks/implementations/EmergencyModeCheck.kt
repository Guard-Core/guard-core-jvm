package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.AccessControl
import com.guardcore.util.IpExtraction
import com.guardcore.util.RequestLogging
import com.guardcore.util.py.IpAddress as PyIpAddress
import com.guardcore.util.py.parseAddress as pyParseAddress

/**
 * Port of `guard_core/core/checks/implementations/emergency_mode.py`: EmergencyModeCheck
 * (emergency_mode.py:13).
 */
public class EmergencyModeCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "emergency_mode"

  /** Python async `check` (emergency_mode.py:26). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    if (!config.emergencyMode) {
      return null
    }

    var clientIp = request.state.getAttr("client_ip") as? String
    if (clientIp.isNullOrEmpty()) {
      clientIp = IpExtraction.extractClientIp(request, config, middleware.agentHandler)
    }

    val clientIpAddr: PyIpAddress? =
        try {
          pyParseAddress(clientIp)
        } catch (e: com.guardcore.errors.ConfigValidationError) {
          null
        }

    val isWhitelisted =
        clientIpAddr != null &&
            AccessControl.ipInList(clientIpAddr, clientIp, config.emergencyWhitelist)

    if (!isWhitelisted) {
      RequestLogging.logActivity(
          request,
          logger,
          logType = "suspicious",
          reason = "[EMERGENCY MODE] Access denied for IP $clientIp",
          level = config.logSuspiciousLevel?.pythonName,
          passiveMode = config.passiveMode,
          checkName = checkName,
          mutedCheckLogs = config.mutedCheckLogs,
          onBlock = config.onBlock,
          sensitiveHeaders = config.logSensitiveHeaders,
          sensitiveParams = config.logSensitiveParams,
          sensitiveBodyFields = config.logSensitiveBodyFields,
      )

      middleware.eventBus?.sendMiddlewareEvent(
          EventTypes.EVENT_EMERGENCY_MODE_BLOCK,
          request,
          if (!config.passiveMode) "request_blocked" else "logged_only",
          "[EMERGENCY MODE] IP $clientIp not in whitelist",
          linkedMapOf(
              "emergency_whitelist_count" to config.emergencyWhitelist.size,
              "emergency_active" to true,
          ),
      )

      if (!config.passiveMode) {
        return middleware.createErrorResponse(503, "Service temporarily unavailable")
      }
    } else {
      RequestLogging.logActivity(
          request,
          logger,
          logType = "info",
          reason = "[EMERGENCY MODE] Allowed access for whitelisted IP $clientIp",
          level = "INFO",
          checkName = checkName,
          mutedCheckLogs = config.mutedCheckLogs,
          sensitiveHeaders = config.logSensitiveHeaders,
          sensitiveParams = config.logSensitiveParams,
          sensitiveBodyFields = config.logSensitiveBodyFields,
      )
    }

    return null
  }

  public companion object : CheckCompanion<EmergencyModeCheck>() {
    /** Python classmethod `applies_to` (emergency_mode.py:18). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean = config.emergencyMode || config.enableDynamicRules

    override fun create(middleware: GuardMiddlewareProtocol): EmergencyModeCheck =
        EmergencyModeCheck(middleware)
  }
}
