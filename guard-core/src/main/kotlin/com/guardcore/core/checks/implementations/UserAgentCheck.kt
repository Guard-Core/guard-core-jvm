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
 * Port of `guard_core/core/checks/implementations/user_agent.py`: UserAgentCheck
 * (user_agent.py:26).
 */
public class UserAgentCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val containerFields: List<String> = listOf("blocked_user_agents")

  /** Python `__init__` (user_agent.py:29). */
  private val ipBanManager: IpBanManager = IpBanManager.getInstance()

  override val checkName: String = "user_agent"

  /** Python async `check` (user_agent.py:53). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    if (
        request.state.getAttr("is_whitelisted") == true ||
            request.state.getAttr("is_exempt") == true
    ) {
      return null
    }

    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    val userAgent = request.headers["User-Agent"] ?: ""

    if (!ChecksHelpers.checkUserAgentAllowed(userAgent, routeConfig, config)) {
      val redactedUserAgent =
          RequestLogging.redactHeaderValueForDisplay(
              userAgent,
              config.logSensitiveParams,
              config.logSensitiveBodyFields,
              config.logSensitiveHeaders,
          )
      RequestLogging.logActivity(
          request,
          logger,
          logType = "suspicious",
          reason = "Blocked user agent: $redactedUserAgent",
          level = config.logSuspiciousLevel?.pythonName,
          passiveMode = config.passiveMode,
          checkName = checkName,
          mutedCheckLogs = config.mutedCheckLogs,
          onBlock = config.onBlock,
          sensitiveHeaders = config.logSensitiveHeaders,
          sensitiveParams = config.logSensitiveParams,
          sensitiveBodyFields = config.logSensitiveBodyFields,
      )

      if (routeConfig?.blockedUserAgents?.isNotEmpty() == true) {
        ChecksHelpers.emitDecoratorEvent(
            middleware,
            request,
            eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
            actionTaken = if (!config.passiveMode) "request_blocked" else "logged_only",
            reason = "User agent '$redactedUserAgent' blocked",
            decoratorType = "access_control",
            linkedMapOf(
                "violation_type" to "user_agent",
                "blocked_user_agent" to redactedUserAgent,
            ),
        )
      } else {
        middleware.eventBus?.sendMiddlewareEvent(
            EventTypes.EVENT_USER_AGENT_BLOCKED,
            request,
            if (!config.passiveMode) "request_blocked" else "logged_only",
            "User agent '$redactedUserAgent' in global blocklist",
            linkedMapOf(
                "user_agent" to redactedUserAgent,
                "filter_type" to "global",
            ),
        )
      }

      if (!config.passiveMode) {
        val clientIp = request.state.getAttr("client_ip") as? String
        if (!clientIp.isNullOrEmpty()) {
          ChecksHelpers.escalateIdentityViolation(
              middleware,
              config,
              ipBanManager,
              request,
              clientIp,
              logger,
              checkName,
              config.mutedCheckLogs,
              "user_agent",
              "Blocked user agent: $redactedUserAgent",
          )
        }
        return middleware.createErrorResponse(403, "User-Agent not allowed")
      }
    }
    return null
  }

  public companion object : CheckCompanion<UserAgentCheck>() {
    /** Python classmethod `applies_to` (user_agent.py:39). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        config.blockedUserAgents.isNotEmpty() ||
            ChecksHelpers.routeConfigApplies(routeConfigs) { rc ->
              rc.blockedUserAgents.isNotEmpty()
            } ||
            config.enableDynamicRules

    override val containerFields: List<String> = listOf("blocked_user_agents")

    override fun create(middleware: GuardMiddlewareProtocol): UserAgentCheck =
        UserAgentCheck(middleware)
  }
}
