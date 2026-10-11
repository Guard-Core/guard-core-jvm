package com.guardcore.core.checks.implementations

import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.IpExtraction
import com.guardcore.util.RequestLogging

/** Python `UNRESOLVED_ROUTE_REASON` (route_config.py:7). */
public const val UNRESOLVED_ROUTE_REASON: String =
    "Route resolution failed; per-route decorator config could not be applied"

/**
 * Port of `guard_core/core/checks/implementations/route_config.py`: RouteConfigCheck
 * (route_config.py:12). Pins the resolved route config and the extracted client IP onto the request
 * state for every later check.
 */
public class RouteConfigCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val enforcedOnExcludedPaths: Boolean = true

  override val checkName: String = "route_config"

  /** Python async `_handle_unresolved_route` (route_config.py:19). */
  private suspend fun handleUnresolvedRoute(request: GuardRequest): GuardResponse? {
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = UNRESOLVED_ROUTE_REASON,
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
        EventTypes.EVENT_ROUTE_UNRESOLVED,
        request,
        if (!config.passiveMode) "request_blocked" else "logged_only",
        UNRESOLVED_ROUTE_REASON,
    )
    if (!config.passiveMode) {
      return middleware.createErrorResponse(500, "Route resolution failed")
    }
    return null
  }

  /** Python async `check` (route_config.py:51). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = middleware.routeResolver?.getRouteConfig(request) as? RouteConfig
    request.state.setAttr("route_config", routeConfig)
    request.state.setAttr(
        "client_ip",
        IpExtraction.extractClientIp(request, config, middleware.agentHandler),
    )
    if (config.routeResolutionStrict && request.state.getAttr("guard_route_unresolved") == true) {
      return handleUnresolvedRoute(request)
    }
    return null
  }

  public companion object : CheckCompanion<RouteConfigCheck>() {
    override fun create(middleware: GuardMiddlewareProtocol): RouteConfigCheck =
        RouteConfigCheck(middleware)
  }
}
