package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/** Port of `guard_core/core/checks/implementations/referrer.py`: ReferrerCheck (referrer.py:18). */
public class ReferrerCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "referrer"

  /** Python async `_handle_missing_referrer` (referrer.py:31). */
  private suspend fun handleMissingReferrer(
      request: GuardRequest,
      routeConfig: RouteConfig,
  ): GuardResponse? {
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Missing referrer header",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
        reason = "Missing referrer header",
        decoratorType = "content_filtering",
        passiveMode = config.passiveMode,
        linkedMapOf(
            "violation_type" to "require_referrer",
            "allowed_domains" to routeConfig.requireReferrer,
        ),
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(403, "Referrer required")
    }

    return null
  }

  /** Python async `_handle_invalid_referrer` (referrer.py:68). */
  private suspend fun handleInvalidReferrer(
      request: GuardRequest,
      referrer: String,
      routeConfig: RouteConfig,
  ): GuardResponse? {
    val redactedReferrer =
        RequestLogging.redactUrlForDisplay(
            referrer,
            config.logSensitiveParams,
            config.logSensitiveBodyFields,
            config.logSensitiveHeaders,
        )
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Invalid referrer: $redactedReferrer",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
        reason = "Referrer '$redactedReferrer' not in allowed domains",
        decoratorType = "content_filtering",
        passiveMode = config.passiveMode,
        linkedMapOf(
            "violation_type" to "require_referrer",
            "referrer" to redactedReferrer,
            "allowed_domains" to routeConfig.requireReferrer,
        ),
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(403, "Invalid referrer")
    }

    return null
  }

  /** Python async `check` (referrer.py:112). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    val requireReferrer = routeConfig?.requireReferrer
    if (routeConfig == null || requireReferrer.isNullOrEmpty()) {
      return null
    }

    val referrer = request.headers["referer"] ?: ""

    if (referrer.isEmpty()) {
      return handleMissingReferrer(request, routeConfig)
    }

    if (!ChecksHelpers.isReferrerDomainAllowed(referrer, requireReferrer)) {
      return handleInvalidReferrer(request, referrer, routeConfig)
    }

    return null
  }

  public companion object : CheckCompanion<ReferrerCheck>() {
    /** Python classmethod `applies_to` (referrer.py:23). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        ChecksHelpers.routeConfigApplies(routeConfigs) { rc -> !rc.requireReferrer.isNullOrEmpty() }

    override fun create(middleware: GuardMiddlewareProtocol): ReferrerCheck =
        ReferrerCheck(middleware)
  }
}
