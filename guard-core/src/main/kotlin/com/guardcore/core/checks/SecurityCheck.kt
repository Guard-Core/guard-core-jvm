package com.guardcore.core.checks

import com.guardcore.config.SecurityConfig
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging
import java.util.logging.Logger

/**
 * Port of `guard_core/core/checks/base.py`: SecurityCheck (base.py:14), the check contract shared
 * by all 17 pipeline checks.
 */
public abstract class SecurityCheck(
    public val middleware: GuardMiddlewareProtocol,
) {
  /** Python ClassVar `requires` (base.py:15). */
  public open val requires: List<String> = emptyList()

  /** Python ClassVar `container_fields` (base.py:16). */
  public open val containerFields: List<String> = emptyList()

  /** Python ClassVar `enforced_on_excluded_paths` (base.py:17). */
  public open val enforcedOnExcludedPaths: Boolean = false

  public val config: SecurityConfig = middleware.config

  public val logger: Logger = middleware.logger

  /** Python classmethod `applies_to` (base.py:25). */
  public open fun appliesTo(
      config: SecurityConfig,
      routeConfigs: Collection<RouteConfig>?,
  ): Boolean = true

  /** Python abstract async `check` (base.py:33). */
  public abstract suspend fun check(request: GuardRequest): GuardResponse?

  /** Python abstract property `check_name` (base.py:36). */
  public abstract val checkName: String

  /** Python async `send_event` (base.py:39). */
  public open suspend fun sendEvent(
      eventType: String,
      request: GuardRequest,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    middleware.eventBus?.sendMiddlewareEvent(eventType, request, actionTaken, reason, metadata)
  }

  /** Python async `create_error_response` (base.py:55). */
  public suspend fun createErrorResponse(statusCode: Int, defaultMessage: String): GuardResponse =
      middleware.createErrorResponse(statusCode, defaultMessage)

  /** Python `is_passive_mode` (base.py:60). */
  public fun isPassiveMode(): Boolean = config.passiveMode

  /** Python async `log_if_allowed` (base.py:63). */
  public suspend fun logIfAllowed(
      request: GuardRequest,
      logType: String = "request",
      reason: String = "",
      passiveMode: Boolean = false,
      triggerInfo: String = "",
      level: String? = "WARNING",
  ) {
    RequestLogging.logActivity(
        request,
        logger,
        logType = logType,
        reason = reason,
        passiveMode = passiveMode,
        triggerInfo = triggerInfo,
        level = level,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )
  }
}
