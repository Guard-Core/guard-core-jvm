package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/**
 * Port of `guard_core/core/checks/implementations/request_logging.py`: RequestLoggingCheck
 * (request_logging.py:11).
 */
public class RequestLoggingCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "request_logging"

  /** Python async `check` (request_logging.py:24). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    RequestLogging.logActivity(
        request,
        logger,
        level = config.logRequestLevel?.pythonName,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )
    return null
  }

  public companion object : CheckCompanion<RequestLoggingCheck>() {
    /** Python classmethod `applies_to` (request_logging.py:16). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean = config.logRequestLevel != null

    override fun create(middleware: GuardMiddlewareProtocol): RequestLoggingCheck =
        RequestLoggingCheck(middleware)
  }
}
