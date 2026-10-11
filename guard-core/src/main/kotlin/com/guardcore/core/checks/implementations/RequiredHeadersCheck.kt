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

/** Python `_classify_header_violation` (required_headers.py:16). */
private fun classifyHeaderViolation(headerName: String): Pair<String, String> {
  val headerLower = headerName.lowercase()
  if (headerLower == "x-api-key") {
    return "authentication" to "api_key_required"
  }
  if (headerLower == "authorization") {
    return "authentication" to "required_header"
  }
  return "advanced" to "required_header"
}

/**
 * Port of `guard_core/core/checks/implementations/required_headers.py`: RequiredHeadersCheck
 * (required_headers.py:26).
 */
public class RequiredHeadersCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "required_headers"

  /** Python async `_report_header_violation` (required_headers.py:39). */
  private suspend fun reportHeaderViolation(
      request: GuardRequest,
      header: String,
      reason: String,
      headerField: String,
  ): GuardResponse? {
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = reason,
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    val (decoratorType, violationType) = classifyHeaderViolation(header)

    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
        reason = reason,
        decoratorType = decoratorType,
        passiveMode = config.passiveMode,
        linkedMapOf(headerField to header),
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(400, reason)
    }
    return null
  }

  /** Python async `_handle_missing_header` (required_headers.py:82). */
  private suspend fun handleMissingHeader(request: GuardRequest, header: String): GuardResponse? {
    val reason = "Missing required header: $header"
    return reportHeaderViolation(request, header, reason, headerField = "missing_header")
  }

  /** Python async `_handle_mismatched_header` (required_headers.py:90). */
  private suspend fun handleMismatchedHeader(
      request: GuardRequest,
      header: String,
  ): GuardResponse? {
    val reason = "Header '$header' does not match the required value"
    return reportHeaderViolation(request, header, reason, headerField = "mismatched_header")
  }

  /** Python async `check` (required_headers.py:98). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig
    val requiredHeaders = routeConfig?.requiredHeaders
    if (routeConfig == null || requiredHeaders.isNullOrEmpty()) {
      return null
    }

    for ((header, expected) in requiredHeaders) {
      val actual = request.headers[header]
      if (actual.isNullOrEmpty()) {
        return handleMissingHeader(request, header)
      }
      if (expected != "required" && actual != expected) {
        return handleMismatchedHeader(request, header)
      }
    }

    return null
  }

  public companion object : CheckCompanion<RequiredHeadersCheck>() {
    /** Python classmethod `applies_to` (required_headers.py:31). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        ChecksHelpers.routeConfigApplies(routeConfigs) { rc -> rc.requiredHeaders.isNotEmpty() }

    override fun create(middleware: GuardMiddlewareProtocol): RequiredHeadersCheck =
        RequiredHeadersCheck(middleware)
  }
}
