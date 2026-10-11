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

/**
 * Port of `guard_core/core/checks/implementations/request_size_content.py`: RequestSizeContentCheck
 * (request_size_content.py:14).
 */
public class RequestSizeContentCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "request_size_content"

  /** Python async `_check_request_size_limit` (request_size_content.py:32). */
  private suspend fun checkRequestSizeLimit(
      request: GuardRequest,
      routeConfig: RouteConfig,
  ): GuardResponse? {
    val maxRequestSize = routeConfig.maxRequestSize
    if (maxRequestSize == null || maxRequestSize == 0) {
      return null
    }

    val contentLength = request.headers["content-length"]
    // python int(content_length) raises ValueError on garbage; NumberFormatException propagates the
    // same way into the pipeline's per-check error handler.
    if (contentLength.isNullOrEmpty() || contentLength.toInt() <= maxRequestSize) {
      return null
    }

    val message = "Request size $contentLength exceeds limit"

    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "$message: $maxRequestSize",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    ChecksHelpers.emitDecoratorEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_CONTENT_FILTERED,
        actionTaken = if (!config.passiveMode) "request_blocked" else "logged_only",
        reason = "$message: $maxRequestSize",
        decoratorType = "content_filtering",
        linkedMapOf("violation_type" to "max_request_size"),
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(413, "Request too large")
    }

    return null
  }

  /** Python async `_check_content_type_allowed` (request_size_content.py:79). */
  private suspend fun checkContentTypeAllowed(
      request: GuardRequest,
      routeConfig: RouteConfig,
  ): GuardResponse? {
    val allowedContentTypes = routeConfig.allowedContentTypes
    if (allowedContentTypes.isNullOrEmpty()) {
      return null
    }

    val contentType = (request.headers["content-type"] ?: "").split(";")[0]
    if (contentType in allowedContentTypes) {
      return null
    }

    val redactedContentType =
        RequestLogging.redactHeaderValueForDisplay(
            contentType,
            config.logSensitiveParams,
            config.logSensitiveBodyFields,
            config.logSensitiveHeaders,
        )
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Invalid content type: $redactedContentType",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    ChecksHelpers.emitDecoratorEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_CONTENT_FILTERED,
        actionTaken = if (!config.passiveMode) "request_blocked" else "logged_only",
        reason = "Content type not in allowed types: $allowedContentTypes",
        decoratorType = "content_filtering",
        linkedMapOf("violation_type" to "content_type"),
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(415, "Unsupported content type")
    }

    return null
  }

  /** Python async `check` (request_size_content.py:131). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig ?: return null

    val sizeResponse = checkRequestSizeLimit(request, routeConfig)
    if (sizeResponse != null) {
      return sizeResponse
    }

    return checkContentTypeAllowed(request, routeConfig)
  }

  public companion object : CheckCompanion<RequestSizeContentCheck>() {
    /** Python classmethod `applies_to` (request_size_content.py:19). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        ChecksHelpers.routeConfigApplies(routeConfigs) { rc ->
          rc.maxRequestSize != null || !rc.allowedContentTypes.isNullOrEmpty()
        }

    override fun create(middleware: GuardMiddlewareProtocol): RequestSizeContentCheck =
        RequestSizeContentCheck(middleware)
  }
}
