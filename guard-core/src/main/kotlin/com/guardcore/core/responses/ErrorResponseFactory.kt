package com.guardcore.core.responses

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.MetricsCollector
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.configToRule
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.MiddlewareResponseFactoryProtocol
import com.guardcore.util.IpExtraction
import java.util.logging.Logger

/**
 * Port of `guard_core/core/responses/context.py` (context.py:10): ResponseContext, the
 * context-object DI carrier for [ErrorResponseFactory].
 */
public class ResponseContext(
    public val config: SecurityConfig,
    public val logger: Logger,
    public val metricsCollector: MetricsCollector,
    public val agentHandler: Any? = null,
    public val guardDecorator: BaseSecurityDecorator? = null,
    public val responseFactory: MiddlewareResponseFactoryProtocol? = null,
)

/**
 * Port of `guard_core/core/responses/factory.py` (factory.py:13): ErrorResponseFactory. Builds
 * error responses (custom message + security headers + modifier), the HTTPS redirect, and the
 * response-exit path (behavioral rules + metrics + headers + CORS + modifier).
 */
public class ErrorResponseFactory(
    public val context: ResponseContext,
) {
  public val logger: Logger = Logger.getLogger("guard_core.core.responses.factory")

  /** Python async `create_error_response` (factory.py:18). */
  public suspend fun createErrorResponse(statusCode: Int, defaultMessage: String): GuardResponse {
    val customMessage = context.config.customErrorResponses[statusCode] ?: defaultMessage
    var response =
        context.responseFactory?.createResponse(customMessage, statusCode)
            ?: throw IllegalStateException("response_factory is required on ResponseContext")

    response = applySecurityHeaders(response)

    response = applyModifier(response)

    return response
  }

  /** Python async `create_https_redirect` (factory.py:34). */
  public suspend fun createHttpsRedirect(request: GuardRequest): GuardResponse {
    val httpsUrl = request.urlReplaceScheme("https")
    val redirectResponse =
        context.responseFactory?.createRedirectResponse(httpsUrl, 301)
            ?: throw IllegalStateException("response_factory is required on ResponseContext")

    return applyModifier(redirectResponse)
  }

  /** Python async `apply_security_headers` (factory.py:42). */
  public suspend fun applySecurityHeaders(
      response: GuardResponse,
      requestPath: String? = null,
  ): GuardResponse {
    val headersConfig = context.config.securityHeaders
    if (headersConfig != null && (headersConfig["enabled"] as? Boolean ?: true)) {
      val securityHeaders =
          SecurityHeadersManager.getInstance().getHeaders(requestPath, config = context.config)
      for ((headerName, headerValue) in securityHeaders) {
        response.headers[headerName] = headerValue
      }
    }

    return response
  }

  /** Python async `apply_cors_headers` (factory.py:55). */
  public suspend fun applyCorsHeaders(response: GuardResponse, origin: String): GuardResponse {
    val headersConfig = context.config.securityHeaders
    if (headersConfig != null && (headersConfig["enabled"] as? Boolean ?: true)) {
      val corsHeaders =
          SecurityHeadersManager.getInstance().getCorsHeaders(origin, config = context.config)
      for ((headerName, headerValue) in corsHeaders) {
        response.headers[headerName] = headerValue
      }
    }

    return response
  }

  /** Python async `apply_modifier` (factory.py:68). */
  public suspend fun applyModifier(response: GuardResponse): GuardResponse {
    val modifier = context.config.customResponseModifier
    if (modifier != null) {
      try {
        return modifier.invoke(response)
      } catch (exc: Exception) {
        logger.severe("custom_response_modifier raised $exc; returning unmodified response")
      }
    }
    return response
  }

  /** Python async `process_response` (factory.py:82). */
  public suspend fun processResponse(
      request: GuardRequest,
      response: GuardResponse,
      responseTime: Double,
      routeConfig: RouteConfig?,
      processBehavioralRules:
          (suspend (GuardRequest, GuardResponse, String, RouteConfig) -> Unit)? =
          null,
      processGlobalBehavioralRules:
          (suspend (GuardRequest, GuardResponse, String, List<BehaviorRule>) -> Unit)? =
          null,
  ): GuardResponse {
    val clientIp =
        resolveClientIpForBehavioralRules(
            request,
            routeConfig,
            processBehavioralRules,
            processGlobalBehavioralRules,
        )

    if (
        clientIp != null &&
            routeConfig != null &&
            routeConfig.behaviorRules.isNotEmpty() &&
            processBehavioralRules != null
    ) {
      processBehavioralRules(request, response, clientIp, routeConfig)
    }

    if (
        clientIp != null &&
            context.config.globalBehaviorRules.isNotEmpty() &&
            processGlobalBehavioralRules != null
    ) {
      val globalRules = context.config.globalBehaviorRules.map { configToRule(it) }
      processGlobalBehavioralRules(request, response, clientIp, globalRules)
    }

    context.metricsCollector.collectRequestMetrics(request, responseTime, response.statusCode)

    val withHeaders = applySecurityHeaders(response, request.urlPath)

    val origin = request.headers["origin"]
    val withCors = if (origin != null) applyCorsHeaders(withHeaders, origin) else withHeaders

    return applyModifier(withCors)
  }

  /** Python async `_resolve_client_ip_for_behavioral_rules` (factory.py:136). */
  private suspend fun resolveClientIpForBehavioralRules(
      request: GuardRequest,
      routeConfig: RouteConfig?,
      processBehavioralRules: (suspend (GuardRequest, GuardResponse, String, RouteConfig) -> Unit)?,
      processGlobalBehavioralRules:
          (suspend (GuardRequest, GuardResponse, String, List<BehaviorRule>) -> Unit)?,
  ): String? {
    val needsClientIp =
        (routeConfig != null &&
            routeConfig.behaviorRules.isNotEmpty() &&
            processBehavioralRules != null) ||
            (context.config.globalBehaviorRules.isNotEmpty() &&
                processGlobalBehavioralRules != null)
    if (!needsClientIp) {
      return null
    }
    return IpExtraction.extractClientIp(
        request,
        context.config,
        context.agentHandler as? com.guardcore.protocols.AgentHandlerProtocol,
    )
  }
}
