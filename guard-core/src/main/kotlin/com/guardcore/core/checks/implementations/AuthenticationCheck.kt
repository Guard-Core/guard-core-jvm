package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.Verifier
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/**
 * Port of `guard_core/core/checks/implementations/authentication.py`: AuthenticationCheck
 * (authentication.py:19).
 */
public class AuthenticationCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "authentication"

  /** Python async `_handle_auth_failure` (authentication.py:39). */
  private suspend fun handleAuthFailure(
      request: GuardRequest,
      authReason: String,
      routeConfig: RouteConfig,
      violationType: String = "require_auth",
  ): GuardResponse? {
    RequestLogging.logActivity(
        request,
        logger,
        logType = "suspicious",
        reason = "Authentication failure: $authReason",
        level = config.logSuspiciousLevel?.pythonName,
        passiveMode = config.passiveMode,
        checkName = checkName,
        mutedCheckLogs = config.mutedCheckLogs,
        onBlock = config.onBlock,
        sensitiveHeaders = config.logSensitiveHeaders,
        sensitiveParams = config.logSensitiveParams,
        sensitiveBodyFields = config.logSensitiveBodyFields,
    )

    val authType = routeConfig.authRequired ?: routeConfig.authorizationHeaderRequired ?: "api_key"
    ChecksHelpers.emitAuthenticationFailedEvent(
        middleware,
        request,
        eventType = EventTypes.EVENT_DECORATOR_VIOLATION,
        reason = authReason,
        authType = authType,
        violationType = violationType,
        passiveMode = config.passiveMode,
    )

    if (!config.passiveMode) {
      return middleware.createErrorResponse(401, "Authentication required")
    }

    return null
  }

  /** Python async `_check_presence` (authentication.py:84). */
  private suspend fun checkPresence(
      request: GuardRequest,
      routeConfig: RouteConfig,
      scheme: String,
  ): GuardResponse? {
    val authHeader = request.headers["authorization"] ?: ""
    val (credential, reason) = ChecksHelpers.extractCredential(authHeader, scheme)
    if (credential == null) {
      return handleAuthFailure(request, reason, routeConfig, violationType = "authorization_header")
    }
    return null
  }

  /** Python async `_resolve_credential` (authentication.py:95). */
  private suspend fun resolveCredential(
      request: GuardRequest,
      routeConfig: RouteConfig,
  ): Triple<GuardResponse?, Any?, String> {
    val authRequired = routeConfig.authRequired
    if (authRequired != null) {
      val verifier = routeConfig.authVerifier ?: config.authVerifier
      val authHeader = request.headers["authorization"] ?: ""
      val (credential, reason) = ChecksHelpers.extractCredential(authHeader, authRequired)
      if (credential == null) {
        val failure = handleAuthFailure(request, reason, routeConfig)
        return Triple(failure, null, "")
      }
      return Triple(null, verifier, credential)
    }
    val verifier = routeConfig.apiKeyVerifier ?: config.authVerifier
    val credential = request.headers[routeConfig.apiKeyHeader ?: ""] ?: ""
    if (credential.isEmpty()) {
      val failure = handleAuthFailure(request, "Missing API key", routeConfig)
      return Triple(failure, null, "")
    }
    return Triple(null, verifier, credential)
  }

  /** Python async `check` (authentication.py:120). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig ?: return null

    val presenceScheme = routeConfig.authorizationHeaderRequired
    if (presenceScheme != null) {
      return checkPresence(request, routeConfig, presenceScheme)
    }

    if (routeConfig.authRequired == null && !routeConfig.apiKeyRequired) {
      return null
    }

    val (failure, verifier, credential) = resolveCredential(request, routeConfig)
    if (failure != null) {
      return failure
    }

    if (verifier == null) {
      return handleAuthFailure(request, "No auth verifier configured", routeConfig)
    }

    val result =
        try {
          val value =
              when (verifier) {
                is com.guardcore.config.AuthVerifier -> verifier.invoke(request, credential)
                is com.guardcore.decorators.RouteAuthVerifier ->
                    verifier.invoke(request, credential)
                else -> throw IllegalStateException("unsupported auth verifier type")
              }
          Verifier.resolveVerifierResult(value)
        } catch (e: Exception) {
          return handleAuthFailure(request, "Authentication error", routeConfig)
        }
    if (!Verifier.truthy(result)) {
      return handleAuthFailure(request, "Authentication failed", routeConfig)
    }

    request.state.setAttr("auth_principal", result)
    return null
  }

  public companion object : CheckCompanion<AuthenticationCheck>() {
    /** Python classmethod `applies_to` (authentication.py:24). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        ChecksHelpers.routeConfigApplies(routeConfigs) { rc ->
          rc.authRequired != null || rc.apiKeyRequired || rc.authorizationHeaderRequired != null
        }

    override fun create(middleware: GuardMiddlewareProtocol): AuthenticationCheck =
        AuthenticationCheck(middleware)
  }
}
