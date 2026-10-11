package com.guardcore.core.bypass

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.routing.RouteConfigResolver
import com.guardcore.core.validation.RequestValidator
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.BlockEvents
import com.guardcore.util.IpExtraction
import com.guardcore.util.RequestLogging
import java.util.logging.Logger

/**
 * Port of `guard_core/core/bypass/context.py` (context.py:9): BypassContext, the context-object DI
 * carrier for [BypassHandler].
 */
public class BypassContext(
    public val config: SecurityConfig,
    public val logger: Logger,
    public val eventBus: SecurityEventBus,
    public val routeResolver: RouteConfigResolver,
    public val responseFactory: ErrorResponseFactory,
    public val validator: RequestValidator,
)

/**
 * Port of `guard_core/core/bypass/handler.py` (handler.py:36): BypassHandler. Handles the
 * path-exclusion passthrough and the route-level all-checks bypass.
 */
public class BypassHandler(
    public val context: BypassContext,
) {
  /** Python `_no_client_address_warned` module global (handler.py:15). */
  private var noClientAddressWarned: Boolean = false

  /** Python `_warn_no_client_address` (handler.py:18): logs once per process. */
  private fun warnNoClientAddress(logger: Logger, rejected: Boolean) {
    if (noClientAddressWarned) {
      return
    }
    noClientAddressWarned = true
    val outcome =
        if (rejected) {
          "the request is rejected with 403 (fail_secure=True)"
        } else {
          "the pipeline runs with identity \"unknown\" (fail_secure=False)"
        }
    logger.warning(
        "no client address on the connection; if the app is served over a " +
            "Unix socket add \"unix\" to trusted_proxies; $outcome. This warning is logged once.",
    )
  }

  /** Python async `handle_passthrough` (handler.py:40). */
  public suspend fun handlePassthrough(
      request: GuardRequest,
      callNext: suspend (GuardRequest) -> GuardResponse?,
  ): GuardResponse? {
    if (context.validator.isPathExcluded(request)) {
      request.state.setAttr("guard_exclusion_scoped", true)
      return null
    }

    if (request.clientHost == null) {
      val clientIp = IpExtraction.extractClientIp(request, context.config)
      request.state.setAttr("client_ip", clientIp)
      if (clientIp == IpExtraction.UNKNOWN_CLIENT_IDENTITY) {
        warnNoClientAddress(context.logger, rejected = context.config.failSecure)
        if (context.config.failSecure) {
          val response =
              context.responseFactory.createErrorResponse(
                  403,
                  "Client address could not be determined",
              )
          BlockEvents.fireBlockHook(
              context.config.onBlock,
              request,
              UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME,
              "Client address could not be determined",
              "",
              false,
              response.statusCode,
              context.config.logSensitiveParams,
              context.config.logSensitiveBodyFields,
              context.config.logSensitiveHeaders,
          )
          return response
        }
      }
    }

    return null
  }

  /** Python async `handle_security_bypass` (handler.py:78). */
  public suspend fun handleSecurityBypass(
      request: GuardRequest,
      callNext: suspend (GuardRequest) -> GuardResponse?,
      routeConfig: RouteConfig?,
  ): GuardResponse? {
    if (routeConfig == null || !context.routeResolver.shouldBypassCheck("all", routeConfig)) {
      return null
    }

    context.eventBus.sendMiddlewareEvent(
        EventTypes.EVENT_SECURITY_BYPASS,
        request,
        "all_checks_bypassed",
        "Route configured to bypass all security checks",
        linkedMapOf(
            "bypassed_checks" to routeConfig.bypassedChecks.toList(),
            "endpoint" to
                RequestLogging.redactEndpointForDisplay(
                    request.urlPath,
                    context.config.logSensitiveParams,
                    context.config.logSensitiveBodyFields,
                    context.config.logSensitiveHeaders,
                ),
        ),
    )

    if (!context.config.passiveMode) {
      val response = callNext(request)
      return response?.let { context.responseFactory.applyModifier(it) }
    }

    return null
  }

  public companion object {
    /** Python `UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME` (handler.py:13). */
    public const val UNRESOLVABLE_CLIENT_ADDRESS_CHECK_NAME: String = "client_address_unresolved"
  }
}
