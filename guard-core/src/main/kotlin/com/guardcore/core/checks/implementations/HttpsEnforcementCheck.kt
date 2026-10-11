package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.py.IpNetwork as PyIpNetwork
import com.guardcore.util.py.parseAddress as pyParseAddress

/**
 * Port of `guard_core/core/checks/implementations/https_enforcement.py`: HttpsEnforcementCheck
 * (https_enforcement.py:11).
 */
public class HttpsEnforcementCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val checkName: String = "https_enforcement"

  /** Python `_is_request_https` (https_enforcement.py:26). */
  private fun isRequestHttps(request: GuardRequest): Boolean {
    var isHttps = request.urlScheme == "https"

    if (
        config.trustXForwardedProto &&
            config.trustedProxies.isNotEmpty() &&
            request.clientHost != null
    ) {
      if (isTrustedProxy(request.clientHost!!)) {
        val forwardedProto = request.headers["X-Forwarded-Proto"] ?: ""
        isHttps = isHttps || forwardedProto.lowercase() == "https"
      }
    }

    return isHttps
  }

  /** Python `_is_trusted_proxy` (https_enforcement.py:40). */
  private fun isTrustedProxy(connectingIp: String): Boolean {
    for (proxy in config.trustedProxies) {
      if ("/" !in proxy) {
        if (connectingIp == proxy) {
          return true
        }
      } else {
        // python: ip_address(connecting_ip) in ip_network(proxy, strict=False)
        if (PyIpNetwork.parse(proxy).contains(pyParseAddress(connectingIp))) {
          return true
        }
      }
    }
    return false
  }

  /** Python async `_create_https_redirect` (https_enforcement.py:52). */
  private suspend fun createHttpsRedirect(request: GuardRequest): GuardResponse =
      middleware.responseFactory?.createHttpsRedirect(request)
          ?: throw IllegalStateException(
              "middleware.response_factory is required for HTTPS redirect",
          )

  /** Python async `check` (https_enforcement.py:58). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig

    val httpsRequired = routeConfig?.requireHttps ?: config.enforceHttps
    if (!httpsRequired) {
      return null
    }

    if (isRequestHttps(request)) {
      return null
    }

    middleware.eventBus?.sendHttpsViolationEvent(request, routeConfig)

    if (!config.passiveMode) {
      return createHttpsRedirect(request)
    }

    return null
  }

  public companion object : CheckCompanion<HttpsEnforcementCheck>() {
    /** Python classmethod `applies_to` (https_enforcement.py:16). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean =
        config.enforceHttps ||
            ChecksHelpers.routeConfigApplies(routeConfigs) { rc -> rc.requireHttps }

    override fun create(middleware: GuardMiddlewareProtocol): HttpsEnforcementCheck =
        HttpsEnforcementCheck(middleware)
  }
}
