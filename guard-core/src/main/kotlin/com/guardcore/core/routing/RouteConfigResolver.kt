package com.guardcore.core.routing

import com.guardcore.config.SecurityConfig
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RouteConfigResolverProtocol
import java.util.logging.Logger

/**
 * Port of `guard_core/core/routing/context.py` (context.py:7): RoutingContext, the context-object
 * DI carrier for the route resolver.
 */
public class RoutingContext(
    public val config: SecurityConfig,
    public val logger: Logger,
    public val guardDecorator: BaseSecurityDecorator? = null,
)

/**
 * Port of `guard_core/core/routing/resolver.py` (resolver.py:6): RouteConfigResolver. Resolves the
 * effective per-route RouteConfig and the check-bypass/provider decisions.
 */
public class RouteConfigResolver(
    public val context: RoutingContext,
) : RouteConfigResolverProtocol {
  /** Python `get_route_config` (resolver.py:10). */
  override fun getRouteConfig(request: GuardRequest): RouteConfig? {
    var guardDecorator = context.guardDecorator
    if (guardDecorator == null) {
      guardDecorator = request.state.getAttr("guard_decorator") as? BaseSecurityDecorator
    }
    if (guardDecorator == null) {
      return null
    }

    val routeId = request.state.getAttr("guard_route_id") as? String
    if (routeId == null || routeId.isEmpty()) {
      return null
    }

    return guardDecorator.getRouteConfig(routeId)
  }

  /** Python `should_bypass_check` (resolver.py:23). */
  override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean {
    val rc = routeConfig as? RouteConfig ?: return false
    return checkName in rc.bypassedChecks || "all" in rc.bypassedChecks
  }

  /** Python `get_cloud_providers_to_check` (resolver.py:33). */
  override fun getCloudProvidersToCheck(routeConfig: Any?): List<String>? {
    val rc = routeConfig as? RouteConfig
    if (rc != null && rc.blockCloudProviders.isNotEmpty()) {
      return rc.blockCloudProviders.toList()
    }
    if (context.config.blockCloudProviders?.isNotEmpty() == true) {
      return context.config.blockCloudProviders!!.toList()
    }
    return null
  }
}
