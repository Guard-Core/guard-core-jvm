package com.guardcore.decorators

/**
 * JVM idiom for the python duck-typed decorator surface read by the pipeline factory
 * (core/checks/factory.py:57-71 reads `_route_configs` and `route_config_revision` off the
 * middleware's guard_decorator).
 */
public interface RouteConfigProvider {
  /** Python `_route_configs` (base.py:66). */
  public fun getRouteConfigs(): Map<String, RouteConfig>

  /** Python `route_config_revision` property (base.py:77); the harness stub carries the token. */
  public fun getRevisionValue(): Int
}
