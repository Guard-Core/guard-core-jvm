package com.guardcore.protocols

/**
 * Ports of the duck-typed middleware surfaces the checks and support modules call through
 * (`guard_core/protocols/middleware_protocol.py` declares them as ``Any``; the JVM port names them
 * so implementations are checked).
 *
 * - [MiddlewareEventBusProtocol]: the `event_bus` seam
 *   (core/events/middleware_events.py:111/137/168 are the three call shapes).
 * - [RouteConfigResolverProtocol]: the `route_resolver` seam (core/routing/resolver.py:10/23/33).
 * - [MiddlewareResponseFactoryProtocol]: the `response_factory` seam (responses/factory.py:36/68
 *   and https_enforcement.py:53 call shapes).
 */
public interface MiddlewareEventBusProtocol {
  /** Python `SecurityEventBus.send_middleware_event` (middleware_events.py:111). */
  public suspend fun sendMiddlewareEvent(
      eventType: String,
      request: GuardRequest,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?> = emptyMap(),
  )

  /** Python `SecurityEventBus.send_https_violation_event` (middleware_events.py:137). */
  public suspend fun sendHttpsViolationEvent(request: GuardRequest, routeConfig: Any?)

  /** Python `SecurityEventBus.send_cloud_detection_events` (middleware_events.py:168). */
  public suspend fun sendCloudDetectionEvents(
      request: GuardRequest,
      clientIp: String,
      cloudProvidersToCheck: List<String>,
      routeConfig: Any?,
      cloudHandler: Any?,
      passiveMode: Boolean,
  )
}

public interface RouteConfigResolverProtocol {
  /** Python `RouteConfigResolver.get_route_config` (resolver.py:10). */
  public fun getRouteConfig(request: GuardRequest): Any?

  /** Python `RouteConfigResolver.should_bypass_check` (resolver.py:23). */
  public fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean

  /** Python `RouteConfigResolver.get_cloud_providers_to_check` (resolver.py:33). */
  public fun getCloudProvidersToCheck(routeConfig: Any?): List<String>?
}

public interface MiddlewareResponseFactoryProtocol {
  /** Python `ResponseFactory.create_response` (factory protocol create_response). */
  public fun createResponse(content: Any?, statusCode: Int): GuardResponse

  /** Python `ResponseFactory.create_redirect_response`. */
  public fun createRedirectResponse(url: Any?, statusCode: Int): GuardResponse

  /** Python `middleware.response_factory.create_https_redirect` (https_enforcement.py:53). */
  public suspend fun createHttpsRedirect(request: GuardRequest): GuardResponse

  /** Python `ErrorResponseFactory.apply_modifier` surface exposed on the middleware factory. */
  public suspend fun applyModifier(response: GuardResponse): GuardResponse
}
