package com.guardcore.protocols

import com.guardcore.config.SecurityConfig
import java.util.logging.Logger

/**
 * Port of `guard_core/protocols/middleware_protocol.py` (middleware_protocol.py:16): the middleware
 * surface handlers and checks call back into.
 *
 * Python property members map to Kotlin val members; the handler properties may return null when a
 * feature is disabled, mirroring the Python contract.
 */
public interface GuardMiddlewareProtocol {
  /** Python attribute `config` (middleware_protocol.py:33). */
  public val config: SecurityConfig

  /** Python attribute `logger` (middleware_protocol.py:34). */
  public val logger: Logger

  /** Python attribute `last_cloud_ip_refresh` (middleware_protocol.py:35). */
  public val lastCloudIpRefresh: Int

  /** Python attribute `suspicious_request_counts` (middleware_protocol.py:36). */
  public val suspiciousRequestCounts: MutableMap<String, MutableMap<String, Int>>

  /** Python property `event_bus` (middleware_protocol.py:39). */
  public val eventBus: Any?

  /** Python property `route_resolver` (middleware_protocol.py:43). */
  public val routeResolver: Any?

  /** Python property `response_factory` (middleware_protocol.py:47). */
  public val responseFactory: Any?

  /** Python property `rate_limit_handler` (middleware_protocol.py:51). */
  public val rateLimitHandler: Any?

  /** Python property `agent_handler` (middleware_protocol.py:55). */
  public val agentHandler: AgentHandlerProtocol?

  /** Python property `geo_ip_handler` (middleware_protocol.py:59). */
  public val geoIpHandler: GeoIPHandler?

  /** Python property `guard_response_factory` (middleware_protocol.py:63). */
  public val guardResponseFactory: GuardResponseFactory?

  /** Python async method `create_error_response` (middleware_protocol.py:67). */
  public suspend fun createErrorResponse(statusCode: Int, defaultMessage: String): GuardResponse

  /** Python async method `refresh_cloud_ip_ranges` (middleware_protocol.py:75). */
  public suspend fun refreshCloudIpRanges()
}
