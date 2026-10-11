package com.guardcore.core.events

import com.guardcore.config.SecurityConfig
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.MiddlewareEventBusProtocol
import com.guardcore.util.AgentEvents
import com.guardcore.util.IpExtraction
import com.guardcore.util.RequestLogging
import java.util.logging.Logger

/**
 * Port of `guard_core/core/events/middleware_events.py`: SecurityEventBus (middleware_events.py:26)
 * with `send_middleware_event` (middleware_events.py:111), `send_https_violation_event`
 * (middleware_events.py:137) and `send_cloud_detection_events` (middleware_events.py:168).
 *
 * The Python bus gates on `agent_handler`/`agent_enable_events` and builds the agent's
 * SecurityEvent telemetry model; the agent model is W7 surface (KNOWN_GAPS G-11), so the JVM bus
 * forwards the same field envelope as a map to the [HandlerAgentSink]. With no agent handler the
 * bus is a faithful no-op, exactly like middleware_events.py:119-120.
 */
public open class SecurityEventBus(
    public val agentHandler: HandlerAgentSink?,
    public val config: SecurityConfig,
    public val geoIpHandler: GeoIPHandler? = null,
    public val eventFilter: EventFilter = EventFilter(),
) : MiddlewareEventBusProtocol {
  public val logger: Logger = Logger.getLogger("guard_core.core.events.middleware_events")

  public val middlewareHandlerName: String = MIDDLEWARE_HANDLER_NAME

  /** Port of `_lookup_country` (middleware_events.py:40). */
  protected fun lookupCountry(clientIp: String): String? {
    val handler = geoIpHandler ?: return null
    return try {
      handler.getCountry(clientIp)
    } catch (e: Exception) {
      logger.warning("GeoIP lookup failed for $clientIp: $e")
      config.onError?.invoke("geoip", e, mapOf("client_ip" to clientIp))
      null
    }
  }

  /** Port of `_forward_trace_headers` (middleware_events.py:56). */
  protected fun forwardTraceHeaders(
      request: GuardRequest,
      metadata: Map<String, Any?>,
  ): Map<String, Any?> {
    var forwarded = metadata
    for (header in listOf("traceparent", "tracestate")) {
      val value = request.headers[header]
      if (!value.isNullOrEmpty() && header !in forwarded) {
        forwarded = LinkedHashMap(forwarded).also { it[header] = value }
      }
    }
    return forwarded
  }

  /**
   * Port of `_build_event` (middleware_events.py:67) up to the telemetry-model boundary: the
   * SecurityEvent field set (timestamp, event_type, ip_address, country, user_agent, action_taken,
   * reason, endpoint, method, response_time, decorator_type, rule_type, handler_name, metadata).
   */
  protected fun buildEvent(
      eventType: String,
      request: GuardRequest,
      clientIp: String,
      country: String?,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?>,
  ): Map<String, Any?> {
    val rawUserAgent = request.headers["User-Agent"]
    val userAgent =
        if (rawUserAgent != null) {
          RequestLogging.redactHeaderValueForDisplay(
              rawUserAgent,
              config.logSensitiveParams,
              config.logSensitiveBodyFields,
              config.logSensitiveHeaders,
          )
        } else {
          null
        }
    return linkedMapOf(
        "timestamp" to java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).toString(),
        "event_type" to eventType,
        "ip_address" to clientIp,
        "country" to country,
        "user_agent" to userAgent,
        "action_taken" to actionTaken,
        "reason" to reason,
        "endpoint" to
            RequestLogging.redactEndpointForDisplay(
                request.urlPath,
                config.logSensitiveParams,
                config.logSensitiveBodyFields,
                config.logSensitiveHeaders,
            ),
        "method" to request.method,
        "response_time" to AgentEvents.getPipelineResponseTime(request),
        "decorator_type" to metadata["decorator_type"],
        "rule_type" to metadata["rule_type"],
        "handler_name" to MIDDLEWARE_HANDLER_NAME,
        "metadata" to metadata,
    )
  }

  /** Port of `send_middleware_event` (middleware_events.py:111). */
  override suspend fun sendMiddlewareEvent(
      eventType: String,
      request: GuardRequest,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?>,
  ) {
    if (agentHandler == null || !config.agentEnableEvents) {
      return
    }
    if (!eventFilter.isEventAllowed(eventType)) {
      return
    }
    try {
      val clientIp = IpExtraction.extractClientIp(request, config)
      val country = lookupCountry(clientIp)
      val forwarded = forwardTraceHeaders(request, metadata)
      val event = buildEvent(eventType, request, clientIp, country, actionTaken, reason, forwarded)
      agentHandler.sendEvent(event)
    } catch (e: Exception) {
      logger.severe("Failed to send security event to agent: $e")
    }
  }

  /** Port of `send_https_violation_event` (middleware_events.py:137). */
  override suspend fun sendHttpsViolationEvent(request: GuardRequest, routeConfig: Any?) {
    val httpsUrl =
        RequestLogging.redactEndpointForDisplay(
            request.urlReplaceScheme("https"),
            config.logSensitiveParams,
            config.logSensitiveBodyFields,
            config.logSensitiveHeaders,
        )
    val rc = routeConfig as? com.guardcore.decorators.RouteConfig
    if (rc != null && rc.requireHttps) {
      sendMiddlewareEvent(
          EventTypes.EVENT_DECORATOR_VIOLATION,
          request,
          "https_redirect",
          "Route requires HTTPS but request was HTTP",
          linkedMapOf(
              "decorator_type" to "authentication",
              "violation_type" to "require_https",
              "original_scheme" to request.urlScheme,
              "redirect_url" to httpsUrl,
          ),
      )
    } else {
      sendMiddlewareEvent(
          EventTypes.EVENT_HTTPS_ENFORCED,
          request,
          "https_redirect",
          "HTTP request redirected to HTTPS for security",
          linkedMapOf(
              "original_scheme" to request.urlScheme,
              "redirect_url" to httpsUrl,
          ),
      )
    }
  }

  /** Port of `send_cloud_detection_events` (middleware_events.py:168). */
  override suspend fun sendCloudDetectionEvents(
      request: GuardRequest,
      clientIp: String,
      cloudProvidersToCheck: List<String>,
      routeConfig: Any?,
      cloudHandler: Any?,
      passiveMode: Boolean,
  ) {
    val handler = cloudHandler as? com.guardcore.handlers.CloudManager
    val cloudDetails = handler?.getCloudProviderDetails(clientIp, cloudProvidersToCheck.toSet())
    if (cloudDetails != null && handler.agentHandler != null) {
      val (provider, network) = cloudDetails
      handler.sendCloudDetectionEvent(
          clientIp,
          provider,
          network,
          if (!passiveMode) "request_blocked" else "logged_only",
      )
    }
    val rc = routeConfig as? com.guardcore.decorators.RouteConfig
    if (rc != null && rc.blockCloudProviders.isNotEmpty()) {
      sendMiddlewareEvent(
          EventTypes.EVENT_DECORATOR_VIOLATION,
          request,
          if (!passiveMode) "request_blocked" else "logged_only",
          "Cloud provider IP $clientIp blocked",
          linkedMapOf(
              "decorator_type" to "access_control",
              "violation_type" to "cloud_provider",
              "blocked_providers" to cloudProvidersToCheck.toList(),
          ),
      )
    }
  }

  public companion object {
    /** Python `_MIDDLEWARE_HANDLER_NAME` (middleware_events.py:23). */
    public const val MIDDLEWARE_HANDLER_NAME: String = "middleware"
  }
}
