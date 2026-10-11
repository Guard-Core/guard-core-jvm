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
 * The bus gates on `agent_handler`/`agent_enable_events` and builds the guard-agent SecurityEvent
 * telemetry envelope (the model's full field set carried as a map; the model class itself is the
 * W7 agent wave surface). With no agent handler the bus is a faithful no-op, exactly like
 * middleware_events.py:119-120.
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
   * Port of `_build_event` (middleware_events.py:67): constructs the SecurityEvent telemetry
   * envelope over the guard-agent model's field set (guard_agent/models.py:208): idempotency_key,
   * timestamp, event_type, ip_address, country, user_agent, action_taken, reason, endpoint,
   * method, status_code, response_time, decorator_type, rule_type, pattern_matched, handler_name,
   * metadata. The bus never passes status_code/pattern_matched (they stay null, exactly like
   * middleware_events.py:82-109); pattern_matched is set by the sus_patterns handler seam.
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
    return securityEventEnvelope(
        eventType = eventType,
        ipAddress = clientIp,
        country = country,
        userAgent =
            if (rawUserAgent != null) {
              RequestLogging.redactHeaderValueForDisplay(
                  rawUserAgent,
                  config.logSensitiveParams,
                  config.logSensitiveBodyFields,
                  config.logSensitiveHeaders,
              )
            } else {
              null
            },
        actionTaken = actionTaken,
        reason = reason,
        endpoint =
            RequestLogging.redactEndpointForDisplay(
                request.urlPath,
                config.logSensitiveParams,
                config.logSensitiveBodyFields,
                config.logSensitiveHeaders,
            ),
        method = request.method,
        responseTime = AgentEvents.getPipelineResponseTime(request),
        decoratorType = metadata["decorator_type"] as? String,
        ruleType = metadata["rule_type"] as? String,
        handlerName = MIDDLEWARE_HANDLER_NAME,
        metadata = metadata,
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
      val clientIp =
          IpExtraction.extractClientIp(request, config, sinkAsAgentProtocol(agentHandler))
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

    /**
     * The bus hands its agent handler to extract_client_ip (middleware_events.py:125-127); the
     * sink-shaped field adapts to the protocol shape the extraction seam reads.
     */
    public fun sinkAsAgentProtocol(sink: com.guardcore.handlers.HandlerAgentSink):
        com.guardcore.protocols.AgentHandlerProtocol =
        object : com.guardcore.protocols.AgentHandlerProtocol {
          override suspend fun initializeRedis(
              redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
          ) {}

          override suspend fun sendEvent(event: Any?) {
            @Suppress("UNCHECKED_CAST")
            sink.sendEvent((event as? Map<String, Any?>) ?: mapOf<String, Any?>())
          }

          override suspend fun sendMetric(metric: Any?) {}

          override suspend fun start() {}

          override suspend fun stop() {}

          override suspend fun flushBuffer() {}

          override suspend fun getDynamicRules(): Any? = null

          override suspend fun healthCheck(): Boolean = true
        }
  }
}
