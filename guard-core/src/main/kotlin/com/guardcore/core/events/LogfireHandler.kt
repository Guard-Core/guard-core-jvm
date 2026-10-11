package com.guardcore.core.events

import java.util.logging.Logger

/**
 * Port of `guard_core/core/events/logfire_handler.py`: LogfireHandler (logfire_handler.py:21).
 *
 * The python module try-imports logfire and flips to `_logfire_available = False` on ImportError
 * (logfire_handler.py:9-15). The JVM artifact carries no logfire dependency, so the SDK surface is
 * the [LogfireSurface] seam: absent by default, which selects exactly the python not-installed
 * branch - `start` logs "logfire not installed, Logfire handler disabled" and the handler stays
 * inert; `health_check` reports the availability flag. A host that provides logfire registers it
 * through [LogfireHandler.installSurface].
 */
public class LogfireHandler(
    private val config: LogfireConfig,
) : AgentTelemetryMember {
  /** The SecurityConfig surface logfire_handler.py reads (logfire_service_name). */
  public interface LogfireConfig {
    public val logfireServiceName: String
  }

  /** The logfire API surface logfire_handler.py drives: configure/shutdown/span/info. */
  public interface LogfireSurface {
    public fun isConfigured(): Boolean

    public fun configure(serviceName: String)

    public fun shutdown()

    public fun span(name: String, attributes: Map<String, Any?>)

    public fun info(message: String, attributes: Map<String, Any?>)
  }

  public companion object {
    private val logger: Logger = Logger.getLogger("guard_core")

    private val configureLock = Any()

    @Volatile public var surface: LogfireSurface? = null

    /** Port of `_logfire_available` (logfire_handler.py:12/15). */
    public val logfireAvailable: Boolean
      get() = surface != null

    /** Port of `_configure_lock` (logfire_handler.py:18). */
    public fun configureLock(): Any = configureLock

    public fun installSurface(surface: LogfireSurface) {
      this.surface = surface
    }
  }

  @Volatile private var started: Boolean = false

  @Volatile private var configuredByGuard: Boolean = false

  /** Port of `start` (logfire_handler.py:27). */
  override suspend fun start() {
    val logfire = surface
    if (logfire == null) {
      logger.warning("logfire not installed, Logfire handler disabled")
      return
    }
    synchronized(configureLock) {
      if (started) {
        return
      }
      if (logfire.isConfigured()) {
        started = true
        logger.warning(
            "logfire is already configured for this process (by a host " +
                "application or an earlier guard_core instance); guard_core " +
                "will not apply its logfire_service_name ${config.logfireServiceName}",
        )
        return
      }
      logfire.configure(config.logfireServiceName)
      configuredByGuard = true
      started = true
    }
  }

  /** Port of `stop` (logfire_handler.py:47). */
  override suspend fun stop() {
    val logfire = surface
    if (logfire == null) {
      return
    }
    synchronized(configureLock) {
      if (configuredByGuard) {
        logfire.shutdown()
        configuredByGuard = false
      }
      started = false
    }
  }

  /** Port of `send_event` (logfire_handler.py:56). */
  override suspend fun sendEvent(event: Map<String, Any?>) {
    val logfire = surface
    if (logfire == null) {
      return
    }
    val eventType = (event["event_type"] as? String) ?: "unknown"
    @Suppress("UNCHECKED_CAST") val metadata = event["metadata"] as? Map<String, Any?>
    val enrichment = LinkedHashMap<String, Any?>()
    if (metadata != null) {
      for ((key, value) in metadata) {
        if (
            key.startsWith("guard.") && key !in setOf("traceparent", "tracestate") && value != null
        ) {
          enrichment[key] = value
        }
      }
    }
    val attributes = LinkedHashMap<String, Any?>()
    attributes["event_type"] = eventType
    attributes["ip_address"] = event["ip_address"] ?: ""
    attributes["action_taken"] = event["action_taken"] ?: ""
    attributes["reason"] = event["reason"] ?: ""
    attributes["endpoint"] = event["endpoint"] ?: ""
    attributes["method"] = event["method"] ?: ""
    attributes["status_code"] = event["status_code"] ?: 0
    attributes.putAll(enrichment)
    logfire.span("guard.event.$eventType", attributes)
  }

  /** Port of `send_metric` (logfire_handler.py:83). */
  override suspend fun sendMetric(metric: Map<String, Any?>) {
    val logfire = surface
    if (logfire == null) {
      return
    }
    val metricType = (metric["metric_type"] as? String) ?: "unknown"
    val value = (metric["value"] as? Number)?.toDouble() ?: 0.0
    val endpoint = (metric["endpoint"] as? String) ?: ""
    @Suppress("UNCHECKED_CAST") val tags = (metric["tags"] as? Map<String, Any?>) ?: emptyMap()
    val safeTags = tags.filterKeys { it != "value" && it != "endpoint" }
    val attributes = LinkedHashMap<String, Any?>()
    attributes["value"] = value
    attributes["endpoint"] = endpoint
    attributes.putAll(safeTags)
    logfire.info("guard.metric.$metricType", attributes)
  }

  /** Port of `initialize_redis` (logfire_handler.py:98). */
  override suspend fun initializeRedis(redisHandler: Any?) {}

  /** Port of `flush_buffer` (logfire_handler.py:101). */
  override suspend fun flushBuffer() {}

  /** Port of `get_dynamic_rules` (logfire_handler.py:104). */
  override suspend fun getDynamicRules(): Any? = null

  /** Port of `health_check` (logfire_handler.py:107). */
  override suspend fun healthCheck(): Boolean = logfireAvailable
}
