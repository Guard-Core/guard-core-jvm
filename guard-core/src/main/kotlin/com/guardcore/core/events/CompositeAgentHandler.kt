package com.guardcore.core.events

import java.util.logging.Logger

/**
 * Port of `guard_core/core/events/composite_handler.py`: CompositeAgentHandler
 * (composite_handler.py:11) fanning events/metrics out over member handlers with the event filter
 * and the [EventEnricher] seam (composite_handler.py:40-41, 52-53). The otel/logfire member
 * handlers are the real `core/events` ports; they construct explicitly and disable with the
 * reference warning strings when their SDK is absent from the dependency set.
 */
public interface AgentTelemetryMember {
  public suspend fun sendEvent(event: Map<String, Any?>)

  public suspend fun sendMetric(metric: Map<String, Any?>) {}

  public suspend fun initializeRedis(redisHandler: Any?) {}

  public suspend fun start() {}

  public suspend fun stop() {}

  public suspend fun flushBuffer() {}

  public suspend fun getDynamicRules(): Any? = null

  public suspend fun healthCheck(): Boolean = true
}

/** Adapter: a [com.guardcore.handlers.HandlerAgentSink] as a composite member. */
public class SinkTelemetryMember(
    private val sink: com.guardcore.handlers.HandlerAgentSink,
) : AgentTelemetryMember {
  override suspend fun sendEvent(event: Map<String, Any?>) {
    sink.sendEvent(event)
  }

  override suspend fun sendMetric(metric: Map<String, Any?>) {
    sink.sendEvent(metric)
  }
}

public class CompositeAgentHandler(
    public val handlers: List<AgentTelemetryMember>,
    public val eventFilter: EventFilter = EventFilter(),
    /** Port of the python `enricher` parameter (composite_handler.py:16). */
    public val enricher: EventEnricher? = null,
) {
  public val logger: Logger = Logger.getLogger("guard_core")

  @Volatile private var started: Boolean = false

  private var failedHandlers: MutableList<String> = mutableListOf()

  public val isStarted: Boolean
    get() = started

  public val isDegraded: Boolean
    get() = started && failedHandlers.isNotEmpty()

  public val failedHandlerNames: List<String>
    get() = failedHandlers.toList()

  /** Port of `send_event` (composite_handler.py:36). */
  public suspend fun sendEvent(event: Map<String, Any?>) {
    val eventType = event["event_type"] as? String
    if (!eventType.isNullOrEmpty() && !eventFilter.isEventAllowed(eventType)) {
      return
    }
    enricher?.enrichEvent(event)
    for (handler in handlers) {
      try {
        handler.sendEvent(event)
      } catch (e: Exception) {
        logger.severe("handler.send_event failed: $e")
      }
    }
  }

  /** Port of `send_metric` (composite_handler.py:48). */
  public suspend fun sendMetric(metric: Map<String, Any?>) {
    val metricType = metric["metric_type"] as? String
    if (!metricType.isNullOrEmpty() && !eventFilter.isMetricAllowed(metricType)) {
      return
    }
    enricher?.enrichMetric(metric)
    for (handler in handlers) {
      try {
        handler.sendMetric(metric)
      } catch (e: Exception) {
        logger.severe("handler.send_metric failed: $e")
      }
    }
  }

  /** Port of `initialize_redis` (composite_handler.py:60). */
  public suspend fun initializeRedis(redisHandler: Any?) {
    for (handler in handlers) {
      try {
        handler.initializeRedis(redisHandler)
      } catch (e: Exception) {
        logger.severe("handler.initialize_redis failed: $e")
      }
    }
  }

  /** Port of `start` (composite_handler.py:67). */
  public suspend fun start() {
    failedHandlers = mutableListOf()
    for (handler in handlers) {
      val handlerName = handler::class.java.simpleName
      try {
        handler.start()
      } catch (e: Exception) {
        failedHandlers.add(handlerName)
        logger.severe("Handler $handlerName failed to start: $e")
      }
    }
    started = true
  }

  /** Port of `stop` (composite_handler.py:78). */
  public suspend fun stop() {
    for (handler in handlers) {
      try {
        handler.stop()
      } catch (e: Exception) {
        logger.severe("handler.stop failed: $e")
      }
    }
  }

  /** Port of `flush_buffer` (composite_handler.py:85). */
  public suspend fun flushBuffer() {
    for (handler in handlers) {
      try {
        handler.flushBuffer()
      } catch (e: Exception) {
        logger.severe("handler.flush_buffer failed: $e")
      }
    }
  }

  /** Port of `get_dynamic_rules` (composite_handler.py:92). */
  public suspend fun getDynamicRules(): Any? {
    for (handler in handlers) {
      try {
        val result = handler.getDynamicRules()
        if (result != null) {
          return result
        }
      } catch (e: Exception) {
        logger.severe("handler.get_dynamic_rules failed: $e")
      }
    }
    return null
  }

  /** Port of `health_check` (composite_handler.py:102). */
  public suspend fun healthCheck(): Boolean {
    if (handlers.isEmpty()) {
      return true
    }
    val results = mutableListOf<Boolean>()
    for (handler in handlers) {
      try {
        results.add(handler.healthCheck())
      } catch (e: Exception) {
        logger.severe("handler.health_check failed: $e")
        results.add(false)
      }
    }
    return results.all { it }
  }
}
