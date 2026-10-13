package com.guardcore.core

import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.RedisHandlerProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Wiring of an injected agent handler into the composite (handler_initializer.py:87-105): the
 * adapters inject an [AgentHandlerProtocol] (the official bridge is also an [AgentTelemetryMember],
 * not a [HandlerAgentSink]), and metrics must reach `send_metric` (metrics.py:45), not
 * `send_event`.
 */
public class AgentTelemetryWiringTest {
  private open class ProtocolAgent : AgentHandlerProtocol {
    val events = mutableListOf<Any?>()
    val metrics = mutableListOf<Any?>()
    var redisInits = 0
    var starts = 0
    var stops = 0
    var flushes = 0

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {
      redisInits += 1
    }

    override suspend fun sendEvent(event: Any?) {
      events.add(event)
    }

    override suspend fun sendMetric(metric: Any?) {
      metrics.add(metric)
    }

    override suspend fun start() {
      starts += 1
    }

    override suspend fun stop() {
      stops += 1
    }

    override suspend fun flushBuffer() {
      flushes += 1
    }

    override suspend fun getDynamicRules(): Any? = "rules"

    override suspend fun healthCheck(): Boolean = false
  }

  /** The GuardAgentTelemetry shape: protocol and member, not a sink. */
  private class BridgeAgent : ProtocolAgent(), AgentTelemetryMember {
    override suspend fun sendEvent(event: Map<String, Any?>) {
      events.add(event)
    }

    override suspend fun sendMetric(metric: Map<String, Any?>) {
      metrics.add(metric)
    }

    override suspend fun initializeRedis(redisHandler: Any?) {}

    override suspend fun start() = super<ProtocolAgent>.start()

    override suspend fun stop() = super<ProtocolAgent>.stop()

    override suspend fun flushBuffer() = super<ProtocolAgent>.flushBuffer()

    override suspend fun getDynamicRules(): Any? = super<ProtocolAgent>.getDynamicRules()

    override suspend fun healthCheck(): Boolean = super<ProtocolAgent>.healthCheck()
  }

  private class SinkOnly : HandlerAgentSink {
    val events = mutableListOf<Map<String, Any?>>()

    override suspend fun sendEvent(event: Map<String, Any?>) {
      events.add(event)
    }
  }

  private object NoopRedis : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?) = true

    override suspend fun delete(namespace: String, key: String): Int? = 0

    override suspend fun keys(pattern: String): List<String>? = emptyList()

    override suspend fun initialize() {}

    override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
        throw UnsupportedOperationException()
  }

  private val event = mapOf<String, Any?>("event_type" to "ip_banned")

  private fun metricsConfig() = coreTestConfig {
    lazyInit = false
    enableRedis = false
    enableDynamicRules = false
    blockCloudProviders = emptySet()
  }

  @Test
  fun memberAgentIsCompositedStartedAndReceivesEvents() {
    coreRunTest {
      resetIpBanGlobalState()
      val agent = BridgeAgent()
      val initializer = HandlerInitializer(config = metricsConfig(), agentHandler = agent)

      initializer.initializeAgentIntegrations()

      assertEquals(listOf<Any?>(agent), initializer.compositeHandler!!.handlers)
      assertEquals(1, agent.starts)
      initializer.buildEventBus().agentHandler!!.sendEvent(event)
      assertEquals(listOf<Any?>(event), agent.events)
    }
  }

  @Test
  fun protocolOnlyAgentIsCompositedAndReceivesEverything() {
    coreRunTest {
      resetIpBanGlobalState()
      val agent = ProtocolAgent()
      val initializer = HandlerInitializer(config = metricsConfig(), agentHandler = agent)

      initializer.initializeAgentIntegrations()
      val composite = initializer.compositeHandler!!
      assertEquals(1, composite.handlers.size)
      assertEquals(1, agent.starts)
      initializer.buildEventBus().agentHandler!!.sendEvent(event)
      initializer.buildMetricsCollector().sendMetric("request_count", 1.0)
      composite.initializeRedis(null)
      assertEquals(0, agent.redisInits)
      composite.initializeRedis(NoopRedis)
      composite.flushBuffer()
      assertEquals(1, agent.redisInits)
      assertEquals(1, agent.flushes)
      assertEquals(listOf<Any?>("rules"), listOf(composite.getDynamicRules()))
      assertEquals(false, composite.healthCheck())
      composite.stop()
      assertEquals(1, agent.stops)
      assertEquals(listOf<Any?>(event), agent.events)
      assertEquals(1, agent.metrics.size)
      assertTrue(agent.events.none { (it as Map<*, *>).containsKey("metric_type") })
    }
  }

  @Test
  fun sinkOnlyAgentKeepsWorking() {
    coreRunTest {
      resetIpBanGlobalState()
      val agent = SinkOnly()
      val initializer = HandlerInitializer(config = metricsConfig(), agentHandler = agent)

      initializer.initializeAgentIntegrations()

      assertEquals(1, initializer.compositeHandler!!.handlers.size)
      initializer.buildEventBus().agentHandler!!.sendEvent(event)
      initializer.buildMetricsCollector().sendMetric("request_count", 1.0)
      assertEquals(2, agent.events.size)
      assertEquals("request_count", agent.events[1]["metric_type"])
    }
  }

  @Test
  fun metricReachesMemberSendMetricNotSendEvent() {
    coreRunTest {
      resetIpBanGlobalState()
      val agent = BridgeAgent()
      val initializer = HandlerInitializer(config = metricsConfig(), agentHandler = agent)
      initializer.initializeAgentIntegrations()

      initializer.buildMetricsCollector().sendMetric("request_count", 1.0)

      assertTrue(agent.events.isEmpty(), "metric leaked into sendEvent: ${agent.events}")
      assertEquals(1, agent.metrics.size)
      assertEquals("request_count", (agent.metrics[0] as Map<*, *>)["metric_type"])
    }
  }

  @Test
  fun wrappedProtocolSinkRoutesMetricsToSendMetric() {
    coreRunTest {
      val agent = ProtocolAgent()
      val sink = HandlerAgentSink.of(agent)

      sink.sendEvent(event)
      sink.sendMetric(mapOf("metric_type" to "request_count"))

      assertEquals(listOf<Any?>(event), agent.events)
      assertEquals(1, agent.metrics.size)
    }
  }

  private class CapturingGeo : GeoIPHandler {
    var agentProtocol: AgentHandlerProtocol? = null

    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun initializeAgent(agentHandler: AgentHandlerProtocol) {
      agentProtocol = agentHandler
    }

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  @Test
  fun geoAdapterRoutesMetricsToSendMetric() {
    coreRunTest {
      resetIpBanGlobalState()
      val agent = BridgeAgent()
      val geo = CapturingGeo()
      val initializer =
          HandlerInitializer(config = metricsConfig(), agentHandler = agent, geoIpHandler = geo)
      initializer.initializeAgentIntegrations()

      geo.agentProtocol!!.sendMetric(mapOf("metric_type" to "request_count"))

      assertTrue(agent.events.isEmpty(), "metric leaked into sendEvent: ${agent.events}")
      assertEquals(1, agent.metrics.size)
    }
  }

  @Test
  fun unrecognizedAgentTypeIsSkippedWithAWarning() {
    coreRunTest {
      resetIpBanGlobalState()
      val initializer = HandlerInitializer(config = metricsConfig(), agentHandler = Any())
      val warnings = mutableListOf<String>()
      val capture =
          object : java.util.logging.Handler() {
            override fun publish(record: java.util.logging.LogRecord) {
              warnings.add(record.message)
            }

            override fun flush() {}

            override fun close() {}
          }
      initializer.logger.addHandler(capture)
      try {
        initializer.initializeAgentIntegrations()
      } finally {
        initializer.logger.removeHandler(capture)
      }

      assertTrue(initializer.compositeHandler!!.handlers.isEmpty())
      assertTrue(warnings.any { it.contains("receives no telemetry") }, "warnings: $warnings")
    }
  }
}
