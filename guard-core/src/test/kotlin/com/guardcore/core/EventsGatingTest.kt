package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.handlers.HandlerAgentSink
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking

/**
 * The G-13 events gating halves (tests/test_core/test_events.py): the metrics-collector and
 * event-bus agent gating, the send counts, and the https/cloud routing on the real bus.
 */
public class EventsGatingTest {
  private class RecordingAgent : HandlerAgentSink {
    val events: MutableList<Map<String, Any?>> = mutableListOf()
    val metrics: MutableList<Map<String, Any?>> = mutableListOf()
    var failWith: Exception? = null

    override suspend fun sendEvent(event: Map<String, Any?>) {
      failWith?.let { throw it }
      events.add(event)
    }

    override suspend fun sendMetric(metric: Map<String, Any?>) {
      failWith?.let { throw it }
      metrics.add(metric)
    }
  }

  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  // metrics.py halves

  @Test
  fun metricsCollectorNoAgentIsSilent() = runBlocking {
    val collector = MetricsCollector(null, config())
    collector.sendMetric("test", 1.0)
  }

  @Test
  fun metricsCollectorDisabledIsSilent() = runBlocking {
    val agent = RecordingAgent()
    val collector = MetricsCollector(agent, config { agentEnableMetrics = false })
    collector.sendMetric("test", 1.0)
    assertEquals(0, agent.metrics.size)
  }

  @Test
  fun metricsCollectorSendsMetric() = runBlocking {
    val agent = RecordingAgent()
    val collector = MetricsCollector(agent, config { agentEnableMetrics = true })
    // MetricsCollector.send_metric dispatches through HandlerAgentSink.sendMetric (metrics.py:45);
    // the sink records the SecurityMetric envelope map.
    collector.sendMetric("response_time", 0.5, mapOf("endpoint" to "/api"))
    assertEquals(0, agent.events.size)
    assertEquals(1, agent.metrics.size)
    assertEquals("response_time", agent.metrics[0]["metric_type"])
    assertEquals(0.5, agent.metrics[0]["value"])
  }

  @Test
  fun metricsCollectorSendMetricExceptionIsSwallowed() = runBlocking {
    val agent = RecordingAgent()
    agent.failWith = IllegalStateException("fail")
    val collector = MetricsCollector(agent, config { agentEnableMetrics = true })
    collector.sendMetric("test", 1.0)
    // metrics.py:47: the failure is logged and swallowed.
  }

  @Test
  fun metricsCollectRequestNoAgentIsSilent() = runBlocking {
    val collector = MetricsCollector(null, config())
    collector.collectRequestMetrics(TestRequest(), 0.1, 200)
  }

  @Test
  fun metricsCollectRequestWithAgentSendsTwo() = runBlocking {
    val agent = RecordingAgent()
    val collector = MetricsCollector(agent, config { agentEnableMetrics = true })
    collector.collectRequestMetrics(TestRequest(), 0.1, 200)
    assertEquals(2, agent.metrics.size)
  }

  @Test
  fun metricsCollectRequestErrorStatusSendsThree() = runBlocking {
    val agent = RecordingAgent()
    val collector = MetricsCollector(agent, config { agentEnableMetrics = true })
    collector.collectRequestMetrics(TestRequest(), 0.1, 500)
    assertEquals(3, agent.metrics.size)
  }

  // middleware_events.py halves

  @Test
  fun eventBusNoAgentIsSilent() = runBlocking {
    val bus = SecurityEventBus(null, config())
    bus.sendMiddlewareEvent("test", TestRequest(), "blocked", "reason")
  }

  @Test
  fun eventBusDisabledIsSilent() = runBlocking {
    val agent = RecordingAgent()
    val bus = SecurityEventBus(agent, config { agentEnableEvents = false })
    bus.sendMiddlewareEvent("test", TestRequest(), "blocked", "reason")
    assertEquals(0, agent.events.size)
  }

  @Test
  fun eventBusSendsEvent() = runBlocking {
    val agent = RecordingAgent()
    val bus = SecurityEventBus(agent, config { agentEnableEvents = true })
    bus.sendMiddlewareEvent("test", TestRequest(), "blocked", "reason")
    assertEquals(1, agent.events.size)
    assertEquals("test", agent.events[0]["event_type"])
    assertEquals("blocked", agent.events[0]["action_taken"])
    assertEquals("reason", agent.events[0]["reason"])
    assertEquals("middleware", agent.events[0]["handler_name"])
  }

  @Test
  fun eventBusSendsEventWithGeoCountry() = runBlocking {
    val agent = RecordingAgent()
    val geo =
        object : com.guardcore.protocols.GeoIPHandler by NoopGeo {
          override fun getCountry(ip: String): String? = "US"
        }
    val bus = SecurityEventBus(agent, config { agentEnableEvents = true }, geoIpHandler = geo)
    bus.sendMiddlewareEvent("test", TestRequest(clientHost = "1.2.3.4"), "blocked", "reason")
    assertEquals(1, agent.events.size)
    assertEquals("US", agent.events[0]["country"])
  }

  @Test
  fun eventBusGeoLookupFailureIsSwallowedAndStillSends() = runBlocking {
    val agent = RecordingAgent()
    val geo =
        object : com.guardcore.protocols.GeoIPHandler by NoopGeo {
          override fun getCountry(ip: String): String? = throw IllegalStateException("geo down")
        }
    val bus = SecurityEventBus(agent, config { agentEnableEvents = true }, geoIpHandler = geo)
    bus.sendMiddlewareEvent("test", TestRequest(), "blocked", "reason")
    assertEquals(1, agent.events.size)
    assertEquals(null, agent.events[0]["country"])
  }

  @Test
  fun eventBusMutedEventTypeIsFiltered() = runBlocking {
    val agent = RecordingAgent()
    val bus =
        SecurityEventBus(
            agent,
            config { agentEnableEvents = true },
            eventFilter = com.guardcore.core.events.EventFilter(mutedEventTypes = setOf("test")),
        )
    bus.sendMiddlewareEvent("test", TestRequest(), "blocked", "reason")
    assertEquals(0, agent.events.size)
  }

  @Test
  fun eventBusHttpsViolationRoutesOnRouteConfig() = runBlocking {
    val agent = RecordingAgent()
    val bus = SecurityEventBus(agent, config { agentEnableEvents = true })
    val routeConfig = com.guardcore.decorators.RouteConfig()
    routeConfig.requireHttps = true
    bus.sendHttpsViolationEvent(TestRequest(), routeConfig)
    assertEquals(1, agent.events.size)
    assertEquals("decorator_violation", agent.events[0]["event_type"])

    agent.events.clear()
    bus.sendHttpsViolationEvent(TestRequest(), null)
    assertEquals(1, agent.events.size)
    assertEquals("https_enforced", agent.events[0]["event_type"])
    assertEquals(
        "https://example.com/api",
        (agent.events[0]["metadata"] as Map<*, *>)["redirect_url"],
    )
  }

  private object NoopGeo : com.guardcore.protocols.GeoIPHandler {
    override val isInitialized: Boolean = true

    override fun getCountry(ip: String): String? = null

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override suspend fun refresh() {}

    override fun close() {}
  }
}
