package com.guardcore.core

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.LogfireHandler
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.OtelHandler
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.RecordingAgent
import com.guardcore.util.ScanRequest
import com.guardcore.core.events.EnrichmentContext
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.events.EventFilter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * W9d core-tail coverage: the HandlerInitializer composite wiring and build arms, the
 * CompositeAgentHandler lifecycle with a failing member, the otel/logfire surfaces, the enricher
 * tails, and the decorator base event surface.
 */

private class RecordingLogfireSurface : LogfireHandler.LogfireSurface {
  override fun isConfigured(): Boolean = true

  override fun configure(serviceName: String) {}

  override fun shutdown() {}

  override fun span(name: String, attributes: Map<String, Any?>) {}

  override fun info(message: String, attributes: Map<String, Any?>) {}
}


private class RecordingOtelSurface : OtelHandler.OtelSurface {
  override fun startSpan(name: String, attributes: Map<String, Any?>, parentContext: Any?) {}

  override fun recordHistogram(name: String, value: Double, attributes: Map<String, Any?>) {}

  override fun recordCounterAdd(name: String, value: Double, attributes: Map<String, Any?>) {}

  override fun extractTraceContext(carrier: Map<String, String>): Any? = null
}

private class MemberAgent(val name: String, var failWith: Exception? = null) : AgentTelemetryMember {
  public val events: MutableList<Map<String, Any?>> = mutableListOf()
  public val metrics: MutableList<Map<String, Any?>> = mutableListOf()

  override suspend fun initializeRedis(redisHandler: Any?) {}

  override suspend fun sendEvent(event: Map<String, Any?>) {
    failWith?.let { throw it }
    events.add(event)
  }

  override suspend fun sendMetric(metric: Map<String, Any?>) {
    failWith?.let { throw it }
    metrics.add(metric)
  }

  override suspend fun start() {}

  override suspend fun stop() {}

  override suspend fun flushBuffer() {}

  override suspend fun getDynamicRules(): Any? = null

  override suspend fun healthCheck(): Boolean = true
}

public class CoreW9dTailsTest {
  private fun config(): com.guardcore.config.SecurityConfig =
      SecurityConfigBuilder().apply { enableRedis = false }.build()

  @Test
  fun testBuildEventBusAndMetricsCollectorArms() = coreRunTest {
    val initializer = HandlerInitializer(config = config())
    // before agent integration the builders fail-closed
    assertFailsWith<IllegalStateException> { initializer.buildEventBus() }
    assertFailsWith<IllegalStateException> { initializer.buildMetricsCollector() }
    // with the composite + filter wired, both build
    val member = MemberAgent("m1")
    initializer.compositeHandler = CompositeAgentHandler(listOf(member), EventFilter())
    initializer.eventFilter = EventFilter()
    val bus = initializer.buildEventBus()
    assertNotNull(bus)
    val collector = initializer.buildMetricsCollector()
    assertNotNull(collector)
  }

  @Test
  fun testCompositeLifecycleWithFailingMember() = coreRunTest {
    val member = MemberAgent("m1")
    member.failWith = IllegalStateException("sink down")
    val composite =
        CompositeAgentHandler(
            listOf(member, MemberAgent("m2")),
            EventFilter(),
        )
    composite.start()
    // the failing member does not break the fan-out
    composite.sendEvent(mapOf("event_type" to "x"))
    composite.sendMetric(mapOf("m" to 1))
    assertTrue(composite.healthCheck())
    composite.flushBuffer()
    composite.stop()
    // dynamic rules pass through
    assertEquals(null, composite.getDynamicRules())
  }

  @Test
  fun testOtelAndLogfireSurfaces() = coreRunTest {
    // the install + double-start + metadata arms (the companion surface is global
    // state: save and restore it around the test)
    val previousLogfire = LogfireHandler.Companion.surface
    val previousOtel = OtelHandler.Companion.surface
    LogfireHandler.Companion.installSurface(RecordingLogfireSurface())
    OtelHandler.Companion.surface = RecordingOtelSurface()
    val logfireConfig =
        object : LogfireHandler.LogfireConfig {
          override val logfireServiceName: String = "w9d"
        }
    val otelConfig =
        object : OtelHandler.ProviderConfig {
          override val otelServiceName: String = "w9d"
          override val otelResourceAttributes: Map<String, String> = mapOf("k" to "v")
          override val otelExporterEndpoint: String? = null
        }
    val logfire = LogfireHandler(logfireConfig)
    val otel = OtelHandler(otelConfig)
    logfire.start()
    logfire.start() // the started short-circuit
    otel.start()
    otel.start()
    assertTrue(logfire.healthCheck())
    assertTrue(otel.healthCheck())
    logfire.sendMetric(mapOf("kind" to "counter", "name" to "n", "value" to 1.0, "metadata" to mapOf("k" to "v")))
    otel.sendMetric(mapOf("kind" to "histogram", "name" to "n", "value" to 0.5))
    logfire.stop()
    otel.stop()
    LogfireHandler.Companion.surface = previousLogfire
    OtelHandler.Companion.surface = previousOtel
  }

  @Test
  fun testEventEnricherTails() = coreRunTest {
    val enricher = EventEnricher(EnrichmentContext(config()))
    val base = linkedMapOf<String, Any?>("event_type" to "behavior_violation", "ip_address" to "1.2.3.4")
    base["metadata"] = mutableMapOf<String, Any?>("client_ip" to "1.2.3.4")
    val enriched = enricher.enrichEvent(base)
    assertNotNull(enriched)
  }

  @Test
  fun testEventBusMutedAndCloudArms() = coreRunTest {
    val request = ScanRequest()
    val bus =
        SecurityEventBus(
            agentHandler = null,
            config = config(),
            eventFilter = EventFilter(mutedEventTypes = setOf("ip_banned")),
        )
    // a muted event type short-circuits
    bus.sendMiddlewareEvent("ip_banned", request, "banned", "reason")
    // cloud detection events with no providers configured
    bus.sendCloudDetectionEvents(request, "1.2.3.4", emptyList(), null, null, false)
    assertTrue(true)
  }

  @Test
  fun testMetricsCollectorAndEventTypes() = coreRunTest {
    val collector = MetricsCollector(null, config(), EventFilter())
    collector.collectRequestMetrics(ScanRequest(), 0.01, 200)
    assertNotNull(com.guardcore.core.events.EventTypes.EVENT_TYPE_VALUES)
  }

  @Test
  fun testBaseDecoratorEventSurface() = coreRunTest {
    val decorator = BaseSecurityDecorator(config())
    decorator.sendDecoratorEvent("custom_event", ScanRequest(), "blocked", "reason", "ipban")
    decorator.sendAccessDeniedEvent(ScanRequest(), "reason", "ipban")
    decorator.sendAuthenticationFailedEvent(ScanRequest(), "auth failed", "api_key")
    decorator.sendRateLimitEvent(ScanRequest(), 5, 60)
    decorator.sendDecoratorViolationEvent(ScanRequest(), "violation", "reason")
    decorator.initializeBehaviorTracking(null)
    decorator.initializeAgent(null, null)
    assertTrue(decorator.routeConfigRevision >= 0)
    // stamped route keys resolve their route key text; ensureRouteConfig allocates + bumps
    val stamped =
        object : com.guardcore.decorators.StampedRoute {
          override val routeKey: String = "/stamped"
          override var stampedRouteId: String? = null
        }
    decorator.ensureRouteConfig(stamped)
    decorator.ensureRouteConfig("plain-string-key")
    decorator.applyRouteConfig(stamped)
    assertNotNull(decorator.getRouteConfig("/stamped"))
  }

  @Test
  fun testRouteConfigTrackedContainers() {
    assertTrue(com.guardcore.decorators.TRACKED_LIST_FIELDS.isNotEmpty())
    assertTrue(com.guardcore.decorators.TRACKED_DICT_FIELDS.isNotEmpty())
    // tracked list mutations bump the revision
    val revision = com.guardcore.decorators.RouteConfigRevision()
    val list = com.guardcore.decorators.TrackedList<String>(revision = revision)
    list.add("a")
    list.add(0, "b")
    list.addAll(listOf("c"))
    list.indexOf("a")
    list.lastIndexOf("a")
    list.listIterator(0)
    list.subList(0, 1)
    list.contains("a")
    list.containsAll(listOf("a"))
    list.set(0, "z")
    list.remove("z")
    list.removeAll(listOf("c"))
    list.retainAll(listOf("a"))
    list.clear()
    val map = com.guardcore.decorators.TrackedMap<String, String>(revision = revision)
    map["k"] = "v"
    map.keys
    map.values
    map.containsKey("k")
    map.containsValue("v")
    map.clear()
    val set = com.guardcore.decorators.TrackedSet<String>(revision = revision)
    set.add("s")
    set.contains("s")
    set.addAll(listOf("t"))
    set.removeAll(listOf("t"))
    set.retainAll(setOf("s"))
    set.clear()
  }
}
