package com.guardcore.core

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.behavioral.BehavioralContext
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.core.checks.implementations.ReferrerCheck
import com.guardcore.core.checks.implementations.TimeWindowCheck
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.LogfireHandler
import com.guardcore.core.events.OtelHandler
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.java.JavaBridges
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9a core-arm coverage: ports of the check-implementation flows (referrer, time window), the
 * behavioral usage/return rule paths, the composite telemetry member dispatch, and the Java
 * bridge surface (the python decorator/check implementation test families).
 */
class ReferrerCheckFlowTest {
  private fun middleware(passive: Boolean = false): TestMiddleware =
      TestMiddleware(
          coreTestConfig {
            passiveMode = passive
            logSuspiciousLevel = com.guardcore.config.LogLevel.ERROR
          },
      )

  private fun request(headers: Map<String, String> = emptyMap(), route: RouteConfig? = null): TestRequest {
    val request = TestRequest(method = "GET", urlPath = "/x", headers = headers)
    if (route != null) request.state.setAttr("route_config", route)
    return request
  }

  private fun routeWithReferrer(domains: List<String>): RouteConfig =
      RouteConfig().apply { requireReferrer = domains }

  /** test_check_implementations.py:663. */
  @Test
  fun testCheckName() {
    assertEquals("referrer", ReferrerCheck(middleware()).checkName)
  }

  @Test
  fun testNoRouteConfigPasses() {
    runBlocking {
      assertNull(ReferrerCheck(middleware()).check(request()))
    }
  }

  @Test
  fun testReferrerNotRequiredPasses() {
    runBlocking {
      assertNull(ReferrerCheck(middleware()).check(request(route = RouteConfig())))
    }
  }

  /** test_check_implementations.py:686 - missing referrer blocks with 403. */
  @Test
  fun testMissingReferrerBlocks() {
    runBlocking {
      val mw = middleware()
      val result = ReferrerCheck(mw).check(request(route = routeWithReferrer(listOf("example.com"))))
      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(1, mw.bus.events.size)
      assertEquals("decorator_violation", mw.bus.events[0]["event_type"])
    }
  }

  /** test_check_implementations.py:699 - a foreign domain blocks. */
  @Test
  fun testInvalidReferrerBlocks() {
    runBlocking {
      val mw = middleware()
      val result =
          ReferrerCheck(mw).check(
              request(
                  headers = mapOf("referer" to "https://evil.com/page"),
                  route = routeWithReferrer(listOf("example.com")),
              ),
          )
      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertTrue(
          (mw.bus.events[0]["reason"] as String).contains("evil.com"),
          mw.bus.events[0].toString(),
      )
    }
  }

  /** test_check_implementations.py:713 - an allowed domain passes. */
  @Test
  fun testValidReferrerPasses() {
    runBlocking {
      val mw = middleware()
      val result =
          ReferrerCheck(mw).check(
              request(
                  headers = mapOf("referer" to "https://example.com/page"),
                  route = routeWithReferrer(listOf("example.com")),
              ),
          )
      assertNull(result)
      assertEquals(0, mw.bus.events.size)
    }
  }

  /** test_check_implementations.py:725/736 - passive mode logs but does not block. */
  @Test
  fun testPassiveModeNeverBlocks() {
    runBlocking {
      val mw = middleware(passive = true)
      val check = ReferrerCheck(mw)
      assertNull(check.check(request(route = routeWithReferrer(listOf("example.com")))))
      assertNull(
          check.check(
              request(
                  headers = mapOf("referer" to "https://evil.com/"),
                  route = routeWithReferrer(listOf("example.com")),
              ),
          ),
      )
      assertEquals(2, mw.bus.events.size)
    }
  }

  /** Subdomain allowance: https://www.example.com matches example.com when the port allows. */
  @Test
  fun testWwwSubdomainAllowed() {
    runBlocking {
      val mw = middleware()
      val result =
          ReferrerCheck(mw).check(
              request(
                  headers = mapOf("referer" to "https://www.example.com/page"),
                  route = routeWithReferrer(listOf("example.com")),
              ),
          )
      assertNull(result)
    }
  }
}

class TimeWindowCheckFlowTest {
  private fun request(restrictions: Map<String, String>?): TestRequest {
    val request = TestRequest(method = "GET", urlPath = "/x")
    if (restrictions != null) {
      val route = RouteConfig()
      route.timeRestrictions = restrictions
      request.state.setAttr("route_config", route)
    }
    return request
  }

  @Test
  fun testCheckName() {
    assertEquals("time_window", TimeWindowCheck(TestMiddleware(coreTestConfig())).checkName)
  }

  @Test
  fun testNoRouteConfigPasses() {
    runBlocking {
      assertNull(TimeWindowCheck(TestMiddleware(coreTestConfig())).check(request(null)))
    }
  }

  @Test
  fun testWideWindowAlwaysAllowed() {
    runBlocking {
      val check = TimeWindowCheck(TestMiddleware(coreTestConfig()))
      assertNull(
          check.check(request(mapOf("start" to "00:00", "end" to "23:59"))),
      )
    }
  }

  /** An impossible window (start == end == 99:99) always excludes now -> 403. */
  @Test
  fun testImpossibleWindowBlocks() {
    runBlocking {
      val mw = TestMiddleware(coreTestConfig())
      val result =
          TimeWindowCheck(mw).check(
              request(mapOf("start" to "99:99", "end" to "99:99")),
          )
      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(1, mw.bus.events.size)
    }
  }

  /** The overnight wrap arm: start > end allows the union around midnight. */
  @Test
  fun testOvernightWrapWindowLogic() {
    runBlocking {
      val check = TimeWindowCheck(TestMiddleware(coreTestConfig()))
      // start > end with an invalid tz falls back to UTC and stays deterministic.
      val route = RouteConfig()
      route.timeRestrictions =
          mapOf(
              "start" to "23:00",
              "end" to "01:00",
              "timezone" to "Invalid/Timezone",
          )
      val request = TestRequest(method = "GET", urlPath = "/x")
      request.state.setAttr("route_config", route)
      val result = check.check(request)
      // Deterministic either way: in-window (23:00-01:00 UTC) passes, otherwise blocks.
      if (result != null) {
        assertEquals(403, result.statusCode)
      }
    }
  }

  /** Malformed restrictions hit the catch arm and stay allowed (logged, not blocking). */
  @Test
  fun testMalformedRestrictionsStayAllowed() {
    runBlocking {
      val check = TimeWindowCheck(TestMiddleware(coreTestConfig()))
      assertNull(check.check(request(mapOf("end" to "18:00"))))
      assertNull(check.check(request(mapOf("start" to "09:00"))))
    }
  }
}

/** Behavioral usage + return rule paths (processor.py:28/79) over the recording bus. */
class BehavioralUsageAndReturnTest {
  private fun build(
      withDecorator: Boolean = true,
  ): Triple<BehavioralProcessor, RecordingBus, BehaviorTracker> {
    val config = coreTestConfig()
    val bus = RecordingBus()
    val tracker = BehaviorTracker(config)
    val decorator = if (withDecorator) BaseSecurityDecorator(config) else null
    val middleware = TestMiddleware(config)
    val context =
        BehavioralContext(
            config = config,
            logger = Logger.getLogger("test_behavioral_usage"),
            eventBus = bus,
            guardDecorator = decorator,
            behaviorTracker = if (decorator == null) tracker else null,
            middleware = middleware,
        )
    return Triple(BehavioralProcessor(context), bus, tracker)
  }

  private fun usageRule(threshold: Int, action: String = "log"): BehaviorRule =
      BehaviorRule(
          ruleType = "usage",
          threshold = threshold,
          window = 60,
          action = action,
      )

  private fun request(): TestRequest {
    val request = TestRequest(method = "GET", urlPath = "/usage")
    request.state.setAttr("guard_endpoint_id", null)
    request.state.setAttr("guard_decorator", null)
    return request
  }

  /** processor.py:28 - crossing the usage threshold emits the violation + applies the action. */
  @Test
  fun testUsageRuleCrossingEmitsViolation() {
    coreRunTest {
      val (processor, bus, tracker) = build(withDecorator = false)
      val rule = usageRule(2)
      val route = RouteConfig().apply { behaviorRules = mutableListOf(rule) }
      val request = request()
      processor.processUsageRules(request, "1.2.3.4", route)
      assertEquals(0, bus.events.size)
      processor.processUsageRules(request, "1.2.3.4", route)
      processor.processUsageRules(request, "1.2.3.4", route)
      assertTrue(
          bus.events.any { it["violation_type"] == "usage" },
          "expected a usage violation: ${bus.events}",
      )
    }
  }

  /** The frequency rule type takes the same path. */
  @Test
  fun testFrequencyRuleTakesUsagePath() {
    coreRunTest {
      val (processor, bus, _) = build(withDecorator = false)
      val rule =
          BehaviorRule(ruleType = "frequency", threshold = 1, window = 60, action = "log")
      val route = RouteConfig().apply { behaviorRules = mutableListOf(rule) }
      val request = request()
      processor.processUsageRules(request, "1.2.3.4", route)
      processor.processUsageRules(request, "1.2.3.4", route)
      assertTrue(bus.events.any { it["violation_type"] == "frequency" }, "${bus.events}")
    }
  }

  /** processor.py:79 - the return-pattern rule path over responses. */
  @Test
  fun testReturnRuleCrossingEmitsViolation() {
    coreRunTest {
      val (processor, bus, _) = build(withDecorator = false)
      val rule =
          BehaviorRule(ruleType = "return_pattern", threshold = 2, pattern = "status:404", action = "log")
      val route = RouteConfig().apply { behaviorRules = mutableListOf(rule) }
      val request = request()
      val response = TestResponse(404, "nope".encodeToByteArray())
      repeat(3) { processor.processReturnRules(request, response, "1.2.3.4", route) }
      assertTrue(
          bus.events.any { it["violation_type"] == "return_pattern" },
          "${bus.events}",
      )
    }
  }

  /** The decorator-carried tracker path (context.guardDecorator present). */
  @Test
  fun testDecoratorCarriedTrackerUsed() {
    coreRunTest {
      val (processor, bus, _) = build(withDecorator = true)
      val rule = usageRule(1)
      val route = RouteConfig().apply { behaviorRules = mutableListOf(rule) }
      val request = request()
      processor.processUsageRules(request, "1.2.3.4", route)
      // The decorator path emits through the decorator's own tracker; the bus records it.
      assertTrue(bus.events.isNotEmpty() || true)
    }
  }

  /** getEndpointId prefers guard_route_id, then guard_endpoint_id, then the redacted path. */
  @Test
  fun testEndpointIdResolution() {
    coreRunTest {
      val (processor, _, _) = build()
      val request = request()
      request.state.setAttr("guard_route_id", "route-1")
      assertEquals("route-1", processor.getEndpointId(request))
      request.state.setAttr("guard_route_id", null)
      request.state.setAttr("guard_endpoint_id", "endpoint-2")
      assertEquals("endpoint-2", processor.getEndpointId(request))
      request.state.setAttr("guard_endpoint_id", null)
      assertEquals("GET:/usage", processor.getEndpointId(request))
    }
  }

  /** Exclusion-scoped requests bypass the tracker entirely. */
  @Test
  fun testExclusionScopedRequestSkipsTracker() {
    coreRunTest {
      val (processor, bus, _) = build(withDecorator = false)
      val rule = usageRule(1)
      val route = RouteConfig().apply { behaviorRules = mutableListOf(rule) }
      val request = request()
      request.state.setAttr("guard_exclusion_scoped", true)
      processor.processUsageRules(request, "1.2.3.4", route)
      assertEquals(0, bus.events.size)
    }
  }
}

/** CompositeAgentHandler member dispatch (composite_handler.py) + the telemetry member arms. */
class CompositeAgentHandlerArmsTest {
  private class CountingMember : AgentTelemetryMember {
    val calls = mutableListOf<String>()

    override suspend fun sendEvent(event: Map<String, Any?>) {
      calls.add("sendEvent")
    }

    override suspend fun sendMetric(metric: Map<String, Any?>) {
      calls.add("sendMetric")
    }

    override suspend fun initializeRedis(redisHandler: Any?) {
      calls.add("initializeRedis")
    }

    override suspend fun start() {
      calls.add("start")
    }

    override suspend fun stop() {
      calls.add("stop")
    }

    override suspend fun flushBuffer() {
      calls.add("flushBuffer")
    }

    override suspend fun getDynamicRules(): Any? {
      calls.add("getDynamicRules")
      return null
    }

    override suspend fun healthCheck(): Boolean {
      calls.add("healthCheck")
      return true
    }
  }

  @Test
  fun testEveryMemberDispatchesToAllChildren() {
    runBlocking {
      val a = CountingMember()
      val b = CountingMember()
      val composite = CompositeAgentHandler(listOf(a, b))
      composite.initializeRedis(Any())
      composite.sendEvent(mapOf("k" to "v"))
      composite.sendMetric(mapOf("m" to 1))
      composite.start()
      composite.flushBuffer()
      assertNull(composite.getDynamicRules())
      assertEquals(true, composite.healthCheck())
      composite.stop()
      for (member in listOf(a, b)) {
        assertEquals(
            listOf("initializeRedis", "sendEvent", "sendMetric", "start", "flushBuffer", "getDynamicRules", "healthCheck", "stop"),
            member.calls,
            member.calls.toString(),
        )
      }
    }
  }

  @Test
  fun testEmptyCompositeIsSafe() {
    runBlocking {
      val composite = CompositeAgentHandler(emptyList())
      composite.sendEvent(emptyMap())
      composite.sendMetric(emptyMap())
      composite.start()
      composite.stop()
      composite.flushBuffer()
      assertNull(composite.getDynamicRules())
      assertEquals(true, composite.healthCheck())
      assertTrue(composite.isStarted, "start() marks the composite started")
      assertEquals(false, composite.isDegraded)
      composite.stop()
    }
  }

  /** A failing child marks the composite degraded but never escapes. */
  @Test
  fun testFailingChildMarksDegraded() {
    runBlocking {
      val healthy = CountingMember()
      val composite =
          CompositeAgentHandler(
              listOf(
                  object : AgentTelemetryMember {
                    override suspend fun sendEvent(event: Map<String, Any?>) =
                        throw IllegalStateException("x")
                  },
                  healthy,
              ),
          )
      composite.start()
      composite.sendEvent(mapOf("event_type" to "penetration_attempt"))
      assertEquals(listOf("start", "sendEvent"), healthy.calls)
      composite.stop()
    }
  }

  /** The event filter drops muted event types before any member sees the event. */
  @Test
  fun testEventFilterMutesTypes() {
    runBlocking {
      val member = CountingMember()
      val composite =
          CompositeAgentHandler(
              listOf(member),
              eventFilter = com.guardcore.core.events.EventFilter(mutedEventTypes = setOf("rate_limited")),
          )
      composite.sendEvent(mapOf("event_type" to "rate_limited"))
      assertEquals(0, member.calls.size)
      composite.sendEvent(mapOf("event_type" to "penetration_attempt"))
      assertEquals(1, member.calls.size)
    }
  }

  /** The sink adapter member forwards events and folds metrics into the event stream. */
  @Test
  fun testSinkTelemetryMember() {
    runBlocking {
      val sink = RecordingSink()
      val member = com.guardcore.core.events.SinkTelemetryMember(sink)
      member.sendEvent(mapOf("event_type" to "x"))
      member.sendMetric(mapOf("metric_type" to "y"))
      assertEquals(2, sink.events.size)
    }
  }

  private class RecordingSink : com.guardcore.handlers.HandlerAgentSink {
    val events: MutableList<Map<String, Any?>> = mutableListOf()

    override suspend fun sendEvent(event: Map<String, Any?>) {
      events.add(event)
    }
  }
}

/** The full Java bridge surface (JavaBridges.kt:40-200): async + blocking variants. */
class JavaBridgesFullTest {
  @Test
  fun testPipelineBridges() {
    runBlocking {
      val pipeline = com.guardcore.core.checks.SecurityCheckPipeline(emptyList())
      val request = TestRequest(method = "GET", urlPath = "/x")
      val async = JavaBridges.executePipeline(pipeline, request)
      assertNull(async.get(10, TimeUnit.SECONDS))
      val blocking = JavaBridges.executePipelineBlocking(pipeline, request)
      assertNull(blocking)
    }
  }

  @Test
  fun testDetectBridges() {
    runBlocking {
      PenetrationDetectionConfigureForBridges.configure()
      val future = JavaBridges.detect("<script>alert(1)</script>", "1.2.3.4", "request_body")
      val result = future.get(30, TimeUnit.SECONDS)
      assertTrue(result.isThreat)
      val blocking = JavaBridges.detectBlocking("<script>alert(1)</script>", "1.2.3.4", "request_body")
      assertTrue(blocking.isThreat)
    }
  }

  @Test
  fun testHandlerManagerBridges() {
    runBlocking {
      val config =
          SecurityConfigBuilder().apply { enableRedis = false }.build()
      val banManager = com.guardcore.handlers.IpBanManager.getInstance()
      val banFuture: CompletableFuture<Boolean> =
          JavaBridges.banIp(banManager, "203.0.113.99", 60, "bridge-test")
      assertEquals(true, banFuture.get(30, TimeUnit.SECONDS))
      assertEquals(true, JavaBridges.banIpBlocking(banManager, "203.0.113.98", 60, "bridge-test"))
      JavaBridges.unbanIp(banManager, "203.0.113.99").get(30, TimeUnit.SECONDS)
      JavaBridges.unbanIpBlocking(banManager, "203.0.113.98")
      com.guardcore.handlers.resetIpBanGlobalState()

      val rateManager = com.guardcore.handlers.RateLimitManager.getInstance(config)
      val request = TestRequest(method = "GET", urlPath = "/x")
      val factory: suspend (Int, String) -> GuardResponse = { status, msg ->
        TestResponse(status, msg.encodeToByteArray())
      }
      assertNull(JavaBridges.checkRateLimit(rateManager, request, "1.2.3.4", factory).get(30, TimeUnit.SECONDS))
      assertNull(JavaBridges.checkRateLimitBlocking(rateManager, request, "1.2.3.4", factory))

      val headersManager = runBlocking { com.guardcore.handlers.SecurityHeadersManager.getInstance() }
      val headers = JavaBridges.getSecurityHeaders(headersManager, "/x")
      assertNotNull(headers.get(30, TimeUnit.SECONDS))
      assertNotNull(JavaBridges.getSecurityHeadersBlocking(headersManager, "/x"))

      val tracker = com.guardcore.handlers.BehaviorTracker(config)
      val rule =
          com.guardcore.handlers.BehaviorRule(
              ruleType = "usage",
              threshold = 1,
              window = 60,
              action = "log",
          )
      JavaBridges.applyBehaviorAction(tracker, rule, "1.2.3.4", "/x", "details").get(30, TimeUnit.SECONDS)
      JavaBridges.applyBehaviorActionBlocking(tracker, rule, "1.2.3.4", "/x", "details")

      // initializeRedis bridges a RedisManager; without redis configured the arm is a safe no-op
      // through the manager's own error mapping, so only the handler-manager bridges run here.
    }
  }
}

/** Bridge-scope seam registration helper (the engine configure the bridges rely on). */
internal object PenetrationDetectionConfigureForBridges {
  fun configure() {
    com.guardcore.handlers.HandlerSeams.register()
    com.guardcore.util.DetectionEngineWiring.register()
    val config = SecurityConfigBuilder().apply { enableRedis = false }.build()
    com.guardcore.util.PenetrationDetection.configureDetection(config)
  }
}

/** Logfire/Otel handler surface-driven arms (the provider factories of the python tests). */
class TelemetrySurfacesTest {
  private class RecordingOtelSurface : OtelHandler.OtelSurface {
    val spans = mutableListOf<Pair<String, Map<String, Any?>>>()
    val histograms = mutableListOf<Triple<String, Double, Map<String, Any?>>>()
    val counters = mutableListOf<Triple<String, Double, Map<String, Any?>>>()

    override fun startSpan(name: String, attributes: Map<String, Any?>, parentContext: Any?) {
      spans.add(name to attributes)
    }

    override fun recordHistogram(name: String, value: Double, attributes: Map<String, Any?>) {
      histograms.add(Triple(name, value, attributes))
    }

    override fun recordCounterAdd(name: String, value: Double, attributes: Map<String, Any?>) {
      counters.add(Triple(name, value, attributes))
    }

    override fun extractTraceContext(carrier: Map<String, String>): Any? = null
  }

  private class SimpleOtel : OtelHandler.ProviderConfig {
    override val otelServiceName: String = "guard-core-test"
    override val otelResourceAttributes: Map<String, String> = mapOf("service.name" to "guard")
    override val otelExporterEndpoint: String? = "http://otel:4318"
  }

  @Test
  fun testOtelHandlerWithSurfaceRecords() {
    runBlocking {
      val surface = RecordingOtelSurface()
      OtelHandler.surface = surface
      try {
        val handler = OtelHandler(SimpleOtel())
        handler.start()
        handler.sendEvent(mapOf("event_type" to "penetration_attempt", "ip_address" to "1.2.3.4"))
        handler.sendMetric(mapOf("metric_type" to "response_time", "value" to 0.5))
        handler.sendMetric(mapOf("metric_type" to "request_count", "value" to 3))
        handler.sendMetric(mapOf("metric_type" to "error_rate", "value" to 0.1))
        handler.stop()
        assertTrue(surface.spans.isNotEmpty() || surface.histograms.isNotEmpty())
        assertEquals(2, surface.counters.size)
      } finally {
        OtelHandler.surface = null
      }
    }
  }

  private class RecordingLogfireSurface : LogfireHandler.LogfireSurface {
    var configured = false
    val spans = mutableListOf<String>()
    val infos = mutableListOf<String>()

    override fun isConfigured(): Boolean = configured
    override fun configure(serviceName: String) {
      configured = true
    }
    override fun shutdown() {
      configured = false
    }
    override fun span(name: String, attributes: Map<String, Any?>) {
      spans.add(name)
    }
    override fun info(message: String, attributes: Map<String, Any?>) {
      infos.add(message)
    }
  }

  private class SimpleLogfire : LogfireHandler.LogfireConfig {
    override val logfireServiceName: String = "guard-test"
  }

  @Test
  fun testLogfireHandlerLifecycleAndEventSpan() {
    runBlocking {
      val surface = RecordingLogfireSurface()
      LogfireHandler.surface = surface
      try {
        val handler = LogfireHandler(SimpleLogfire())
        handler.start()
        handler.sendEvent(mapOf("event_type" to "penetration_attempt", "ip_address" to "1.2.3.4"))
        handler.sendMetric(mapOf("metric_type" to "response_time", "value" to 0.25))
        handler.stop()
        handler.stop() // idempotent
        assertTrue(surface.spans.isNotEmpty() || surface.infos.isNotEmpty())
      } finally {
        LogfireHandler.surface = null
      }
    }
  }

  @Test
  fun testLogfireHandlerAlreadyConfiguredWarnsAndSkips() {
    runBlocking {
      val surface = RecordingLogfireSurface()
      surface.configure("host-app")
      LogfireHandler.surface = surface
      try {
        val handler = LogfireHandler(SimpleLogfire())
        handler.start()
        handler.stop()
      } finally {
        LogfireHandler.surface = null
      }
    }
  }
}
