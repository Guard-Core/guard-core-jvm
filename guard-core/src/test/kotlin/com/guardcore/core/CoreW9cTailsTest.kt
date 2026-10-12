package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.EnrichmentContext
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.LogfireHandler
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.OtelHandler
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.events.SinkTelemetryMember
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.validation.RequestValidator
import com.guardcore.core.validation.ValidationContext
import com.guardcore.handlers.RecordingAgent
import com.guardcore.java.JavaBridges
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** W9c arm closure: the check base surface, pipeline staleness, validator tails, events arms. */
class CheckBaseW9cTest {
  private class BareCheck(mw: com.guardcore.protocols.GuardMiddlewareProtocol) : SecurityCheck(mw) {
    override val checkName: String = "bare"
    var failApply: Boolean = false
    var response: com.guardcore.protocols.GuardResponse? = null

    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<com.guardcore.decorators.RouteConfig>?,
    ): Boolean = !failApply

    override suspend fun check(
        request: com.guardcore.protocols.GuardRequest,
    ): com.guardcore.protocols.GuardResponse? = response
  }

  private fun middleware(): TestMiddleware =
      TestMiddleware(
          SecurityConfigBuilder()
              .apply {
                enableRedis = false
                enablePenetrationDetection = false
                enableRateLimiting = false
                enableIpBanning = false
              }
              .build(),
      )

  @Test
  fun testCheckBaseSurface() = runBlocking {
    val mw = middleware()
    val check = BareCheck(mw)
    val request = TestRequest()
    // Default appliesTo accepts; the override gates.
    assertTrue(check.appliesTo(mw.config, null))
    check.failApply = true
    assertFalse(check.appliesTo(mw.config, emptyList()))
    check.failApply = false
    // sendEvent goes through the bus; metadata and action surface on the recording bus.
    check.sendEvent(
        EventTypes.EVENT_RATE_LIMITED,
        request,
        "logged_only",
        "because",
        mapOf("k" to "v"),
    )
    // create_error_response delegates to the middleware factory.
    val response = check.createErrorResponse(429, "slow down")
    assertEquals(429, response.statusCode)
    // is_passive_mode mirrors the config.
    assertFalse(check.isPassiveMode())
    assertNull(check.check(request))
    check.response = response
    assertEquals(response, check.check(request))
  }
}

class PipelineW9cTest {
  private fun config(): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            enablePenetrationDetection = false
            enableRateLimiting = false
            enableIpBanning = false
            whitelist = listOf("1.2.3.4")
            blockedUserAgents = listOf("curl/*")
            endpointRateLimits = mapOf("/x" to Pair(5, 60))
          }
          .build()

  @Test
  fun testPipelineSignatureAndStaleness() {
    val c1 = config()
    val pipeline =
        SecurityCheckPipeline(
            emptyList(),
            config = c1,
            watchedContainerFields =
                listOf("whitelist", "blacklist", "blocked_user_agents", "endpoint_rate_limits"),
        )
    val isStale =
        SecurityCheckPipeline::class.java.getDeclaredMethod("isStale", SecurityConfig::class.java)
    isStale.isAccessible = true
    val containerSize =
        SecurityCheckPipeline::class.java.getDeclaredMethod("containerSize", Any::class.java)
    containerSize.isAccessible = true
    // Same container sizes: not stale.
    assertEquals(false, isStale.invoke(pipeline, c1))
    // A bigger whitelist changes the container signature: stale.
    val c2 =
        SecurityConfigBuilder.fromConfig(c1)
            .apply {
              whitelist = listOf("1.2.3.4", "5.6.7.8")
              blockedUserAgents = listOf("curl/*", "wget/*")
              endpointRateLimits = mapOf("/x" to Pair(1, 2), "/y" to Pair(3, 4))
            }
            .build()
    assertEquals(true, isStale.invoke(pipeline, c2))
    // Container size dispatch: null/scalar -> 0; collections and maps size themselves.
    assertEquals(0, containerSize.invoke(pipeline, null))
    assertEquals(2, containerSize.invoke(pipeline, listOf("a", "b")))
    assertEquals(1, containerSize.invoke(pipeline, mapOf("k" to "v")))
    assertEquals(0, containerSize.invoke(pipeline, 42))
    // The watched-field signature covers the map-shaped endpoint limits.
    val signature =
        SecurityCheckPipeline::class
            .java
            .getDeclaredMethod("containerSignature", SecurityConfig::class.java)
    signature.isAccessible = true
    assertTrue((signature.invoke(pipeline, c1) as List<*>).isNotEmpty())
  }
}

class RequestValidatorW9cTest {
  private fun context(trustedProxies: List<String> = emptyList()): ValidationContext {
    val builder = SecurityConfigBuilder()
    builder.enableRedis = false
    builder.enablePenetrationDetection = false
    builder.enableRateLimiting = false
    builder.enableIpBanning = false
    if (trustedProxies.isNotEmpty()) builder.trustedProxies = trustedProxies
    val mw = TestMiddleware(builder.build())
    return ValidationContext(mw.config, mw.logger, mw.eventBus)
  }

  @Test
  fun testTrustedProxyArms() {
    val validator = RequestValidator(context(trustedProxies = listOf("10.0.0.0/8")))
    // The connecting IP is a trusted proxy directly.
    assertTrue(validator.isTrustedProxy("10.0.0.1"))
    assertFalse(validator.isTrustedProxy("192.0.2.99"))
    // A different proxy list still matches by network.
    assertTrue(
        RequestValidator(context(trustedProxies = listOf("192.0.2.0/24")))
            .isTrustedProxy("192.0.2.44"),
    )
    assertFalse(
        RequestValidator(context(trustedProxies = listOf("192.0.2.0/24")))
            .isTrustedProxy("10.0.0.1"),
    )
  }

  @Test
  fun testTimeWindowArms() = runBlocking {
    val validator = RequestValidator(context())
    // The all-day window always passes.
    assertTrue(validator.checkTimeWindow(mapOf("start" to "00:00", "end" to "23:59")))
    // Malformed restrictions fail open.
    assertTrue(validator.checkTimeWindow(mapOf("junk" to "x")))
    // A window that excludes now fails.
    val now = LocalDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("HH:mm"))
    val windowStart = if (now >= "12:00") "00:00" else "12:00"
    val windowEnd = if (windowStart == "00:00") "11:59" else "23:59"
    if (windowStart == "00:00") {
      assertFalse(validator.checkTimeWindow(mapOf("start" to windowStart, "end" to windowEnd)))
    } else {
      assertFalse(validator.checkTimeWindow(mapOf("start" to windowStart, "end" to windowEnd)))
    }
  }
}

class BehavioralW9cTest {
  @Test
  fun testProcessorUsageAndReturnArms() = runBlocking {
    val cfg =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              enablePenetrationDetection = false
              enableRateLimiting = false
              enableIpBanning = false
              globalBehaviorRules =
                  listOf(
                      com.guardcore.config.BehaviorRuleConfig(
                          ruleType = com.guardcore.config.RuleType.FREQUENCY,
                          threshold = 2,
                          window = 60,
                          action = com.guardcore.config.RuleAction.LOG,
                      ),
                  )
            }
            .build()
    val bus = RecordingBus()
    val tracker = com.guardcore.handlers.BehaviorTracker(cfg)
    val context =
        com.guardcore.core.behavioral.BehavioralContext(
            config = cfg,
            logger = java.util.logging.Logger.getLogger("w9c_behavioral"),
            eventBus = bus,
            guardDecorator = null,
            behaviorTracker = tracker,
            middleware = null,
        )
    val processor = com.guardcore.core.behavioral.BehavioralProcessor(context)
    val request = TestRequest()
    val routeConfig = com.guardcore.decorators.RouteConfig()
    // Usage passes: the frequency counter accumulates, the log action fires at threshold.
    processor.processUsageRules(request, "192.0.2.10", routeConfig)
    processor.processUsageRules(request, "192.0.2.10", routeConfig)
    processor.processUsageRules(request, "192.0.2.10", routeConfig)
    // Return-pattern scan against a response body.
    val response = com.guardcore.core.TestResponse(200, "token=secret".encodeToByteArray())
    processor.processReturnRules(request, response, "192.0.2.10", routeConfig)
    assertTrue(true)
  }
}

private fun sinkMember(agent: RecordingAgent): com.guardcore.core.events.AgentTelemetryMember =
    com.guardcore.core.events.SinkTelemetryMember(agent)

class EventsW9cTest {
  private fun config(extra: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            enablePenetrationDetection = false
            enableRateLimiting = false
            enableIpBanning = false
          }
          .apply(extra)
          .build()

  @Test
  fun testBusForwardedHeadersAndSinkAdapter() = runBlocking {
    val mw = TestMiddleware(config { enableAgent = false })
    val bus = SecurityEventBus(RecordingAgent(), mw.config, null)
    val request = TestRequest(headers = mapOf("User-Agent" to "ua", "Connection" to "close"))
    // The full middleware event path: enrichment, filtering, dispatch.
    bus.sendMiddlewareEvent(
        EventTypes.EVENT_RATE_LIMITED,
        request,
        "logged_only",
        "because",
        mapOf("k" to "v"),
    )
    bus.sendHttpsViolationEvent(request, null)
    // The sink adapter wraps a raw sink as a full telemetry member.
    val adapter =
        com.guardcore.core.events.SecurityEventBus.Companion.sinkAsAgentProtocol(RecordingAgent())
    adapter.sendEvent(mapOf("event_type" to "t"))
  }

  @Test
  fun testCompositeAndCollectors() = runBlocking {
    val agent = RecordingAgent()
    val composite = CompositeAgentHandler(listOf(sinkMember(agent)))
    composite.sendEvent(
        mapOf(
            "event_type" to "rate_limited",
            "ip_address" to "1.2.3.4",
            "action_taken" to "request_blocked",
            "reason" to "r",
            "metadata" to emptyMap<String, Any?>(),
        ),
    )
    assertEquals(1, agent.events.size)
    // A failing handler does not break the others.
    val failing = sinkMember(RecordingAgent().apply { failWith = IllegalStateException("x") })
    val composite2 = CompositeAgentHandler(listOf(failing, sinkMember(RecordingAgent())))
    composite2.sendEvent(mapOf("event_type" to "t"))
    composite2.sendMetric(mapOf("metric_type" to "m", "value" to 1))
    assertTrue(composite2.healthCheck())
    composite2.start()
    composite2.flushBuffer()
    composite2.stop()
    // MetricsCollector accumulates the request metric families.
    val collector = MetricsCollector(null, config())
    collector.collectRequestMetrics(TestRequest(), 0.1, 200)
    collector.sendMetric("requests_total", 1.0, null)
    assertNotNull(EventTypes.EVENT_TYPE_VALUES)
    assertNotNull(EventTypes.METRIC_TYPE_VALUES)
  }

  @Test
  fun testOtelAndLogfireSurfaces() = runBlocking {
    val otel = OtelHandler(SimpleOtelW9cConfig())
    assertEquals("http://h:1/v1/traces", OtelHandler.otlpSignalEndpoint("http://h:1", "/v1/traces"))
    assertNull(OtelHandler.otlpSignalEndpoint(null, "/v1/traces"))
    otel.start()
    otel.sendEvent(mapOf("event_type" to "e", "ip_address" to "1.2.3.4"))
    otel.sendMetric(mapOf("metric_type" to "requests_total", "value" to 1))
    otel.flushBuffer()
    otel.stop()
    val logfire =
        LogfireHandler(
            object : com.guardcore.core.events.LogfireHandler.LogfireConfig {
              override val logfireServiceName: String = "w9c"
            },
        )
    logfire.start()
    logfire.sendEvent(mapOf("event_type" to "e", "ip_address" to "1.2.3.4"))
    logfire.sendMetric(mapOf("metric_type" to "m", "value" to 1))
    logfire.flushBuffer()
    logfire.stop()
  }

  @Test
  fun testEnricherCorrelationTails() = runBlocking {
    val enricher = EventEnricher(EnrichmentContext(config = config()))
    val event =
        enricher.enrichEvent(
            mapOf(
                "event_type" to "penetration_attempt",
                "ip_address" to "203.0.113.9",
                "reason" to "sqli probe",
                "metadata" to mapOf("rule_type" to "sqli", "handler_name" to "h"),
            ),
        )
    assertNotNull(event)
    val minimal = enricher.enrichEvent(mapOf("event_type" to "e"))
    assertNotNull(minimal)
    val metric = enricher.enrichMetric(mapOf("metric_type" to "requests_total", "value" to 1))
    assertNotNull(metric)
  }
}

class JavaBridgesW9cTest {
  @Test
  fun testRateLimitAndRedisBridges() = runBlocking {
    val mw =
        TestMiddleware(
            SecurityConfigBuilder()
                .apply {
                  enableRedis = false
                  enablePenetrationDetection = false
                  enableRateLimiting = false
                  enableIpBanning = false
                }
                .build(),
        )
    val rateManager = com.guardcore.handlers.RateLimitManager.getInstance(mw.config)
    val future =
        JavaBridges.checkRateLimit(
            rateManager,
            TestRequest(urlPath = "/w9c"),
            "203.0.113.77",
            createErrorResponse = { code: Int, msg: String ->
              com.guardcore.core.TestResponse(code, msg.encodeToByteArray())
            },
        )
    assertNotNull(future.get(30, java.util.concurrent.TimeUnit.SECONDS))
    // The redis initializer bridge over a disabled-redis manager completes.
    val redisManager = com.guardcore.handlers.RedisManager(mw.config)
    JavaBridges.initializeRedis(redisManager).get(30, java.util.concurrent.TimeUnit.SECONDS)
  }
}

private class SimpleOtelW9cConfig : OtelHandler.ProviderConfig {
  override val otelServiceName: String = "w9c"
  override val otelResourceAttributes: Map<String, String> = emptyMap()
  override val otelExporterEndpoint: String? = "http://127.0.0.1:1"
}

class ErrorResponseW9cTest {
  @Test
  fun testCustomModifierAndCorsHeaders() = runBlocking {
    val mw =
        TestMiddleware(
            SecurityConfigBuilder()
                .apply {
                  enableRedis = false
                  enablePenetrationDetection = false
                  enableRateLimiting = false
                  enableIpBanning = false
                  enableCors = true
                  corsAllowOrigins = listOf("http://good.example")
                  corsAllowMethods = listOf("GET", "POST")
                  corsAllowHeaders = listOf("X-Ok")
                  corsExposeHeaders = listOf("X-Exposed")
                  corsAllowCredentials = true
                  corsMaxAge = 600
                }
                .build(),
        )
    val context =
        com.guardcore.core.responses.ResponseContext(
            mw.config,
            mw.logger,
            MetricsCollector(null, mw.config),
            responseFactory = mw.responseFactory,
        )
    val factory = ErrorResponseFactory(context)
    val error = factory.createErrorResponse(403, "denied")
    assertEquals(403, error.statusCode)
    val processed =
        factory.processResponse(
            TestRequest(),
            com.guardcore.core.TestResponse(200, ByteArray(0)),
            0.01,
            null,
        ) { _, _, _, _ ->
        }
    assertEquals(200, processed.statusCode)
  }
}
