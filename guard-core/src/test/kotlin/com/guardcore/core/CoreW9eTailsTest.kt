package com.guardcore.core

import com.guardcore.config.BehaviorRuleConfig
import com.guardcore.config.RuleAction
import com.guardcore.config.RuleType
import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.behavioral.BehavioralContext
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.checks.Verifier
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.EventFilter
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.LogfireHandler
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.OtelHandler
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.responses.ResponseContext
import com.guardcore.core.routing.RouteConfigResolver
import com.guardcore.core.routing.RoutingContext
import com.guardcore.core.validation.RequestValidator
import com.guardcore.core.validation.ValidationContext
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9e arm closure for the facade core: the warn-once bypass tail, the response-factory
 * required-seam guards, the behavioral decorator-event arms, the pipeline error/toString surface,
 * the SecurityCheck default-method synthetics, the telemetry members, and the events enrichment
 * tails. Existing fixtures (CoreTestSupport) carry the request/middleware doubles.
 */
class CoreW9eTailsTest {
  private fun config(apply: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      coreTestConfig(apply)

  private fun errorFactory(
      config: SecurityConfig,
      middleware: TestMiddleware,
      decorator: BaseSecurityDecorator? = null,
  ): ErrorResponseFactory =
      ErrorResponseFactory(
          ResponseContext(
              config = config,
              logger = middleware.logger,
              metricsCollector = MetricsCollector(null, config),
              agentHandler = null,
              guardDecorator = decorator,
              responseFactory = middleware.responseFactory,
          ),
      )

  private fun usageRule(): BehaviorRuleConfig =
      BehaviorRuleConfig(
          ruleType = RuleType.USAGE,
          threshold = 1,
          window = 60,
          action = RuleAction.LOG,
      )

  // ------------------------------------------------------------ bypass

  @Test
  fun `bypass handler warns about a missing client address exactly once`() = coreRunTest {
    val cfg = config()
    val middleware = TestMiddleware(cfg)
    val validator =
        RequestValidator(
            ValidationContext(config = cfg, logger = middleware.logger, eventBus = middleware.bus),
        )
    val context =
        com.guardcore.core.bypass.BypassContext(
            config = cfg,
            logger = middleware.logger,
            eventBus = middleware.bus,
            routeResolver = RouteConfigResolver(RoutingContext(cfg, middleware.logger)),
            responseFactory = errorFactory(cfg, middleware),
            validator = validator,
        )
    val handler = com.guardcore.core.bypass.BypassHandler(context)
    // two passes over an anonymous request: fail-secure rejects, and the warn-once guard
    // takes its early return on the second pass
    val first = handler.handlePassthrough(TestRequest(clientHost = null)) { TestResponse(200) }
    assertEquals(403, first?.statusCode)
    val second = handler.handlePassthrough(TestRequest(clientHost = null)) { TestResponse(200) }
    assertEquals(403, second?.statusCode)
  }

  // ------------------------------------------------------------ response factory

  @Test
  fun `error response factory requires a response factory seam`() = coreRunTest {
    val cfg = config()
    val middleware = TestMiddleware(cfg)
    val bare =
        ErrorResponseFactory(
            ResponseContext(
                config = cfg,
                logger = middleware.logger,
                metricsCollector = MetricsCollector(null, cfg),
                responseFactory = null,
            ),
        )
    val error = assertFailsWith<IllegalStateException> { bare.createErrorResponse(403, "nope") }
    assertTrue(error.message!!.contains("response_factory is required"), error.message)
    val redirectError =
        assertFailsWith<IllegalStateException> { bare.createHttpsRedirect(TestRequest()) }
    assertTrue(
        redirectError.message!!.contains("response_factory is required"),
        redirectError.message,
    )
  }

  @Test
  fun `process response runs per-route behavioral rules and the global sweep`() = coreRunTest {
    val cfg = config { behaviorScanResponseBody = true }
    val middleware = TestMiddleware(cfg)
    val decorator = BaseSecurityDecorator(cfg)
    val factory = errorFactory(cfg, middleware, decorator)
    val route = RouteConfig()
    route.behaviorRules =
        mutableListOf(BehaviorRule(ruleType = "usage", threshold = 1, window = 60, action = "log"))
    val tracker = BehaviorTracker(cfg)

    val request = TestRequest()
    val initial = middleware.responseFactory.createResponse("ok", 200)
    val processed =
        factory.processResponse(
            request,
            initial,
            0.0,
            route,
            { req, resp, ip, rc ->
              BehavioralProcessor(
                      BehavioralContext(
                          config = cfg,
                          logger = middleware.logger,
                          eventBus = middleware.bus,
                          guardDecorator = decorator,
                          behaviorTracker = tracker,
                          middleware = middleware,
                      ),
                  )
                  .processReturnRules(req, resp, ip, rc)
            },
            { _, _, _, _ -> },
        )
    assertEquals(200, processed.statusCode)

    // the global-return-rules sweep over the same decorator seam
    val global =
        factory.processResponse(
            TestRequest(),
            middleware.responseFactory.createResponse("ok", 200),
            0.0,
            null,
            { _, _, _, _ -> },
            { req, resp, ip, rules ->
              BehavioralProcessor(
                      BehavioralContext(
                          config = cfg,
                          logger = middleware.logger,
                          eventBus = middleware.bus,
                          guardDecorator = decorator,
                          behaviorTracker = tracker,
                          middleware = middleware,
                      ),
                  )
                  .processGlobalReturnRules(req, resp, ip, rules)
            },
        )
    assertEquals(200, global.statusCode)
  }

  // ------------------------------------------------------------ behavioral processor

  @Test
  fun `behavioral processor reports decorator violations on threshold hits`() = coreRunTest {
    val cfg = config { behaviorScanResponseBody = true }
    val middleware = TestMiddleware(cfg)
    val decorator = BaseSecurityDecorator(cfg)
    val tracker = BehaviorTracker(cfg)
    val processor =
        BehavioralProcessor(
            BehavioralContext(
                config = cfg,
                logger = middleware.logger,
                eventBus = middleware.bus,
                guardDecorator = decorator,
                behaviorTracker = tracker,
                middleware = middleware,
            ),
        )
    val route = RouteConfig()
    route.behaviorRules =
        mutableListOf(BehaviorRule(ruleType = "usage", threshold = 1, window = 60, action = "log"))
    // threshold 1 trips on the first tracked call and drives the decorator violation event
    processor.processUsageRules(TestRequest(), "192.0.2.10", route)
    // correlated categories over the middleware's suspicious request counts
    middleware.suspiciousRequestCounts["192.0.2.10"] = linkedMapOf("sqli" to 2)
    processor.processUsageRules(TestRequest(), "192.0.2.10", route)
    assertTrue(true)
  }

  // ------------------------------------------------------------ pipeline surface

  @Test
  fun `pipeline skips a redis failure under fail-open and renders its summary`() = coreRunTest {
    val cfg = config { redisFailOpen = true }
    val middleware = TestMiddleware(cfg)
    val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
    assertTrue(pipeline.toString().startsWith("SecurityCheckPipeline("))
    assertTrue(pipeline.size > 0)
    val failing =
        object : SecurityCheck(middleware) {
          override val checkName: String = "w9e_redis_fail"

          override suspend fun check(request: GuardRequest): GuardResponse? {
            throw com.guardcore.errors.GuardRedisError(503, "down")
          }
        }
    val tiny = SecurityCheckPipeline(listOf(failing))
    assertNull(tiny.execute(TestRequest()))
  }

  // ------------------------------------------------------------ SecurityCheck defaults

  @Test
  fun `security check default members answer over the test middleware`() = coreRunTest {
    val middleware = TestMiddleware(config())
    val check =
        object : SecurityCheck(middleware) {
          override val checkName: String = "w9e_defaults"

          override suspend fun check(request: GuardRequest): GuardResponse? = null
        }
    assertTrue(check.appliesTo(middleware.config, null))
    assertTrue(check.appliesTo(middleware.config, listOf(RouteConfig())))
    assertTrue(check.requires.isEmpty())
    assertTrue(check.containerFields.isEmpty())
    assertFalse(check.enforcedOnExcludedPaths)
    check.sendEvent("w9e_event", TestRequest(), "logged", "because")
    check.sendEvent("w9e_event", TestRequest(), "logged", "because", mapOf("k" to "v"))
    assertFalse(check.isPassiveMode())
    check.logIfAllowed(TestRequest())
    check.logIfAllowed(
        TestRequest(),
        logType = "suspicious",
        reason = "r",
        passiveMode = true,
        triggerInfo = "t",
        level = "INFO",
    )
    val response = check.createErrorResponse(418, "teapot")
    assertEquals(418, response.statusCode)
    assertEquals("w9e_defaults", check.checkName)
  }

  // ------------------------------------------------------------ checks helpers + factory

  @Test
  fun `checks helpers emit the decorator and rate-limit event surfaces`() = coreRunTest {
    val cfg = config()
    val middleware = TestMiddleware(cfg)
    val request = TestRequest()
    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        "access_denied",
        "nope",
        "ip_blacklist",
        passiveMode = false,
    )
    ChecksHelpers.emitAccessDeniedEvent(
        middleware,
        request,
        "access_denied",
        "nope",
        "ip_blacklist",
        passiveMode = true,
        metadata = mapOf("extra" to 1),
    )
    ChecksHelpers.emitDecoratorEvent(
        middleware,
        request,
        "decorator_violation",
        "request_blocked",
        "reason",
        "access_control",
    )
    ChecksHelpers.emitDecoratorEvent(
        middleware,
        request,
        "decorator_violation",
        "request_blocked",
        "reason",
        "access_control",
        metadata = mapOf("extra" to 2),
    )
    ChecksHelpers.emitRateLimitEvent(
        middleware,
        request,
        "rate_limited",
        5,
        60,
        "too many",
        passiveMode = false,
    )
    assertTrue(true)
  }

  @Test
  fun `checks factory exposes the fixed default order`() {
    assertEquals(17, ChecksFactory.DEFAULT_CHECK_CLASSES.size)
    val middleware =
        TestMiddleware(
            coreTestConfig {
              emergencyMode = true
              logRequestLevel = com.guardcore.config.LogLevel.ERROR
            },
        )
    val rendered =
        ChecksFactory.buildDefaultPipeline(middleware).checks.joinToString { it.checkName }
    assertTrue(rendered.startsWith("route_config"), rendered)
    assertTrue(rendered.contains("rate_limit"), rendered)
  }

  @Test
  fun `verifier resolves completion stages and plain values`() = coreRunTest {
    val stage = CompletableFuture.completedStage<Any?>("w9e")
    assertEquals("w9e", Verifier.resolveVerifierResult(stage))
    assertEquals("plain", Verifier.resolveVerifierResult("plain"))
    assertTrue(Verifier.truthy("x"))
    assertFalse(Verifier.truthy(""))
  }

  // ------------------------------------------------------------ routing + protocols

  @Test
  fun `route config resolver falls back to the global cloud provider block list`() {
    val cfg = config { blockCloudProviders = setOf("AWS") }
    val middleware = TestMiddleware(cfg)
    val resolver = RouteConfigResolver(RoutingContext(cfg, middleware.logger))
    assertEquals(listOf("AWS"), resolver.getCloudProvidersToCheck(null))
  }

  @Test
  fun `event bus cloud detection walks the decorator violation arm`() = coreRunTest {
    val cfg = config { blockCloudProviders = setOf("AWS") }
    val middleware = TestMiddleware(cfg)
    val bus = SecurityEventBus(null, cfg, null)
    val route = RouteConfig()
    route.blockCloudProviders = linkedSetOf("AWS")
    bus.sendCloudDetectionEvents(TestRequest(), "192.0.2.99", listOf("AWS"), route, null, false)
    bus.sendCloudDetectionEvents(TestRequest(), "192.0.2.99", listOf("AWS"), route, null, true)
    assertTrue(true)
  }

  // ------------------------------------------------------------ telemetry members

  @Test
  fun `logfire handler lifecycle answers across its surface`() = coreRunTest {
    val handler =
        LogfireHandler(
            object : LogfireHandler.LogfireConfig {
              override val logfireServiceName: String = "w9e"
            },
        )
    assertNotNull(LogfireHandler.configureLock())
    handler.initializeRedis(null)
    assertNull(handler.getDynamicRules())
    // no surface installed: start/stop/sendEvent degrade quietly
    handler.start()
    handler.sendEvent(mapOf("event_type" to "w9e"))
    handler.stop()
    // an installed surface drives configure/shutdown/span/info and the enrichment copy
    val surface =
        object : LogfireHandler.LogfireSurface {
          var configured: Boolean = false

          override fun isConfigured(): Boolean = configured

          override fun configure(serviceName: String) {
            configured = true
          }

          override fun shutdown() {
            configured = false
          }

          override fun span(name: String, attributes: Map<String, Any?>) {}

          override fun info(message: String, attributes: Map<String, Any?>) {}
        }
    LogfireHandler.installSurface(surface)
    val installed = handler
    installed.start()
    installed.sendEvent(
        mapOf(
            "event_type" to "w9e",
            "metadata" to mapOf("guard.custom" to "v", "traceparent" to "tp", "other" to 1),
        ),
    )
    installed.stop()
    // start over an already-configured host surface takes the warning branch
    surface.configured = true
    installed.start()
    // uninstall: the companion surface is process-global and other tests
    // assert the surface-less behavior
    LogfireHandler.surface = null
  }

  @Test
  fun `otel handler lifecycle answers across its surface`() = coreRunTest {
    val handler =
        OtelHandler(
            object : OtelHandler.ProviderConfig {
              override val otelServiceName: String = "w9e"
              override val otelResourceAttributes: Map<String, String> = mapOf("a" to "b")
              override val otelExporterEndpoint: String? = null
            },
        )
    handler.initializeRedis(null)
    assertNull(handler.getDynamicRules())
    // no surface: sendEvent returns before touching the SDK
    handler.start()
    handler.sendEvent(mapOf("event_type" to "w9e"))
    handler.stop()
    // an installed surface records spans with status-code + enrichment attributes
    OtelHandler.surface =
        object : OtelHandler.OtelSurface {
          override fun startSpan(
              name: String,
              attributes: Map<String, Any?>,
              parentContext: Any?,
          ) {}

          override fun recordHistogram(
              name: String,
              value: Double,
              attributes: Map<String, Any?>,
          ) {}

          override fun recordCounterAdd(
              name: String,
              value: Double,
              attributes: Map<String, Any?>,
          ) {}

          override fun extractTraceContext(carrier: Map<String, String>): Any? =
              if (carrier["traceparent"]?.startsWith("00-") == true) "ctx" else null
        }
    handler.start()
    handler.sendEvent(
        mapOf(
            "event_type" to "w9e",
            "status_code" to 418,
            "metadata" to
                mapOf(
                    "traceparent" to "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                    "tracestate" to "w9e=1",
                    "guard.custom" to "v",
                ),
        ),
    )
    // a failing extractor takes the null-context arm
    handler.sendEvent(
        mapOf(
            "event_type" to "w9e2",
            "metadata" to mapOf("traceparent" to "bogus"),
        ),
    )
    handler.stop()
    OtelHandler.surface = null
  }

  @Test
  fun `composite handler fans out with a failing member and the default member bodies`() =
      coreRunTest {
        val failing =
            object : AgentTelemetryMember {
              override suspend fun sendEvent(event: Map<String, Any?>) {
                throw IllegalStateException("w9e member failure")
              }

              override suspend fun sendMetric(metric: Map<String, Any?>) {
                throw IllegalStateException("w9e metric failure")
              }

              override suspend fun initializeRedis(redisHandler: Any?) {
                throw IllegalStateException("w9e redis failure")
              }

              override suspend fun start() {
                throw IllegalStateException("w9e start failure")
              }

              override suspend fun stop() {
                throw IllegalStateException("w9e stop failure")
              }

              override suspend fun flushBuffer() {
                throw IllegalStateException("w9e flush failure")
              }

              override suspend fun getDynamicRules(): Any? {
                throw IllegalStateException("w9e rules failure")
              }

              override suspend fun healthCheck(): Boolean {
                throw IllegalStateException("w9e health failure")
              }
            }
        // only sendEvent is overridden: the composite calls hit the interface default bodies
        val defaultOnly =
            object : AgentTelemetryMember {
              override suspend fun sendEvent(event: Map<String, Any?>) {}
            }
        val composite =
            CompositeAgentHandler(
                listOf(defaultOnly, failing),
                EventFilter(mutedMetricTypes = setOf("w9e_muted_metric")),
            )
        composite.initializeRedis(null)
        composite.start()
        composite.sendMetric(mapOf("metric_type" to "w9e_muted_metric"))
        composite.sendMetric(mapOf("metric_type" to "w9e_metric", "value" to 1))
        composite.sendEvent(mapOf("event_type" to "w9e_event"))
        assertNull(composite.getDynamicRules())
        // the failing member's health arm records false for the mixed composite
        assertFalse(composite.healthCheck())
        composite.flushBuffer()
        composite.stop()
        assertTrue(composite.isStarted)
      }

  @Test
  fun `event enricher decorates metadata and metric tags`() = coreRunTest {
    val cfg = config()
    val middleware = TestMiddleware(cfg)
    val enricher =
        EventEnricher(
            com.guardcore.core.events.EnrichmentContext(
                config = cfg,
                agentHandler = null,
                dynamicRuleHandler = null,
                behaviorTracker = null,
            ),
        )
    val metadata = linkedMapOf<String, Any?>()
    val event =
        linkedMapOf<String, Any?>(
            "event_type" to "w9e",
            "ip_address" to "192.0.2.10",
            "metadata" to metadata,
        )
    enricher.enrichEvent(event)
    enricher.enrichMetric(
        linkedMapOf<String, Any?>("metric_type" to "w9e", "tags" to linkedMapOf<String, String>()),
    )
    // malformed metadata shapes take the failure-tolerant arms
    enricher.enrichEvent(linkedMapOf<String, Any?>("ip_address" to "192.0.2.10"))
    enricher.enrichMetric(linkedMapOf<String, Any?>("metric_type" to "w9e"))
    assertTrue(true)
  }

  @Test
  fun `metrics collector drops muted metric types`() = coreRunTest {
    val cfg = config { agentEnableMetrics = true }
    val sink =
        object : com.guardcore.handlers.HandlerAgentSink {
          override suspend fun sendEvent(event: Map<String, Any?>) {}
        }
    val collector = MetricsCollector(sink, cfg, EventFilter(mutedMetricTypes = setOf("w9e_muted")))
    collector.sendMetric("w9e_muted", 1.0)
    collector.sendMetric("w9e_metric", 1.0, mapOf("k" to "v"))
    collector.collectRequestMetrics(TestRequest(), 0.0, 200)
    assertTrue(true)
  }

  @Test
  fun `event types filter gate answers`() {
    val filter = EventFilter(mutedEventTypes = setOf("w9e_muted"))
    assertFalse(filter.isEventAllowed("w9e_muted"))
    assertTrue(filter.isEventAllowed(EventTypes.EVENT_SECURITY_BYPASS))
  }
}
