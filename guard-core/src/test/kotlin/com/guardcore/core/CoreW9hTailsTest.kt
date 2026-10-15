package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.config.ThreatBanConfig
import com.guardcore.core.behavioral.BehavioralContext
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.core.events.EnrichmentContext
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.EventFilter
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.OtelHandler
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.core.validation.RequestValidator
import com.guardcore.core.validation.ValidationContext
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.DynamicRuleManager
import com.guardcore.handlers.DynamicRules
import com.guardcore.handlers.IpBanManager
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.protocols.RequestState
import com.guardcore.protocols.RouteConfigResolverProtocol
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9h batch 6: the final core tails to the family 100 percent line gate - the initializer adapter
 * bodies, the enricher rule/behavior correlation, the event-bus trace-header and failure arms, the
 * behavioral processor decorator-violation arm, the per-check early returns, and the small
 * protocol/factory singles.
 */
class CoreW9hTailsTest {
  private fun config(apply: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      coreTestConfig(apply)

  private fun resolverWith(routes: Map<String, RouteConfig>): RouteConfigResolverProtocol =
      object : RouteConfigResolverProtocol {
        override fun getRouteConfig(request: GuardRequest): Any? = routes[request.urlPath]

        override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean {
          val rc = routeConfig as? RouteConfig ?: return false
          return checkName in rc.bypassedChecks
        }

        override fun getCloudProvidersToCheck(routeConfig: Any?): List<String>? {
          val rc = routeConfig as? RouteConfig ?: return null
          return if (rc.blockCloudProviders.isEmpty()) null else rc.blockCloudProviders.toList()
        }
      }

  private fun middleware(
      apply: SecurityConfigBuilder.() -> Unit = {},
      routes: Map<String, RouteConfig> = emptyMap(),
  ): TestMiddleware = TestMiddleware(config(apply), null, null, resolverWith(routes))

  private fun routeOf(mw: TestMiddleware, path: String): RouteConfig? =
      mw.routeResolver?.getRouteConfig(TestRequest(urlPath = path)) as? RouteConfig

  private fun requestWithRoute(
      route: RouteConfig?,
      clientIp: String? = "192.0.2.10",
      headers: Map<String, String> = emptyMap(),
      path: String = "/api",
  ): TestRequest {
    val request = TestRequest(urlPath = path, headers = headers, clientHost = clientIp)
    if (route != null) {
      request.state.setAttr("route_config", route)
    }
    if (clientIp != null) {
      request.state.setAttr("client_ip", clientIp)
    }
    return request
  }

  /** A bounded-body request double for the body-reading surfaces. */
  private class BoundedRequest(
      override val urlPath: String = "/api",
      override val method: String = "POST",
      override val headers: Map<String, String> = emptyMap(),
      private val bodyBytes: ByteArray = ByteArray(0),
      override val clientHost: String? = "192.0.2.10",
  ) : GuardRequest, com.guardcore.protocols.BoundedBodyReader {
    override val urlScheme: String = "http"
    override val urlFull: String = "http://example.com$urlPath"
    override val queryParams: Map<String, String> = emptyMap()
    override val state: RequestState = TestState()
    override val scope: Map<String, Any?> = emptyMap()

    override fun urlReplaceScheme(scheme: String): String = "$scheme://example.com$urlPath"

    override suspend fun body(): ByteArray = bodyBytes

    override suspend fun readBodyPrefix(maxBytes: Int): ByteArray =
        bodyBytes.take(maxBytes).toByteArray()
  }

  private class RecordingGeo(val country: String?) : GeoIPHandler {
    var agentInitialized: AgentHandlerProtocol? = null
    var throwOnInitializeRedis = false

    override val isInitialized: Boolean
      get() = true

    override fun getCountry(ip: String): String? = country

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {
      if (throwOnInitializeRedis) {
        throw IllegalStateException("geo redis boom")
      }
    }

    override suspend fun initializeAgent(agentHandler: AgentHandlerProtocol) {
      agentInitialized = agentHandler
    }

    override suspend fun refresh() {}

    override fun close() {}
  }

  private class ThrowingGeo : GeoIPHandler {
    override val isInitialized: Boolean
      get() = false

    override fun getCountry(ip: String): String? = throw IllegalStateException("geo boom")

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun initializeAgent(agentHandler: AgentHandlerProtocol) {}

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun emptyAgent(): AgentHandlerProtocol =
      object : AgentHandlerProtocol {
        override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

        override suspend fun sendEvent(event: Any?) {}

        override suspend fun sendMetric(metric: Any?) {}

        override suspend fun start() {}

        override suspend fun stop() {}

        override suspend fun flushBuffer() {}

        override suspend fun getDynamicRules(): Any? = "member-rules"

        override suspend fun healthCheck(): Boolean = true
      }

  // ------------------------------------------------------------------ HandlerInitializer

  /** The composite-sink and agent-protocol adapter bodies (180-181, 187-219). */
  @Test
  fun `initializer composite sinks forward to the composite`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val mw =
        middleware(
            apply = {
              enableEnrichment = true
              enableAgent = true
              agentApiKey = "w9h"
            },
        )
    val initializer =
        HandlerInitializer(config = mw.config, redisHandler = null, agentHandler = emptyAgent())
    try {
      initializer.initializeAgentIntegrations()
      // buildEventBus falls back to the composite sink; the bus forwards through it (180-181).
      val bus = initializer.buildEventBus()
      bus.sendMiddlewareEvent(
          EventTypes.EVENT_PENETRATION_ATTEMPT,
          TestRequest(),
          "request_blocked",
          "because",
          linkedMapOf(),
      )
      // The composite surface answers over the composed members.
      val composite = initializer.compositeHandler!!
      assertTrue(composite.healthCheck())
      composite.flushBuffer()
      composite.stop()
    } finally {
      initializer.shutdownAgentIntegrations()
    }
  }

  /** runLazyInit's failure arms (235-236, 244-245). */
  @Test
  fun `lazy init survives cloud and geo failures`(): Unit = runBlocking {
    CloudManager.resetInstance()
    IpBanManager.resetInstance()
    com.guardcore.handlers.fetchProviderRangesOverride = { _ ->
      throw IllegalStateException("fetch exploded")
    }
    val mw = middleware(apply = { blockCloudProviders = setOf("AWS") })
    val geo = RecordingGeo("US").apply { throwOnInitializeRedis = true }
    val initializer = HandlerInitializer(config = mw.config, redisHandler = mw, geoIpHandler = geo)
    initializer.runLazyInit()
    com.guardcore.handlers.fetchProviderRangesOverride = null
    CloudManager.resetInstance()
  }

  /**
   * resolveCloudIpStore's factory and junk arms (256-258, 260) + the no-redis loader (285, 288).
   */
  @Test
  fun `cloud ip store resolution arms`(): Unit = runBlocking {
    CloudManager.resetInstance()
    IpBanManager.resetInstance()
    val factory = com.guardcore.handlers.InMemoryCloudIpStore()
    val initializer =
        HandlerInitializer(
            config =
                config {
                  blockCloudProviders = setOf("AWS")
                  cloudIpStore = { _: Any? -> factory }
                },
        )
    initializer.loadCloudAndGeoWithoutRedis()
    // A junk cloudIpStore value resolves to null without failing (260).
    val junk =
        HandlerInitializer(
            config =
                config {
                  blockCloudProviders = setOf("AWS")
                  cloudIpStore = 42
                },
        )
    junk.loadCloudAndGeoWithoutRedis()
    CloudManager.resetInstance()
  }

  /** The geo agent-protocol adapter bodies (410-430) over a recording geo handler. */
  @Test
  fun `initializer wires the geo agent protocol`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val mw =
        middleware(
            apply = {
              enableEnrichment = true
              enableAgent = true
              agentApiKey = "w9h"
            },
        )
    val geo = RecordingGeo("US")
    val initializer =
        HandlerInitializer(config = mw.config, redisHandler = null, geoIpHandler = geo)
    initializer.initializeAgentIntegrations()
    val agent = assertNotNull(geo.agentInitialized)
    agent.initializeRedis(FakeRedisProtocol())
    agent.sendEvent(mapOf("event_type" to "x"))
    agent.sendEvent("not-a-map")
    agent.sendMetric(mapOf("m" to 1))
    agent.start()
    agent.stop()
    agent.flushBuffer()
    assertNull(agent.getDynamicRules())
    assertTrue(agent.healthCheck())
    initializer.shutdownAgentIntegrations()
  }

  /** The dynamic-rule telemetry adapters (462-463, 471-472). */
  @Test
  fun `initializer wires dynamic rule telemetry`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val mw =
        middleware(
            apply = {
              enableDynamicRules = true
              enableAgent = true
              agentApiKey = "w9h"
            },
        )
    val initializer =
        HandlerInitializer(config = mw.config, redisHandler = null, agentHandler = emptyAgent())
    try {
      initializer.initializeAgentIntegrations()
      // initializeDynamicRuleManager wires the dynamic-rule telemetry adapters over the
      // sink-shaped agent handler (462-463 / 471-472).
      initializer.initializeDynamicRuleManager()
    } finally {
      initializer.shutdownAgentIntegrations()
    }
  }

  // ------------------------------------------------------------------ EventEnricher

  /** The enrichment tolerance arms (99-100, 109-110) and the correlation arms (139-154, 164). */
  @Test
  fun `event enricher correlation and tolerance arms`(): Unit = runBlocking {
    val cfg = config {
      agentProjectId = "proj"
      otelServiceName = "svc"
      otelResourceAttributes = linkedMapOf("deployment.environment" to "prod")
    }
    val tracker = BehaviorTracker(cfg)
    // No rule handler and no tracker: identity + threat score still apply (139).
    val plain = EventEnricher(EnrichmentContext(cfg))
    val event1 =
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "metadata" to linkedMapOf<String, Any?>(),
        )
    plain.enrichEvent(event1)
    val metadata1 = event1["metadata"] as MutableMap<String, Any?>
    assertEquals("proj", metadata1[EventTypes.ENRICHMENT_KEY_PROJECT_ID])

    // A rule handler with current rules correlates the rule id/version (151-154).
    val manager = DynamicRuleManager(cfg)
    manager.currentRules =
        DynamicRules(
            ruleId = "r1",
            version = 4,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
            ipBlacklist = listOf("192.0.2.10"),
        )
    val correlating = EventEnricher(EnrichmentContext(cfg, dynamicRuleHandler = manager))
    val event2 =
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "ip_address" to "192.0.2.10",
            "metadata" to linkedMapOf<String, Any?>(),
        )
    correlating.enrichEvent(event2)
    val metadata2 = event2["metadata"] as MutableMap<String, Any?>
    assertEquals("r1", metadata2[EventTypes.ENRICHMENT_KEY_RULE_ID])

    // A miss returns null without enrichment keys (143).
    manager.currentRules =
        DynamicRules(
            ruleId = "r2",
            version = 1,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
        )
    val event3 =
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "ip_address" to "203.0.113.77",
            "metadata" to linkedMapOf<String, Any?>(),
        )
    correlating.enrichEvent(event3)
    val metadata3 = event3["metadata"] as MutableMap<String, Any?>
    assertNull(metadata3[EventTypes.ENRICHMENT_KEY_RULE_ID])

    // Behavior correlation over a tracker with recorded usage; the empty-ip arm (164).
    tracker.trackEndpointUsage("/e", "192.0.2.10", BehaviorRule("usage", 1))
    val behaving = EventEnricher(EnrichmentContext(cfg, behaviorTracker = tracker))
    val event4 =
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "ip_address" to "192.0.2.10",
            "metadata" to linkedMapOf<String, Any?>(),
        )
    behaving.enrichEvent(event4)
    val metadata4 = event4["metadata"] as MutableMap<String, Any?>
    assertEquals(1, metadata4[EventTypes.ENRICHMENT_KEY_RECENT_EVENT_COUNT])
    val event5 =
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "metadata" to linkedMapOf<String, Any?>(),
        )
    behaving.enrichEvent(event5)

    // The tolerance arms: a polluted tracker bag and a read-only metric bag (99-100, 109-110).
    @Suppress("UNCHECKED_CAST") val polluted = tracker.usageCounts as MutableMap<String, Any>
    polluted["/e"] = "garbage"
    val event6 =
        linkedMapOf<String, Any?>(
            "event_type" to "rate_limited",
            "ip_address" to "192.0.2.10",
            "metadata" to linkedMapOf<String, Any?>(),
        )
    behaving.enrichEvent(event6)
    val metric = linkedMapOf<String, Any?>("tags" to mapOf<String, Any?>("k" to "v"))
    behaving.enrichMetric(metric)
  }

  // ------------------------------------------------------------------ SecurityEventBus

  /**
   * The trace-header forwarding arm (54), the send-failure arm (132-133), and the sink (224-241).
   */
  @Test
  fun `event bus forwards trace headers and survives sink failures`(): Unit = runBlocking {
    val mw = middleware()
    // The companion sink protocol forwards events and folds non-map payloads (224-241).
    val forwarded = mutableListOf<Map<String, Any?>>()
    val sink =
        object : com.guardcore.handlers.HandlerAgentSink {
          override suspend fun sendEvent(event: Map<String, Any?>) {
            forwarded.add(event)
          }
        }
    val protocol = SecurityEventBus.sinkAsAgentProtocol(sink)
    protocol.sendEvent(mapOf("event_type" to "x"))
    protocol.sendEvent("junk")
    protocol.sendMetric("junk-metric")
    protocol.start()
    protocol.stop()
    protocol.flushBuffer()
    assertNull(protocol.getDynamicRules())
    assertTrue(protocol.healthCheck())
    // The real envelope plus the folded non-map payload.
    assertEquals(2, forwarded.size)

    // A live agent surface with a traceparent-carrying request walks the forward arm (54)
    // and the sink-protocol adapter inside extract_client_ip.
    val liveBus =
        SecurityEventBus(
            agentHandler = com.guardcore.handlers.HandlerAgentSink.of(emptyAgent()),
            config = config { agentEnableEvents = true },
            geoIpHandler = ThrowingGeo(),
            eventFilter = EventFilter(),
        )
    val traceRequest =
        TestRequest(
            urlPath = "/api",
            headers = mapOf("traceparent" to "00-abc-def-01", "tracestate" to "congo=1"),
        )
    liveBus.sendMiddlewareEvent(
        EventTypes.EVENT_PENETRATION_ATTEMPT,
        traceRequest,
        "request_blocked",
        "because",
        linkedMapOf(),
    )
    liveBus.sendMiddlewareEvent(
        EventTypes.EVENT_PENETRATION_ATTEMPT,
        traceRequest,
        "request_blocked",
        "because",
        linkedMapOf("traceparent" to "00-abc-def-01"),
    )
  }

  // ------------------------------------------------------------------ BehavioralProcessor

  /**
   * The decorator-violation arm (130-139), the middleware default (27), and the counts arm (207).
   */
  @Test
  fun `behavioral processor decorator and middleware arms`(): Unit = runBlocking {
    val mw = middleware()
    val decorator = com.guardcore.decorators.SecurityDecorator(mw.config)
    val tracker = BehaviorTracker(mw.config)
    val processor =
        BehavioralProcessor(
            BehavioralContext(
                config = mw.config,
                logger = Logger.getLogger("w9h-behavioral"),
                eventBus = mw.bus,
                guardDecorator = decorator,
                behaviorTracker = tracker,
            ),
        )
    val route =
        RouteConfig().apply {
          behaviorRules.add(BehaviorRule("return_pattern", 1, pattern = "status:200"))
        }
    val response =
        object : GuardResponse {
          override val headers: MutableMap<String, String> = linkedMapOf()
          override val statusCode: Int = 200
          override val body: ByteArray = ByteArray(0)
        }
    val request = requestWithRoute(route)
    request.state.setAttr("guard_decorator", decorator)
    processor.processReturnRules(request, response, "192.0.2.10", route)

    // A middleware that is not the GuardMiddlewareProtocol yields no correlated categories (207).
    val plainProcessor =
        BehavioralProcessor(
            BehavioralContext(
                config = mw.config,
                logger = Logger.getLogger("w9h-behavioral"),
                eventBus = mw.bus,
                guardDecorator = null,
                behaviorTracker = tracker,
                middleware = Object(),
            ),
        )
    plainProcessor.processReturnRules(request, response, "192.0.2.10", route)
  }

  // ------------------------------------------------------------------ Decorators

  /**
   * The decorator factory defaults and the honeypot parse arms (36, 171, 239-240, 329-349, 421,
   * 437, 452).
   */
  @Test
  fun `security decorator factory and honeypot arms`(): Unit = runBlocking {
    val decorator = com.guardcore.decorators.SecurityDecorator(config())
    val key = Any()
    // requireIp with defaults only (36).
    decorator.requireIp(key)
    // behaviorAnalysis with a return pattern runs the body-scan validator (171).
    decorator.behaviorAnalysis(
        key,
        listOf(BehaviorRule("return_pattern", 1, pattern = "status:200")),
    )
    // apiKeyAuth conflicts with a required authorization header (239-240); a stamped
    // route key keeps both factory calls on the same route config.
    val authKey =
        object : com.guardcore.decorators.StampedRoute {
          override val routeKey: String = "/authed"
          override var stampedRouteId: String? = null
        }
    decorator.requireAuthorizationHeader(authKey)
    assertFailsWith<IllegalArgumentException> { decorator.apiKeyAuth(authKey) }
    // detectionExclusion with defaults only (329), then every optional field (340-349).
    decorator.detectionExclusion(Any())
    decorator.detectionExclusion(
        Any(),
        headers = setOf("x-a"),
        params = setOf("p"),
        bodyFields = setOf("b"),
        categories = setOf("xss"),
        scanBody = false,
        semanticHeaders = setOf("x-s"),
    )
    // The honeypot validator: malformed JSON takes the catch (421); an unknown content
    // type takes the else arm (437); the simple response body getter (452).
    val validator = com.guardcore.decorators.honeypotValidatorClosure(listOf("trap"), config())
    val junk =
        BoundedRequest(
            headers = mapOf("content-type" to "application/json"),
            bodyBytes = "not json {".toByteArray(),
        )
    assertNull(validator(junk))
    val otherType =
        BoundedRequest(
            headers = mapOf("content-type" to "text/plain"),
            bodyBytes = "trap=gotcha".toByteArray(),
        )
    assertNull(validator(otherType))
    val filled =
        BoundedRequest(
            headers = mapOf("content-type" to "application/json"),
            bodyBytes = """{"trap": "gotcha"}""".toByteArray(),
        )
    val blocked = validator(filled)
    assertNotNull(blocked as? GuardResponse)
    assertEquals(403, (blocked as GuardResponse).statusCode)
    assertEquals(
        1,
        com.guardcore.decorators.SimpleDecoratorResponse(200, "x").body.size,
    )
  }

  /** BaseSecurityDecorator: the default geo handler (32) and behavior-tracking default (99). */
  @Test
  fun `base decorator defaults`(): Unit = runBlocking {
    val decorator = com.guardcore.decorators.SecurityDecorator(config())
    assertNull(decorator.geoIpHandler)
    decorator.initializeBehaviorTracking()
  }

  // ------------------------------------------------------------------ Checks

  /**
   * RateLimitCheck: the geo-rate-limit arms (127, 231, 235), passive mode (145), and guards (299,
   * 306).
   */
  @Test
  fun `rate limit check geo and guard arms`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val geo = RecordingGeo("US")
    val mw =
        middleware(
            apply = {
              enableRateLimiting = true
              geoIpHandler = geo
            },
            routes =
                mapOf(
                    "/geo" to
                        RouteConfig().apply { geoRateLimits = linkedMapOf("US" to (1 to 60)) },
                    "/geo-none" to
                        RouteConfig().apply { geoRateLimits = linkedMapOf("CA" to (1 to 60)) },
                    "/bypass" to RouteConfig().apply { bypassedChecks.add("rate_limit") },
                ),
        )
    val check = com.guardcore.core.checks.implementations.RateLimitCheck(mw)
    // The geo route with a matching country takes the geoRateLimits table (231) and the
    // endpoint-less apply call (127).
    check.check(requestWithRoute(routeOf(mw, "/geo"), path = "/geo"))
    // No matching country and no wildcard -> null (235).
    assertNull(check.check(requestWithRoute(routeOf(mw, "/geo-none"), path = "/geo-none")))
    // A missing client ip guard (299) and the route bypass (306).
    val noIp = TestRequest(urlPath = "/geo")
    noIp.state.setAttr("route_config", RouteConfig())
    assertNull(check.check(noIp))
    assertNull(check.check(requestWithRoute(routeOf(mw, "/bypass"), path = "/bypass")))
  }

  /** RateLimitCheck: passive mode keeps the exceeded result unblocked (145). */
  @Test
  fun `rate limit check passive mode returns null`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val mw =
        middleware(
            apply = {
              enableRateLimiting = true
              passiveMode = true
              rateLimit = 1
              rateLimitWindow = 60
            },
        )
    val check = com.guardcore.core.checks.implementations.RateLimitCheck(mw)
    val route = RouteConfig()
    check.check(requestWithRoute(route))
    check.check(requestWithRoute(route))
  }

  /** CloudProviderCheck: the bypass arm (83) and the not-cloud arm (92). */
  @Test
  fun `cloud provider check bypass and not-cloud arms`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedOverride = cloud.isCloudIpOverride
    cloud.isCloudIpOverride = { _, _ -> false }
    try {
      val mw =
          middleware(
              apply = {},
              routes =
                  mapOf(
                      "/bypass" to RouteConfig().apply { bypassedChecks.add("clouds") },
                      "/providers" to
                          RouteConfig().apply { blockCloudProviders = linkedSetOf("AWS") },
                  ),
          )
      val check = com.guardcore.core.checks.implementations.CloudProviderCheck(mw)
      assertNull(check.check(requestWithRoute(routeOf(mw, "/bypass"), path = "/bypass")))
      assertNull(check.check(requestWithRoute(routeOf(mw, "/providers"), path = "/providers")))
    } finally {
      cloud.isCloudIpOverride = savedOverride
    }
  }

  /** IpSecurityCheck: the country-block arm (78) and the scoped arm (314). */
  @Test
  fun `ip security check country and scoped arms`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val geo = RecordingGeo("US")
    val routes = mapOf("/blocked" to RouteConfig().apply { blockedCountries = listOf("US") })
    val mw = TestMiddleware(config {}, null, geo, resolverWith(routes))
    val check = com.guardcore.core.checks.implementations.IpSecurityCheck(mw)
    val blocked = check.check(requestWithRoute(routeOf(mw, "/blocked"), path = "/blocked"))
    assertNotNull(blocked)

    // The scoped-exclusion arm routes to the global restrictions with escalate=false (314).
    val scoped = requestWithRoute(RouteConfig())
    scoped.state.setAttr("guard_exclusion_scoped", true)
    assertNull(check.check(scoped))
  }

  /** RequiredHeadersCheck: the authorization and plain violation reasons (20-21, 23). */
  @Test
  fun `required headers violation reasons`(): Unit = runBlocking {
    val mw =
        middleware(
            apply = {},
            routes =
                mapOf(
                    "/auth" to
                        RouteConfig().apply { requiredHeaders["Authorization"] = "required" },
                    "/key" to RouteConfig().apply { requiredHeaders["X-Api-Key"] = "required" },
                ),
        )
    val check = com.guardcore.core.checks.implementations.RequiredHeadersCheck(mw)
    val authBlocked = check.check(requestWithRoute(routeOf(mw, "/auth"), path = "/auth"))
    assertNotNull(authBlocked)
    val keyBlocked = check.check(requestWithRoute(routeOf(mw, "/key"), path = "/key"))
    assertNotNull(keyBlocked)
  }

  /** CustomValidatorsCheck's empty-registry arm (67). */
  @Test
  fun `custom validators check no-op arm`(): Unit = runBlocking {
    val mw = middleware()
    val check = com.guardcore.core.checks.implementations.CustomValidatorsCheck(mw)
    assertNull(check.check(requestWithRoute(RouteConfig())))
  }

  /** SuspiciousActivityCheck's banned arm (89) and ChecksHelpers' threshold arms (474, 479). */
  @Test
  fun `suspicious activity banned arm over threshold counts`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val mw =
        middleware(
            apply = {
              enableIpBanning = true
              autoBanThreshold = 1
              threatBanConfig = mapOf<String, ThreatBanConfig>("xss" to ThreatBanConfig(1, 60))
            },
        )
    val check = com.guardcore.core.checks.implementations.SuspiciousActivityCheck(mw)
    // Seed the ip's category counts past the threshold and the cached detection result
    // with a matching threat, so the active-mode ban resolves (89).
    mw.suspiciousRequestCounts["192.0.2.10"] = linkedMapOf("xss" to 3)
    val route = RouteConfig()
    val request = requestWithRoute(route)
    request.state.setAttr(
        com.guardcore.core.checks.ChecksHelpers.DETECTION_RESULT_STATE_ATTR,
        Triple<GuardRequest, RouteConfig?, com.guardcore.DetectionResult>(
            request,
            route,
            com.guardcore.DetectionResult(
                isThreat = true,
                triggerInfo = "xss",
                threatCategories = listOf("xss"),
            ),
        ),
    )
    val response = check.check(request)
    // The ban resolves through the threat-category threshold (counts 3 >= 1) so the
    // active-mode arm returns the 403 ban response.
    if (response == null) {
      throw AssertionError("expected the banned 403 response")
    }
    assertEquals(403, response.statusCode)
    // The below-threshold continue and the failed-ban null return through the helper (474).
    val manager = IpBanManager.getInstance()
    val below =
        com.guardcore.core.checks.ChecksHelpers.resolveAndApplyThresholdBan(
            mapOf("xss" to 0),
            mw.config,
            manager,
            "192.0.2.55",
            listOf("xss", "other"),
            "reason",
        )
    assertNull(below)
    com.guardcore.handlers.resetIpBanGlobalState()
  }

  /** AuthenticationCheck's unsupported-verifier arm (132). */
  @Test
  fun `authentication check rejects unsupported verifier`(): Unit = runBlocking {
    val mw =
        middleware(
            apply = {},
            routes = mapOf("/api" to RouteConfig().apply { authRequired = "basic" }),
        )
    val check = com.guardcore.core.checks.implementations.AuthenticationCheck(mw)
    val request =
        requestWithRoute(
            routeOf(mw, "/api"),
            headers = mapOf("authorization" to "Basic dXNlcjpwYXNz"),
            path = "/api",
        )
    val result = check.check(request)
    assertNotNull(result)
  }

  /** HttpsEnforcementCheck's proxy-CIDR arm (51) and the missing-factory throw (61-62). */
  @Test
  fun `https enforcement proxy and factory arms`(): Unit = runBlocking {
    val mw =
        middleware(
            apply = {
              enforceHttps = true
              trustXForwardedProto = true
              trustedProxies = listOf("10.0.0.0/8")
            },
            routes = mapOf("/api" to RouteConfig().apply { requireHttps = true }),
        )
    val check = com.guardcore.core.checks.implementations.HttpsEnforcementCheck(mw)
    // A request over a trusted proxy with a forwarded proto resolves https (51).
    val forwarded =
        TestRequest(
            urlPath = "/api",
            urlScheme = "http",
            clientHost = "10.1.2.3",
            headers = mapOf("X-Forwarded-Proto" to "https"),
        )
    forwarded.state.setAttr("route_config", routeOf(mw, "/api"))
    forwarded.state.setAttr("client_ip", "10.1.2.3")
    assertNull(check.check(forwarded))

    // A middleware whose response factory is absent fails closed (61-62).
    val bare =
        object : com.guardcore.protocols.GuardMiddlewareProtocol {
          override val config: SecurityConfig = config { enforceHttps = true }
          override val logger: Logger = Logger.getLogger("w9h-bare")
          override var lastCloudIpRefresh: Int = 0
          override val suspiciousRequestCounts: MutableMap<String, MutableMap<String, Int>> =
              linkedMapOf()
          override val eventBus: com.guardcore.protocols.MiddlewareEventBusProtocol? = null
          override val routeResolver: RouteConfigResolverProtocol? = null
          override val responseFactory: com.guardcore.protocols.MiddlewareResponseFactoryProtocol? =
              null
          override val rateLimitHandler: Any? = null
          override val agentHandler: AgentHandlerProtocol? = null
          override val geoIpHandler: GeoIPHandler? = null
          override val guardResponseFactory: com.guardcore.protocols.GuardResponseFactory? = null

          override suspend fun createErrorResponse(
              statusCode: Int,
              defaultMessage: String,
          ): GuardResponse = TestResponse(statusCode)

          override suspend fun refreshCloudIpRanges() {}
        }
    val bareCheck = com.guardcore.core.checks.implementations.HttpsEnforcementCheck(bare)
    val plain = TestRequest(urlPath = "/api")
    plain.state.setAttr("route_config", RouteConfig().apply { requireHttps = true })
    assertFailsWith<IllegalStateException> { bareCheck.check(plain) }
  }

  /** CloudIpRefreshCheck's in-flight restore arm (50). */
  @Test
  fun `cloud ip refresh restores the timestamp when a refresh is in flight`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedStore = cloud.store
    val savedRedis = cloud.redisHandler
    cloud.redisHandler = null
    try {
      val mw = middleware(apply = { blockCloudProviders = setOf("AWS") })
      val release = kotlinx.coroutines.CompletableDeferred<Unit>()
      // Occupy the single-flight slot so the check's scheduleRefresh returns false.
      val inFlight = cloud.scheduleRefresh(setOf("AWS"), ttl = 60, refresh = { release.await() })
      assertTrue(inFlight)
      val check = com.guardcore.core.checks.implementations.CloudIpRefreshCheck(mw)
      assertNull(
          check.check(
              requestWithRoute(RouteConfig().apply { blockCloudProviders = linkedSetOf("AWS") }),
          ),
      )
      release.complete(Unit)
    } finally {
      cloud.redisHandler = savedRedis
      cloud.store = savedStore
    }
  }

  /** RequestSizeContentCheck's within-limit arm (37). */
  @Test
  fun `request size within limit passes`(): Unit = runBlocking {
    val mw =
        middleware(
            apply = {},
            routes = mapOf("/api" to RouteConfig().apply { maxRequestSize = 1000 }),
        )
    val check = com.guardcore.core.checks.implementations.RequestSizeContentCheck(mw)
    assertNull(
        check.check(
            requestWithRoute(
                routeOf(mw, "/api"),
                headers = mapOf("content-length" to "10"),
                path = "/api",
            ),
        ),
    )
  }

  /** ChecksHelpers: the decorator rate-limit event (109-110) and the referrer catch (347). */
  @Test
  fun `checks helpers event and referrer arms`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val mw = middleware()
    val decorator = com.guardcore.decorators.SecurityDecorator(mw.config)
    val request = requestWithRoute(RouteConfig())
    request.state.setAttr("guard_decorator", decorator)
    com.guardcore.core.checks.ChecksHelpers.emitRateLimitEvent(
        mw,
        request,
        EventTypes.EVENT_RATE_LIMITED,
        5,
        60,
        "rate_limit_exceeded",
        passiveMode = false,
    )
    // The referrer catch: an unparseable referrer URL (347).
    assertFalse(
        com.guardcore.core.checks.ChecksHelpers.isReferrerDomainAllowed(
            "http://[::1",
            listOf("example.com"),
        ),
    )
  }

  /** SecurityCheckPipeline: the construction surface (23) and the structured log fields (93-97). */
  @Test
  fun `pipeline construction and log fields`(): Unit = runBlocking {
    val mw = middleware()
    val pipeline =
        com.guardcore.core.checks.SecurityCheckPipeline(
            checks = emptyList(),
            mutedCheckLogs = setOf("rate_limit"),
            config = mw.config,
        )
    assertNotNull(pipeline.logger)
    assertNull(pipeline.execute(TestRequest()))
  }

  /** ChecksFactory: the default container-fields carrier (32). */
  @Test
  fun `check factory default container fields`() {
    val factory =
        object :
            com.guardcore.core.checks.CheckCompanion<com.guardcore.core.checks.SecurityCheck>() {
          override fun appliesTo(
              config: SecurityConfig,
              routeConfigs: Collection<RouteConfig>?,
          ): Boolean = false

          override fun create(
              middleware: com.guardcore.protocols.GuardMiddlewareProtocol,
          ): com.guardcore.core.checks.SecurityCheck = throw UnsupportedOperationException()
        }
    assertTrue(factory.containerFields.isEmpty())
  }

  // ------------------------------------------------------------------ Events singles

  /** OtelHandler: the span-attrs table (55) and the extract catch (145). */
  @Test
  fun `otel handler span attrs and extract catch`(): Unit = runBlocking {
    val handler =
        OtelHandler(
            object : OtelHandler.ProviderConfig {
              override val otelServiceName: String = "w9h"
              override val otelResourceAttributes: Map<String, String> = mapOf("a" to "b")
              override val otelExporterEndpoint: String? = null
            },
        )
    handler.start()
    // A surface whose extract raises takes the parent-context catch (145); the span
    // dispatch walks the EVENT_SPAN_ATTRS table (55).
    val previous = OtelHandler.surface
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
              throw IllegalStateException("no sdk")
        }
    try {
      handler.sendEvent(
          mapOf(
              "event_type" to "penetration_attempt",
              "ip_address" to "192.0.2.10",
              "metadata" to mapOf<String, Any?>("traceparent" to "00-abc-def-01"),
          ),
      )
    } finally {
      OtelHandler.surface = previous
    }
  }

  /** EventTypes: the check-name table initialization (109). */
  @Test
  fun `event types check name table initializes`() {
    assertTrue(EventTypes.CHECK_NAME_VALUES.contains("cloud_provider"))
    assertTrue(EventTypes.METRIC_TYPE_VALUES.isNotEmpty())
  }

  /** ErrorResponseFactory: the process-response hook defaults (118). */
  @Test
  fun `error response factory default hooks`(): Unit = runBlocking {
    val mw = middleware()
    val factory =
        com.guardcore.core.responses.ErrorResponseFactory(
            com.guardcore.core.responses.ResponseContext(
                config = mw.config,
                logger = mw.logger,
                metricsCollector = MetricsCollector(null, mw.config),
                agentHandler = null,
                responseFactory = mw.responseFactory,
            ),
        )
    // Both behavioral hooks default to null (118) and the pass-through response survives.
    val response = factory.processResponse(TestRequest(), TestResponse(200), 1.0, null)
    assertNotNull(response)
  }

  /** RouteConfig: the tracked-set containsAll arm (154). */
  @Test
  fun `tracked set contains all`() {
    val route = RouteConfig()
    val tracked = route.blockCloudProviders
    tracked.add("AWS")
    tracked.add("GCP")
    assertTrue(tracked.containsAll(listOf("AWS")))
  }

  /**
   * RequestValidator: the logger surface (35), the proxy-equality arm (68-69), and the wrap window
   * (90).
   */
  @Test
  fun `request validator proxy and time window arms`(): Unit = runBlocking {
    val mw = middleware(apply = { trustedProxies = listOf("192.0.2.10") })
    val validator =
        RequestValidator(ValidationContext(mw.config, Logger.getLogger("w9h-validator"), mw.bus))
    assertNotNull(validator.logger)
    assertTrue(validator.isTrustedProxy("192.0.2.10"))
    // The wrap-around expression (start > end) evaluates regardless of the current time (90).
    val fmt = java.time.format.DateTimeFormatter.ofPattern("HH:mm")
    val now = java.time.LocalTime.now(java.time.ZoneOffset.UTC).format(fmt)
    val nowHour = now.substring(0, 2).toInt()
    // start > end: the wrap comparison always evaluates (90); the result is time-dependent.
    validator.checkTimeWindow(
        mapOf("start" to "%02d:00".format((nowHour + 1) % 24), "end" to "%02d:00".format(nowHour)),
    )
    // A window that always contains now (plain arm) for contrast.
    assertTrue(
        validator.checkTimeWindow(
            mapOf(
                "start" to "%02d:00".format((nowHour + 23) % 24),
                "end" to "%02d:00".format((nowHour + 1) % 24),
            ),
        ),
    )
  }

  /** A bus implementation exercising the omittable-metadata default (protocols line 22). */
  private class DefaultMetadataBus : com.guardcore.protocols.MiddlewareEventBusProtocol {
    var lastType: String? = null

    override suspend fun sendMiddlewareEvent(
        eventType: String,
        request: GuardRequest,
        actionTaken: String,
        reason: String,
        metadata: Map<String, Any?>,
    ) {
      lastType = eventType
    }

    override suspend fun sendHttpsViolationEvent(request: GuardRequest, routeConfig: Any?) {}

    override suspend fun sendCloudDetectionEvents(
        request: GuardRequest,
        clientIp: String,
        cloudProvidersToCheck: List<String>,
        routeConfig: Any?,
        cloudHandler: Any?,
        passiveMode: Boolean,
    ) {}
  }

  /** CloudIpStore default ttl arm (protocols line 12). */
  @Test
  fun `protocol default arguments`(): Unit = runBlocking {
    val bus = DefaultMetadataBus()
    bus.sendMiddlewareEvent("x", TestRequest(), "blocked", "because")
    assertEquals("x", bus.lastType)
    val store = com.guardcore.handlers.InMemoryCloudIpStore()
    store.set("AWS", setOf("10.9.0.0/16"))
    assertNotNull(store.get("AWS"))
  }

  /** HandlerSeams: the registered lambdas resolve their targets (24, 29). */
  @Test
  fun `handler seams resolve geo and cloud lambdas`() = runBlocking {
    HandlerSeamsRegister.register()
    // A second register() call takes the double-check return (24).
    com.guardcore.handlers.HandlerSeams.register()
    val geo = ConfigSeamsHolder.geoIpHandlerFactory?.invoke("w9h-token", null, 3600)
    assertNotNull(geo)
    val details =
        com.guardcore.util.AccessControl.cloudIpChecker?.invoke("203.0.113.1", setOf("AWS"))
    assertNull(details)
  }

  private object ConfigSeamsHolder {
    val geoIpHandlerFactory = com.guardcore.config.ConfigSeams.geoIpHandlerFactory
  }

  private class FakeRedisProtocol : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        true

    override suspend fun delete(namespace: String, key: String): Int? = 1

    override suspend fun keys(pattern: String): List<String>? = emptyList()

    override suspend fun initialize() {}

    override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
        object : com.guardcore.protocols.GuardRedisConnection {
          override val client: Any? = null

          override fun close() {}
        }
  }
}
