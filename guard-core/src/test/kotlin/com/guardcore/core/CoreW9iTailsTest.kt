package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.behavioral.BehavioralContext
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.OtelHandler
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.DynamicRules
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.protocols.RequestState
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

/**
 * W9i batch 7 (completing): the final core tails to the family 100 percent line gate - the
 * behavioral return-pattern violation through the decorator and the middleware counts arm, the
 * lazy-init geo failure arm and the merged dynamic-rule telemetry adapter, the event-bus send
 * failure and the sink protocol adapter, the otel span-attrs table and the throwing extraction
 * surface, the composite dynamic-rules short circuit, the referrer parse catch, and the small
 * check singles.
 */
class CoreW9iTailsTest {
  private fun config(apply: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      coreTestConfig(apply)

  private fun middleware(
      apply: SecurityConfigBuilder.() -> Unit = {},
  ): TestMiddleware = TestMiddleware(config(apply))

  private fun requestWithRoute(route: RouteConfig, path: String = "/api"): GuardRequest =
      TestRequest(urlPath = path).apply { state.setAttr("route_config", route) }

  private class NullRedisConnection : GuardRedisConnection {
    override val client: Any? = null

    override fun close() {}
  }

  private class NullRedis : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        true

    override suspend fun delete(namespace: String, key: String): Int? = 1

    override suspend fun keys(pattern: String): List<String>? = null

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection = NullRedisConnection()
  }

  private class ThrowingGeo : com.guardcore.protocols.GeoIPHandler {
    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {
      throw IllegalStateException("w9i geo redis down")
    }

    override suspend fun initializeAgent(agentHandler: com.guardcore.protocols.AgentHandlerProtocol) {}

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  // ------------------------------------------------------------------ BehavioralProcessor

  /**
   * processReturnRules' threshold-crossing decorator arm (130-139): two matching responses push
   * the tracked timestamps past the threshold. The correlated-categories middleware arm (207)
   * runs processGlobalReturnRules with a middleware that is not the GuardMiddlewareProtocol.
   */
  @Test
  fun `behavioral return rules cross the threshold through the decorator`(): Unit = runBlocking {
    val mw = middleware()
    val decorator = com.guardcore.decorators.SecurityDecorator(mw.config)
    val tracker = BehaviorTracker(mw.config)
    val processor =
        BehavioralProcessor(
            BehavioralContext(
                config = mw.config,
                logger = Logger.getLogger("w9i-behavioral"),
                eventBus = mw.bus,
                guardDecorator = decorator,
                behaviorTracker = tracker,
            ),
        )
    val route =
        RouteConfig().apply {
          behaviorRules.add(BehaviorRule("return_pattern", 1, pattern = "status:200"))
        }
    val response = TestResponse(200, ByteArray(0))
    val request = requestWithRoute(route)

    // The first drive seeds the tracker; the second crosses the threshold and
    // dispatches the decorator violation.
    processor.processReturnRules(request, response, "192.0.2.10", route)
    processor.processReturnRules(request, response, "192.0.2.10", route)

    // The global-return path with a middleware surface that is not the protocol:
    // the correlated-categories lookup yields no categories (207).
    val plainProcessor =
        BehavioralProcessor(
            BehavioralContext(
                config = mw.config,
                logger = Logger.getLogger("w9i-behavioral"),
                eventBus = mw.bus,
                guardDecorator = null,
                behaviorTracker = tracker,
                middleware = Object(),
            ),
        )
    plainProcessor.processGlobalReturnRules(
        request,
        response,
        "192.0.2.10",
        listOf(BehaviorRule("return_pattern", 5, pattern = "status:200")),
    )
  }

  // ------------------------------------------------------------------ HandlerInitializer

  /** runLazyInit's geo failure arm (206-207): a handler whose initializeRedis throws. */
  @Test
  fun `lazy init logs and swallows a failing geo handler`(): Unit = runBlocking {
    val initializer = HandlerInitializer(config(), geoIpHandler = ThrowingGeo())
    initializer.runLazyInit()
  }

  /**
   * initializeDynamicRuleManager wires the merged telemetry adapter: a composite member that
   * returns dynamic rules drives the update loop's rule-received event through the adapter's
   * sendEvent body (424-434).
   */
  @Test
  fun `dynamic rule telemetry adapter forwards events`(): Unit = runBlocking {
    val rules =
        DynamicRules(
            ruleId = "w9i-rules",
            version = 1,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
        )
    var events = 0
    val rulesMember =
        object : com.guardcore.core.events.AgentTelemetryMember {
          override suspend fun sendEvent(event: Map<String, Any?>) {}

          override suspend fun getDynamicRules(): Any? = rules
        }
    val countingMember =
        object : com.guardcore.core.events.AgentTelemetryMember {
          override suspend fun sendEvent(event: Map<String, Any?>) {
            events += 1
          }
        }
    val composite = CompositeAgentHandler(listOf(rulesMember, countingMember))
    val builder = SecurityConfigBuilder()
    builder.validateFields = false
    builder.enableDynamicRules = true
    builder.enableAgent = true
    builder.agentApiKey = "w9i"
    builder.dynamicRuleInterval = 1
    val initializer =
        HandlerInitializer(
            builder.build(),
            agentHandler =
                object : HandlerAgentSink {
                  override suspend fun sendEvent(event: Map<String, Any?>) {}
                },
        )
    initializer.compositeHandler = composite
    initializer.initializeDynamicRuleManager()
    // The update loop's first pass fires the rule-received event through the adapter.
    delay(1500)
    assertTrue(events >= 1, "expected the adapter to forward the rule event")
  }

  // ------------------------------------------------------------------ SecurityEventBus

  /** The send-failure catch (132-133) over a throwing agent sink and the sink protocol
   * adapter's initializeRedis body (224). */
  @Test
  fun `event bus survives a failing agent and adapts the sink`(): Unit = runBlocking {
    val mw =
        middleware(apply = { agentEnableEvents = true; enableAgent = true; agentApiKey = "w9i" })
    val bus =
        SecurityEventBus(
            agentHandler =
                object : HandlerAgentSink {
                  override suspend fun sendEvent(event: Map<String, Any?>) {
                    throw IllegalStateException("w9i agent down")
                  }
                },
            config = mw.config,
        )
    bus.sendMiddlewareEvent(
        EventTypes.EVENT_PENETRATION_ATTEMPT,
        TestRequest(urlPath = "/api"),
        "request_blocked",
        "because",
        linkedMapOf(),
    )

    // The sink-shaped agent handler adapts to the AgentHandlerProtocol; its
    // initializeRedis member is the protocol-required no-op (224).
    val protocolAdapter =
        SecurityEventBus.sinkAsAgentProtocol(
            object : HandlerAgentSink {
              override suspend fun sendEvent(event: Map<String, Any?>) {}
            },
        )
    protocolAdapter.initializeRedis(NullRedis())
  }

  // ------------------------------------------------------------------ OtelHandler

  /** The span-attrs table (55) and the extraction-surface failure arm (145). */
  @Test
  fun `otel handler span attrs and a throwing surface`(): Unit = runBlocking {
    assertTrue(OtelHandler.EVENT_SPAN_ATTRS.isNotEmpty())
    val mw =
        middleware(apply = { agentEnableEvents = true; enableAgent = true; agentApiKey = "w9i" })
    val previousSurface = OtelHandler.surface
    OtelHandler.surface =
        object : OtelHandler.OtelSurface {
          override fun startSpan(name: String, attributes: Map<String, Any?>, parentContext: Any?) {}

          override fun recordHistogram(name: String, value: Double, attributes: Map<String, Any?>) {}

          override fun recordCounterAdd(name: String, value: Double, attributes: Map<String, Any?>) {}

          override fun extractTraceContext(carrier: Map<String, String>): Any? {
            throw IllegalStateException("w9i otel surface down")
          }
        }
    try {
      val bus =
          SecurityEventBus(
              agentHandler =
                  object : HandlerAgentSink {
                    override suspend fun sendEvent(event: Map<String, Any?>) {}
                  },
              config = mw.config,
          )
      bus.sendMiddlewareEvent(
          EventTypes.EVENT_PENETRATION_ATTEMPT,
          TestRequest(urlPath = "/api"),
          "request_blocked",
          "because",
          linkedMapOf("traceparent" to "00-abc-def-01"),
      )
    } finally {
      OtelHandler.surface = previousSurface
    }
  }

  // ------------------------------------------------------------------ CompositeAgentHandler

  /** getDynamicRules' short circuit over a null member followed by a rules member (150). */
  @Test
  fun `composite dynamic rules short circuit over a null member`(): Unit = runBlocking {
    val composite =
        CompositeAgentHandler(
            listOf(
                object : com.guardcore.core.events.AgentTelemetryMember {
                  override suspend fun sendEvent(event: Map<String, Any?>) {}
                },
                object : com.guardcore.core.events.AgentTelemetryMember {
                  override suspend fun sendEvent(event: Map<String, Any?>) {}

                  override suspend fun getDynamicRules(): Any? = "w9i-rules"
                },
            ),
        )
    assertEquals("w9i-rules", composite.getDynamicRules())
  }

  // ------------------------------------------------------------------ Checks helpers

  /** isReferrerDomainAllowed's urlsplit catch (347) and resolveAndApplyThresholdBan's
   * not-applied arm (479). */
  @Test
  fun `referrer parse catch and threshold ban not applied`(): Unit = runBlocking {
    assertFalse(
        com.guardcore.core.checks.ChecksHelpers.isReferrerDomainAllowed(
            "http://[::1",
            listOf("allowed.test"),
        ),
    )

    com.guardcore.handlers.IpBanManager.resetInstance()
    val ipBanManager = com.guardcore.handlers.IpBanManager.getInstance()
    ipBanManager.banIpOverride = { _, _, _ -> false }
    try {
      val banned =
          com.guardcore.core.checks.ChecksHelpers.resolveAndApplyThresholdBan(
              ipCounts = mapOf("xss" to 3),
              config =
                  config {
                    enableIpBanning = true
                    threatBanConfig = mapOf("xss" to com.guardcore.config.ThreatBanConfig(1, 60))
                  },
              ipBanManager = ipBanManager,
              clientIp = "192.0.2.10",
              threatCategories = listOf("xss"),
              reason = "w9i",
          )
      assertNull(banned)
    } finally {
      ipBanManager.banIpOverride = null
    }
  }

  // ------------------------------------------------------------------ Check singles

  /** RequiredHeadersCheck's non-auth violation classification (23). */
  @Test
  fun `required headers classifies an advanced header violation`(): Unit = runBlocking {
    val mw = middleware()
    val route =
        RouteConfig().apply { requiredHeaders.put("x-tenant-id", "tenant-1") }
    val check = com.guardcore.core.checks.implementations.RequiredHeadersCheck(mw)
    val blocked = check.check(requestWithRoute(route))
    assertNotNull(blocked)
  }

  /** CustomValidatorsCheck's all-pass arm (67). */
  @Test
  fun `custom validators pass through when every validator holds`(): Unit = runBlocking {
    val mw = middleware()
    val route =
        RouteConfig().apply {
          customValidators.add({ _ -> true })
        }
    val check = com.guardcore.core.checks.implementations.CustomValidatorsCheck(mw)
    assertNull(check.check(requestWithRoute(route)))
  }

  /** RateLimitCheck's passive-mode arm (145): an exceeded verdict yields no block. */
  @Test
  fun `rate limit check yields in passive mode`(): Unit = runBlocking {
    val mw =
        middleware(
            apply = {
              passiveMode = true
              enableRateLimiting = true
              rateLimit = 1
              rateLimitWindow = 60
            },
        )
    val route = RouteConfig().apply { rateLimit = 1; rateLimitWindow = 60 }
    val check = com.guardcore.core.checks.implementations.RateLimitCheck(mw)
    assertNull(check.check(requestWithRoute(route)))
    // The second request exceeds the limit; passive mode logs it and yields (145).
    assertNull(check.check(requestWithRoute(route)))
  }

  // ------------------------------------------------------------------ Protocols

  /** The interface default-arg synthetics: CloudIpStore.set without ttl (12) and
   * sendMiddlewareEvent without metadata (22), invoked through the protocol types. */
  @Test
  fun `protocol default arguments invoke the interface synthetics`(): Unit = runBlocking {
    var stored: Pair<String, Set<String>>? = null
    val store: com.guardcore.protocols.CloudIpStoreProtocol =
        object : com.guardcore.protocols.CloudIpStoreProtocol {
          override suspend fun get(provider: String): Set<String>? =
              stored?.takeIf { it.first == provider }?.second

          override suspend fun set(provider: String, ranges: Set<String>, ttl: Int?) {
            stored = provider to ranges
          }

          override suspend fun clear() {
            stored = null
          }
        }
    store.set("aws", setOf("203.0.113.0/24"))
    assertEquals(setOf("203.0.113.0/24"), store.get("aws"))

    val bus: com.guardcore.protocols.MiddlewareEventBusProtocol = RecordingBus()
    bus.sendMiddlewareEvent(
        EventTypes.EVENT_PENETRATION_ATTEMPT,
        TestRequest(urlPath = "/api"),
        "request_blocked",
        "because",
    )
  }
}
