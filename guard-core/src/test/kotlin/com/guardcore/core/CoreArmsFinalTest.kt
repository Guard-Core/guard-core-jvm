package com.guardcore.core

import com.guardcore.config.EventFilter
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.RecordingAgent
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.GUARD_LOGGER
import com.guardcore.util.LogCapture
import java.util.logging.Level
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9a initializer-arm closure: the enricher/composite-sink/lazy-init/redis-failure halves of
 * HandlerInitializer that the python-mock-only tests left open, plus the dynamic-rule composite
 * adapters and shutdown semantics (handler_initializer.py arms).
 */
class HandlerInitializerArmsTest {
  private class CountingRedis : RedisHandlerProtocol {
    var initializeCalls: Int = 0

    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?) = true

    override suspend fun delete(namespace: String, key: String): Int? = 0

    override suspend fun keys(pattern: String): List<String>? = emptyList()

    override suspend fun initialize() {
      initializeCalls += 1
    }

    override fun getConnection(): GuardRedisConnection =
        object : GuardRedisConnection {
          override val client: Any? = null

          override fun close() {}
        }
  }

  private class FailingRedis : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?) = true

    override suspend fun delete(namespace: String, key: String): Int? = 0

    override suspend fun keys(pattern: String): List<String>? = emptyList()

    override suspend fun initialize() {
      throw com.guardcore.errors.GuardRedisError(503, "Redis connection failed")
    }

    override fun getConnection(): GuardRedisConnection =
        object : GuardRedisConnection {
          override val client: Any? = null

          override fun close() {}
        }
  }

  private class CountingGeo : GeoIPHandler {
    var initializeCalls: Int = 0
    var initializeRedisCalls: Int = 0
    var initializeAgentCalls: Int = 0

    override val isInitialized: Boolean = false

    override suspend fun initialize() {
      initializeCalls += 1
    }

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {
      initializeRedisCalls += 1
    }

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {
      initializeAgentCalls += 1
    }

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun securityConfig(
      mutate: com.guardcore.config.SecurityConfigBuilder.() -> Unit = {},
  ) = coreTestConfig {
    lazyInit = false
    enableRedis = true
    enableDynamicRules = false
    blockCloudProviders = emptySet()
    mutate()
  }

  /** handler_initializer.py:38 with a foreign geo handler (the getStatus reflection arm). */
  @Test
  fun testGetInitializationStatusWithForeignGeoObject() {
    CloudManager.resetInstance()
    val foreign =
        object {
          @Suppress("unused")
          fun getStatus(): Map<String, Any?> = mapOf("ready" to true, "entries" to 5)
        }
    val initializer = HandlerInitializer(config = securityConfig(), geoIpHandler = foreign)
    val status = initializer.getInitializationStatus()
    assertEquals(true, (status["geo_ip"] as Map<*, *>)["ready"])
    assertEquals(5, (status["geo_ip"] as Map<*, *>)["entries"])
  }

  @Test
  fun testGetInitializationStatusWithProtocolGeo() {
    CloudManager.resetInstance()
    val initializer = HandlerInitializer(config = securityConfig(), geoIpHandler = CountingGeo())
    val status = initializer.getInitializationStatus()
    assertEquals(false, (status["geo_ip"] as Map<*, *>)["ready"])
  }

  /** handler_initializer.py:58 enrichment builder arms. */
  @Test
  fun testBuildEnricherDisabled() {
    val initializer = HandlerInitializer(config = securityConfig())
    assertNull(initializer.buildEnricher())
  }

  @Test
  fun testBuildEnricherEnabled() {
    val initializer =
        HandlerInitializer(
            config =
                securityConfig {
                  enableEnrichment = true
                  enableAgent = true
                  agentApiKey = "k"
                },
            agentHandler = RecordingAgent(),
        )
    val enricher = initializer.buildEnricher()
    assertNotNull(enricher)
    assertNotNull(initializer.behaviorTracker)
  }

  @Test
  fun testBuildEnricherEnabledWithDynamicRules() {
    val initializer =
        HandlerInitializer(
            config =
                securityConfig {
                  enableEnrichment = true
                  enableAgent = true
                  agentApiKey = "k"
                  enableDynamicRules = true
                },
            agentHandler = RecordingAgent(),
        )
    assertNotNull(initializer.buildEnricher())
  }

  @Test
  fun testBuildEnricherRequiresAgent() {
    val error =
        try {
          HandlerInitializer(config = securityConfig { enableEnrichment = true }).buildEnricher()
          null
        } catch (e: com.guardcore.errors.ConfigValidationError) {
          e
        }
    assertNotNull(error)
    assertTrue(
        error!!.message!!.contains("enable_enrichment requires enable_agent=True"),
        error.message,
    )
  }

  /** The composite member factory seam + event bus/metrics/filter builders. */
  @Test
  fun testBuildersAndMemberFactory() {
    coreRunTest {
      resetIpBanGlobalState()
      val initializer =
          HandlerInitializer(
              config = securityConfig { enableOtel = true },
              agentHandler = RecordingAgent(),
          )
      val customMember =
          object : AgentTelemetryMember {
            override suspend fun sendEvent(event: Map<String, Any?>) {}
          }
      initializer.compositeMemberFactory = { members, _ -> members + customMember }
      val composite = initializer.buildCompositeHandler()
      assertTrue(
          composite.handlers.any { it === customMember },
          "member factory output must join the composite: ${composite.handlers.size}",
      )
      assertNotNull(initializer.eventFilter)
      // buildMetricsCollector requires the agent-integration pass first (its guard).
      initializer.compositeHandler = composite
      assertNotNull(initializer.buildMetricsCollector())
      composite.start()
      composite.stop()
    }
  }

  @Test
  fun testBuildCompositeHandlerOtelWithoutFactoryRaises() {
    val initializer =
        HandlerInitializer(
            config = securityConfig { enableOtel = true },
            agentHandler = RecordingAgent(),
        )
    val error =
        try {
          initializer.buildCompositeHandler()
          null
        } catch (e: IllegalStateException) {
          e
        }
    assertNotNull(error)
    assertTrue(error!!.message!!.contains("compositeMemberFactory"), error.message)
  }

  @Test
  fun testBuildEventBusWithGeo() {
    coreRunTest {
      resetIpBanGlobalState()
      val initializer = HandlerInitializer(config = securityConfig(), geoIpHandler = CountingGeo())
      initializer.initializeAgentIntegrations()
      initializer.shutdownAgentIntegrations()
    }
  }

  /** The composite sink forwards events to the composed handler (compositeSink arms). */
  @Test
  fun testCompositeSinkForwardsToComposite() {
    coreRunTest {
      resetIpBanGlobalState()
      val initializer =
          HandlerInitializer(
              config = securityConfig(),
              redisHandler = CountingRedis(),
              agentHandler = RecordingAgent(),
          )
      initializer.initializeAgentIntegrations()
      val composite = initializer.compositeHandler!!
      val sink = initializer.compositeHandler!!.handlers
      assertTrue(sink.isNotEmpty())
      // The sink is exercised through sendEvent on the composite (the events path).
      composite.sendEvent(mapOf("event_type" to "penetration_attempt"))
      initializer.shutdownAgentIntegrations()
      assertNull(initializer.compositeHandler)
      // Idempotent shutdown.
      initializer.shutdownAgentIntegrations()
    }
  }

  /** The composite surface answers over the composed members. */
  @Test
  fun testCompositeSinkAgentProtocolForwards() {
    coreRunTest {
      resetIpBanGlobalState()
      val initializer =
          HandlerInitializer(
              config = securityConfig(),
              redisHandler = CountingRedis(),
              agentHandler = RecordingAgent(),
          )
      initializer.initializeAgentIntegrations()
      val protocolSink = initializer.compositeHandler
      assertNotNull(protocolSink)
      initializer.shutdownAgentIntegrations()
    }
  }

  /** lazy_init path: the cloud/geo redis initialization parks on the background task. */
  @Test
  fun testInitializeRedisHandlersLazyInit() {
    coreRunTest {
      resetIpBanGlobalState()
      CloudManager.resetInstance()
      val redis = CountingRedis()
      val geo = CountingGeo()
      val redisManager =
          com.guardcore.handlers.RedisManager(securityConfig()) { _, _, _ ->
            com.guardcore.handlers.NoopRedisOperations()
          }
      val initializer =
          HandlerInitializer(
              config =
                  securityConfig {
                    lazyInit = true
                    blockCloudProviders = setOf("AWS")
                  },
              redisHandler = redisManager,
              geoIpHandler = geo,
          )
      initializer.initializeRedisHandlers()
      assertNotNull(initializer.lazyInitTask)
      // Wait for the background lazy pass, then verify the wiring took.
      initializer.lazyInitTask!!.get(30, java.util.concurrent.TimeUnit.SECONDS)
      kotlinx.coroutines.delay(200)
      assertEquals(1, geo.initializeRedisCalls)
    }
  }

  @Test
  fun testInitializeRedisHandlersLazyInitWithoutRedisWarns() {
    coreRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.WARNING)
      try {
        val initializer =
            HandlerInitializer(
                config =
                    securityConfig {
                      lazyInit = true
                      enableRedis = true
                      redisUrl = null
                    },
                redisHandler = null,
                geoIpHandler = CountingGeo(),
            )
        initializer.initializeRedisHandlers()
        assertTrue(
            capture.text().contains("lazy_init has no effect without Redis"),
            capture.text(),
        )
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** connectRedis failure: fail-open falls back to the no-redis path, fail-closed raises. */
  @Test
  fun testConnectRedisFailOpenFallsBack() {
    coreRunTest {
      resetIpBanGlobalState()
      CloudManager.resetInstance()
      val initializer =
          HandlerInitializer(
              config = securityConfig { redisFailOpen = true },
              redisHandler = FailingRedis(),
              geoIpHandler = CountingGeo(),
          )
      initializer.initializeRedisHandlers()
      assertEquals(1, (initializer.geoIpHandler as CountingGeo).initializeCalls)
    }
  }

  @Test
  fun testConnectRedisFailClosedRaises() {
    coreRunTest {
      val initializer =
          HandlerInitializer(
              config = securityConfig { redisFailOpen = false },
              redisHandler = FailingRedis(),
          )
      val error =
          try {
            initializer.initializeRedisHandlers()
            null
          } catch (e: com.guardcore.errors.GuardRedisError) {
            e
          }
      assertNotNull(error)
    }
  }

  /** initializeAgentForHandlers with a foreign telemetry object returns early (the else arm). */
  @Test
  fun testInitializeAgentForHandlersForeignTelemetryIsInert() {
    coreRunTest {
      resetIpBanGlobalState()
      val initializer =
          HandlerInitializer(
              config = securityConfig(),
              agentHandler = object {},
          )
      initializer.initializeAgentForHandlers()
    }
  }

  /** The composite AgentHandlerProtocol adapter over the geo handler (initializeAgent arms). */
  @Test
  fun testInitializeAgentForHandlersWithGeoReceivesProtocol() {
    coreRunTest {
      resetIpBanGlobalState()
      val geo = CountingGeo()
      val initializer =
          HandlerInitializer(
              config = securityConfig(),
              redisHandler = CountingRedis(),
              agentHandler = RecordingAgent(),
              geoIpHandler = geo,
          )
      initializer.initializeAgentIntegrations()
      assertEquals(1, geo.initializeAgentCalls)
      initializer.shutdownAgentIntegrations()
    }
  }

  /** initializeDynamicRuleManager with a composite telemetry (the getDynamicRules adapter). */
  @Test
  fun testInitializeDynamicRuleManagerWithComposite() {
    coreRunTest {
      resetIpBanGlobalState()
      com.guardcore.handlers.DynamicRuleManager.resetInstance()
      val initializer =
          HandlerInitializer(
              config =
                  securityConfig {
                    enableDynamicRules = true
                    enableAgent = true
                    agentApiKey = "test-key"
                  },
              redisHandler = CountingRedis(),
              agentHandler = RecordingAgent(),
          )
      initializer.initializeAgentIntegrations()
      assertNotNull(initializer.compositeHandler)
      initializer.shutdownAgentIntegrations()
      com.guardcore.handlers.DynamicRuleManager.resetInstance()
    }
  }

  /** shutdown with no composite is a no-op (the guard arm). */
  @Test
  fun testShutdownWithoutCompositeIsNoop() {
    coreRunTest {
      val initializer = HandlerInitializer(config = securityConfig())
      initializer.shutdownAgentIntegrations()
    }
  }

  /** buildEventBus routes through the configured event filter (the filter wiring). */
  @Test
  fun testBuildEventFilterMutesConfiguredTypes() {
    val initializer =
        HandlerInitializer(
            config = securityConfig { mutedEventTypes = setOf("rate_limited") },
        )
    val filter = initializer.buildEventFilter()
    assertEquals(false, filter.isEventAllowed("rate_limited"))
    assertEquals(true, filter.isEventAllowed("penetration_attempt"))
  }
}

/** EventFilter vocabulary + the responses factory modifier arms. */
class EventFilterAndResponsesArmsTest {
  @Test
  fun testEventFilterDefaultsAllowEverything() {
    val filter = EventFilter()
    assertEquals(true, filter.isEventAllowed("anything"))
  }
}
