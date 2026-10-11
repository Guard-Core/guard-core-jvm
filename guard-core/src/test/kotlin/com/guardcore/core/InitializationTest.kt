package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RecordingAgent
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.SusPatternsRegistry
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import java.nio.file.Files
import java.util.logging.Level
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_initialization.py: HandlerInitializer's redis/agent wiring, the
 * dynamic-rule-manager gating, the composite/event-filter builders, and the redis-unreachable
 * degradation halves.
 *
 * Seam mapping: python mocks every handler; the JVM drives the real singletons with recording
 * fakes at the protocol seams and asserts the same wiring through the managers' public handler
 * fields. The DynamicRuleManager is constructed inside the initializer (python observes it via
 * class-patching, which has no JVM analog), so its enabled/no-redis halves assert the completion
 * and warning surfaces.
 */
public class InitializationTest {
  /** Recording redis with an initialize call count (python's `handler.initialize` AsyncMock). */
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

  /** Broken-restore redis: get_key raises (python's get_key AsyncMock side_effect). */
  private class BrokenGetKeyRedis : RedisHandlerProtocol {
    var getKeyCalls: Int = 0

    override suspend fun getKey(namespace: String, key: String): Any? {
      getKeyCalls += 1
      throw com.guardcore.errors.GuardRedisError(503, "Redis connection failed")
    }

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?) = true

    override suspend fun delete(namespace: String, key: String): Int? = 0

    override suspend fun keys(pattern: String): List<String>? = emptyList()

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection =
        object : GuardRedisConnection {
          override val client: Any? = null

          override fun close() {}
        }
  }

  /** Counting geo handler (python's mock_geo_ip_handler) with an optional getStatus. */
  private class CountingGeo(
      private val withGetStatus: Map<String, Any?>? = null,
  ) : GeoIPHandler {
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

    override suspend fun initializeAgent(agentHandler: com.guardcore.protocols.AgentHandlerProtocol) {
      initializeAgentCalls += 1
    }

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  /** python `Mock(spec=[])`: a geo handler presenting no methods at all. */
  private class BareObject

  /** python `Mock(spec=["is_initialized"])`. */
  private class ReadyGeo : GeoIPHandler {
    override val isInitialized: Boolean = true

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun initializeAgent(agentHandler: com.guardcore.protocols.AgentHandlerProtocol) {}

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun securityConfig(mutate: com.guardcore.config.SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      coreTestConfig {
        lazyInit = false
        enableRedis = true
        enableDynamicRules = false
        blockCloudProviders = emptySet()
        mutate()
      }

  private fun initializer(
      config: SecurityConfig,
      redis: Any? = CountingRedis(),
      agent: Any? = RecordingAgent(),
      geo: Any? = CountingGeo(),
      rateLimit: Any? = RateLimitManager.getInstance(config),
      decorator: Any? = BaseSecurityDecorator(config),
  ): HandlerInitializer =
      HandlerInitializer(
          config = config,
          redisHandler = redis,
          agentHandler = agent,
          geoIpHandler = geo,
          rateLimitHandler = rateLimit,
          guardDecorator = decorator,
      )

  // ------------------------------- test_initialization.py:82-88

  @Test
  fun init() {
    val config = securityConfig()
    val redis = CountingRedis()
    val initializer = HandlerInitializer(config = config, redisHandler = redis)

    assertTrue(initializer.config === config)
    assertTrue(initializer.redisHandler === redis)
  }

  // ------------------------------- test_initialization.py:91-105

  @Test
  fun initializeRedisHandlersDisabled() {
    coreRunTest {
      val config = securityConfig { enableRedis = false }
      val initializer = HandlerInitializer(config = config)

      initializer.initializeRedisHandlers()
    }
  }

  @Test
  fun initializeRedisHandlersNoHandler() {
    coreRunTest {
      val config = securityConfig()
      val initializer = HandlerInitializer(config = config, redisHandler = null)

      initializer.initializeRedisHandlers()
    }
  }

  // ------------------------------- test_initialization.py:108-134

  @Test
  fun initializeRedisHandlersBasic() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val redis = CountingRedis()
      val geo = CountingGeo()
      val rateLimit = RateLimitManager.getInstance(config)
      val initializer = initializer(config, redis, geo = geo, rateLimit = rateLimit)

      initializer.initializeRedisHandlers()

      assertEquals(1, redis.initializeCalls)
      assertEquals(redis, IpBanManager.getInstance().redisHandler)
      assertEquals(1, geo.initializeRedisCalls)
      assertEquals(redis, rateLimit.redisHandler)
      assertEquals(redis, SusPatternsRegistry.redisHandler)
    }
  }

  // ------------------------------- test_initialization.py:137-161
  // python asserts cloud.initialize_redis(handler, providers, ttl=...); the JVM drives the real
  // CloudManager, which requires a RedisManager (the cast in the initializer) - the observable
  // wiring is the manager assignment plus the in-memory store swap onto the redis-backed store.

  @Test
  fun initializeRedisHandlersWithCloud() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val redisManager =
          com.guardcore.handlers.RedisManager(config) { _, _, _ ->
            com.guardcore.handlers.NoopRedisOperations()
          }
      val cloud = CloudManager.getInstance()
      val savedRedisHandler = cloud.redisHandler
      val savedStore = cloud.store
      val initializer =
          HandlerInitializer(
              config = securityConfig { blockCloudProviders = setOf("AWS", "GCP") },
              redisHandler = redisManager,
          )

      try {
        initializer.initializeRedisHandlers()

        assertEquals(redisManager, cloud.redisHandler)
      } finally {
        cloud.redisHandler = savedRedisHandler
        cloud.store = savedStore
      }
    }
  }

  // ------------------------------- test_initialization.py:164-188

  @Test
  fun initializeRedisHandlersSetsCloudIpStoreWhenConfigured() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val customStore = RecordingCloudIpStore()
      val cloud = CloudManager.getInstance()
      val savedStore = cloud.store
      val initializer =
          HandlerInitializer(
              config = securityConfig { cloudIpStore = customStore },
              redisHandler = CountingRedis(),
          )

      try {
        initializer.initializeRedisHandlers()

        assertEquals(customStore, cloud.store)
      } finally {
        cloud.store = savedStore
      }
    }
  }

  // ------------------------------- test_initialization.py:191-214

  @Test
  fun initializeRedisHandlersNoOptionalHandlers() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val redis = CountingRedis()
      val initializer =
          HandlerInitializer(
              config = config,
              redisHandler = redis,
              geoIpHandler = null,
              rateLimitHandler = null,
          )

      initializer.initializeRedisHandlers()

      assertEquals(1, redis.initializeCalls)
    }
  }

  // ------------------------------- test_initialization.py:217-246

  @Test
  fun initializeRedisHandlersInitializesBehaviorTrackingWithRules() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val redis = CountingRedis()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("route")
      rc.behaviorRules.add(
          BehaviorRule(ruleType = "usage", threshold = 5, window = 60, action = "ban"),
      )
      val initializer = initializer(config, redis, decorator = decorator)

      initializer.initializeRedisHandlers()

      assertEquals(redis, decorator.behaviorTracker.redisHandler)
    }
  }

  // ------------------------------- test_initialization.py:249-266

  @Test
  fun initializeRedisHandlersSkipsBehaviorTrackingWithoutRules() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val redis = CountingRedis()
      val decorator = BaseSecurityDecorator(config)
      decorator.ensureRouteConfig("route")
      val initializer = initializer(config, redis, decorator = decorator)

      initializer.initializeRedisHandlers()

      assertNull(decorator.behaviorTracker.redisHandler)
    }
  }

  // ------------------------------- test_initialization.py:269-290

  @Test
  fun initializeRedisHandlersSkipsBehaviorTrackingWithoutDecorator() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val initializer =
          HandlerInitializer(config = config, redisHandler = CountingRedis(), guardDecorator = null)

      initializer.initializeRedisHandlers()
    }
  }

  // ------------------------------- test_initialization.py:293-298

  @Test
  fun initializeAgentForHandlersNoAgent() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val initializer = HandlerInitializer(config = config, agentHandler = null)

      initializer.initializeAgentForHandlers()
    }
  }

  // ------------------------------- test_initialization.py:301-328

  @Test
  fun initializeAgentForHandlersBasic() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val rateLimit = RateLimitManager.getInstance(config)
      val initializer = initializer(config, agent = agent, rateLimit = rateLimit)

      initializer.initializeAgentForHandlers()

      assertEquals(agent, IpBanManager.getInstance().agentHandler)
      assertEquals(agent, rateLimit.agentHandler)
      assertEquals(agent, SusPatternsRegistry.agentHandler)
      assertEquals(agent, SecurityHeadersManager.getInstance().agentHandler)
    }
  }

  // ------------------------------- test_initialization.py:331-355

  @Test
  fun initializeAgentForHandlersWithCloud() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val cloud = CloudManager.getInstance()
      val savedAgentHandler = cloud.agentHandler
      val initializer =
          HandlerInitializer(
              config = securityConfig { blockCloudProviders = setOf("AWS") },
              agentHandler = agent,
          )

      try {
        initializer.initializeAgentForHandlers()

        assertEquals(agent, cloud.agentHandler)
      } finally {
        cloud.agentHandler = savedAgentHandler
      }
    }
  }

  // ------------------------------- test_initialization.py:358-380
  // python asserts the geo handler received the agent handler; the initializer wraps the sink in
  // the AgentHandlerProtocol adapter, so the JVM pins the call (count) rather than the identity.

  @Test
  fun initializeAgentForHandlersWithGeoip() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val geo = CountingGeo()
      val initializer = initializer(config, agent = agent, geo = geo)

      initializer.initializeAgentForHandlers()

      assertEquals(1, geo.initializeAgentCalls)
    }
  }

  // ------------------------------- test_initialization.py:383-411

  @Test
  fun initializeAgentForHandlersWithoutRateLimitHandler() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val initializer =
          HandlerInitializer(
              config = config,
              agentHandler = agent,
              rateLimitHandler = null,
          )

      initializer.initializeAgentForHandlers()

      assertEquals(agent, IpBanManager.getInstance().agentHandler)
      assertEquals(agent, SusPatternsRegistry.agentHandler)
      assertEquals(agent, SecurityHeadersManager.getInstance().agentHandler)
    }
  }

  // ------------------------------- test_initialization.py:414-439

  @Test
  fun initializeAgentForHandlersGeoipWithoutInitializeAgent() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val initializer =
          HandlerInitializer(
              config = config,
              agentHandler = RecordingAgent(),
              geoIpHandler = BareObject(),
          )

      initializer.initializeAgentForHandlers()
    }
  }

  // ------------------------------- test_initialization.py:442-452

  @Test
  fun initializeDynamicRuleManagerDisabled() {
    coreRunTest {
      val config = securityConfig { enableDynamicRules = false }
      val initializer = HandlerInitializer(config = config)
      val capture =
          com.guardcore.handlers.LogCapture(
              java.util.logging.Logger.getLogger("guard_core.core.initialization"),
              Level.CONFIG,
          )
      try {
        initializer.initializeDynamicRuleManager()

        assertEquals(
            0,
            capture.records.filter { it.level == Level.WARNING }.size,
        )
      } finally {
        capture.release()
      }
    }
  }

  // ------------------------------- test_initialization.py:455-472

  @Test
  fun initializeDynamicRuleManagerNoAgent() {
    coreRunTest {
      val initializer =
          HandlerInitializer(
              config = securityConfig {
                enableDynamicRules = true
                enableAgent = true
                agentApiKey = "test-key"
              },
              agentHandler = null,
          )
      val capture =
          com.guardcore.handlers.LogCapture(
              java.util.logging.Logger.getLogger("guard_core.core.initialization"),
              Level.CONFIG,
          )
      try {
        initializer.initializeDynamicRuleManager()

        val warnings =
            capture.records.filter {
              it.level == Level.WARNING &&
                  it.loggerName == "guard_core.core.initialization" &&
                  it.message.contains("Dynamic rules enabled but agent unavailable")
            }
        assertEquals(1, warnings.size)
      } finally {
        capture.release()
      }
    }
  }

  // ------------------------------- test_initialization.py:475-545
  // python class-patches DynamicRuleManager to observe construction, the redis-before-agent
  // order, and the no-redis skip; the JVM constructs and wires the manager inside the
  // initializer, so these halves assert the observable completion surface (no warnings, the
  // singleton untouched).

  @Test
  fun initializeDynamicRuleManagerEnabled() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig {
        enableDynamicRules = true
        enableAgent = true
        agentApiKey = "test-key"
      }
      val initializer = initializer(config)
      val capture =
          com.guardcore.handlers.LogCapture(
              java.util.logging.Logger.getLogger("guard_core.core.initialization"),
              Level.CONFIG,
          )
      try {
        initializer.initializeDynamicRuleManager()

        assertEquals(0, capture.records.filter { it.level == Level.WARNING }.size)
      } finally {
        capture.release()
      }
    }
  }

  @Test
  fun initializeDynamicRuleManagerNoRedis() {
    coreRunTest {
      val config = securityConfig {
        enableDynamicRules = true
        enableAgent = true
        agentApiKey = "test-key"
      }
      val initializer =
          HandlerInitializer(config = config, agentHandler = RecordingAgent(), redisHandler = null)

      initializer.initializeDynamicRuleManager()
    }
  }

  // ------------------------------- test_initialization.py:549-554

  @Test
  fun initializeAgentIntegrationsNoAgent() {
    coreRunTest {
      val config = securityConfig()
      val initializer = HandlerInitializer(config = config, agentHandler = null)

      initializer.initializeAgentIntegrations()

      assertNull(initializer.compositeHandler)
    }
  }

  // ------------------------------- test_initialization.py:557-585

  @Test
  fun initializeAgentIntegrationsFull() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val redis = CountingRedis()
      val rateLimit = RateLimitManager.getInstance(config)
      val decorator = BaseSecurityDecorator(config)
      val initializer = initializer(config, redis, agent, rateLimit = rateLimit, decorator = decorator)

      initializer.initializeAgentIntegrations()

      assertNotNull(initializer.compositeHandler)
      // The managers receive the composite sink (the python run's mock_init_handlers half).
      assertNotNull(IpBanManager.getInstance().agentHandler)
      assertNotNull(rateLimit.agentHandler)
      assertNotNull(SusPatternsRegistry.agentHandler)
      assertNotNull(SecurityHeadersManager.getInstance().agentHandler)
      assertTrue(decorator.agentHandler === initializer.compositeHandler)
    }
  }

  // ------------------------------- test_initialization.py:588-603

  @Test
  fun initializeAgentIntegrationsNoRedis() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val initializer =
          HandlerInitializer(
              config = config,
              agentHandler = agent,
              redisHandler = null,
          )

      initializer.initializeAgentIntegrations()

      assertNotNull(initializer.compositeHandler)
      assertNotNull(IpBanManager.getInstance().agentHandler)
    }
  }

  // ------------------------------- test_initialization.py:606-621

  @Test
  fun initializeAgentIntegrationsNoDecorator() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val agent = RecordingAgent()
      val initializer =
          HandlerInitializer(config = config, agentHandler = agent, guardDecorator = null)

      initializer.initializeAgentIntegrations()

      assertNotNull(initializer.compositeHandler)
      assertNotNull(IpBanManager.getInstance().agentHandler)
    }
  }

  // ------------------------------- test_initialization.py:624-640

  @Test
  fun initializeAgentIntegrationsDecoratorNoMethod() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = securityConfig()
      val initializer =
          HandlerInitializer(
              config = config,
              agentHandler = RecordingAgent(),
              guardDecorator = BareObject(),
          )

      initializer.initializeAgentIntegrations()

      assertNotNull(initializer.compositeHandler)
    }
  }

  // ------------------------------- test_initialization.py:643-652

  @Test
  fun buildCompositeHandlerAgentOnly() {
    val config = securityConfig {
      enableOtel = false
      enableLogfire = false
    }
    val agent = RecordingAgent()
    val initializer = HandlerInitializer(config = config, agentHandler = agent)

    val result = initializer.buildCompositeHandler()

    assertEquals(1, result.handlers.size)
  }

  // ------------------------------- test_initialization.py:655-665
  // python class-patches OtelHandler; the JVM seam is the compositeMemberFactory (the W4b
  // contract): a host providing the SDK surface registers its member factory.

  @Test
  fun buildCompositeHandlerWithOtel() {
    val config = securityConfig {
      enableOtel = true
      enableLogfire = false
    }
    val initializer = HandlerInitializer(config = config, agentHandler = RecordingAgent())
    initializer.compositeMemberFactory = { _, _ -> listOf(fakeMember()) }

    val result = initializer.buildCompositeHandler()

    assertEquals(2, result.handlers.size)
  }

  @Test
  fun buildCompositeHandlerWithLogfire() {
    val config = securityConfig {
      enableOtel = false
      enableLogfire = true
    }
    val initializer = HandlerInitializer(config = config, agentHandler = RecordingAgent())
    initializer.compositeMemberFactory = { _, _ -> listOf(fakeMember()) }

    val result = initializer.buildCompositeHandler()

    assertEquals(2, result.handlers.size)
  }

  @Test
  fun buildCompositeHandlerOtelAndLogfire() {
    val config = securityConfig {
      enableOtel = true
      enableLogfire = true
    }
    val initializer = HandlerInitializer(config = config, agentHandler = RecordingAgent())
    initializer.compositeMemberFactory = { _, _ -> listOf(fakeMember(), fakeMember()) }

    val result = initializer.buildCompositeHandler()

    assertEquals(3, result.handlers.size)
  }

  // ------------------------------- test_initialization.py:700-711

  @Test
  fun buildCompositeHandlerNoAgent() {
    val config = securityConfig {
      enableOtel = true
      enableLogfire = false
    }
    val initializer = HandlerInitializer(config = config, agentHandler = null)
    initializer.compositeMemberFactory = { _, _ -> listOf(fakeMember()) }

    val result = initializer.buildCompositeHandler()

    assertEquals(1, result.handlers.size)
  }

  // ------------------------------- test_initialization.py:714-723

  @Test
  fun buildEventFilter() {
    val config = securityConfig {
      mutedEventTypes = setOf("penetration_attempt")
      mutedMetricTypes = setOf("response_time")
    }
    val initializer = HandlerInitializer(config = config)

    val result = initializer.buildEventFilter()

    assertEquals(setOf("penetration_attempt"), result.mutedEventTypes)
    assertEquals(setOf("response_time"), result.mutedMetricTypes)
  }

  // ------------------------------- test_initialization.py:726-736

  @Test
  fun getInitializationStatusReportsCloudAndGeo() {
    val config = securityConfig()
    val initializer =
        HandlerInitializer(config = config, geoIpHandler = StatusOnlyGeo())

    val status = initializer.getInitializationStatus()

    assertTrue("cloud_providers" in status)
    assertEquals(
        mapOf("ready" to true, "last_refreshed" to null, "entries" to 5),
        status["geo_ip"],
    )
  }

  // ------------------------------- test_initialization.py:739-750

  @Test
  fun getInitializationStatusFallsBackWithoutGetStatusMethod() {
    val config = securityConfig()
    val initializer = HandlerInitializer(config = config, geoIpHandler = ReadyGeo())

    val status = initializer.getInitializationStatus()

    assertEquals(
        mapOf("ready" to true, "last_refreshed" to null, "entries" to 0),
        status["geo_ip"],
    )
  }

  // ------------------------------- test_initialization.py:753-761

  @Test
  fun getInitializationStatusGeoNoneWhenNoGeoHandler() {
    val config = securityConfig()
    val initializer = HandlerInitializer(config = config, geoIpHandler = null)

    val status = initializer.getInitializationStatus()

    assertNull(status["geo_ip"])
    assertTrue("cloud_providers" in status)
  }

  // ------------------------------- test_initialization.py:764-796

  @Test
  fun initializeRedisHandlersDegradesToMemoryWhenUnreachableFailOpen() {
    coreRunTest {
      resetIpBanGlobalState()
      SusPatternsRegistry.redisHandler = null
      val config = securityConfig { redisFailOpen = true }
      val redis = FailingInitializeRedis()
      val geo = CountingGeo()
      val initializer = HandlerInitializer(config = config, redisHandler = redis, geoIpHandler = geo)
      val capture =
          com.guardcore.handlers.LogCapture(
              java.util.logging.Logger.getLogger("guard_core.core.initialization"),
              Level.CONFIG,
          )

      try {
        initializer.initializeRedisHandlers()

        assertEquals(1, geo.initializeCalls)
        assertNull(IpBanManager.getInstance().redisHandler)
        assertNull(SusPatternsRegistry.redisHandler)
        assertTrue(
            capture.records.any {
              it.level == Level.SEVERE &&
                  it.message.contains("Redis unavailable during initialization")
            },
        )
      } finally {
        capture.release()
      }
    }
  }

  // ------------------------------- test_initialization.py:799-815

  @Test
  fun initializeRedisHandlersReraisesRedisUnreachableFailOpenIsFalse() {
    coreRunTest {
      resetIpBanGlobalState()
      SusPatternsRegistry.redisHandler = null
      val config = securityConfig { redisFailOpen = false }
      val initializer =
          HandlerInitializer(config = config, redisHandler = FailingInitializeRedis())
      val capture =
          com.guardcore.handlers.LogCapture(
              java.util.logging.Logger.getLogger("guard_core.core.initialization"),
              Level.CONFIG,
          )

      try {
        assertFailsWith<com.guardcore.errors.GuardRedisError> {
          initializer.initializeRedisHandlers()
        }

        assertTrue(
            capture.records.any {
              it.level == Level.SEVERE &&
                  it.message.contains("Redis unavailable during initialization")
            },
        )
      } finally {
        capture.release()
      }
    }
  }

  // ------------------------------- test_initialization.py:818-843

  @Test
  fun initializeRedisHandlersCompletesWhenSusPatternsGetKeyFails() {
    coreRunTest {
      resetIpBanGlobalState()
      for (failOpen in listOf(true, false)) {
        val config = securityConfig { redisFailOpen = failOpen }
        val redis = BrokenGetKeyRedis()
        SusPatternsRegistry.redisHandler = null
        val initializer = initializer(config, redis)

        initializer.initializeRedisHandlers()

        assertEquals(redis, SusPatternsRegistry.redisHandler)
        assertTrue(redis.getKeyCalls >= 1)
      }
    }
  }

  // ------------------------------- test_initialization.py:846-882

  @Test
  fun initializeRedisHandlersCompletesWhenGeoIpHandlerGetKeyFails() {
    coreRunTest {
      resetIpBanGlobalState()
      val tmp = Files.createTempDirectory("w8a-init")
      for (failOpen in listOf(true, false)) {
        val config = securityConfig { redisFailOpen = failOpen }
        val redis = BrokenGetKeyRedis()
        val geo =
            com.guardcore.handlers.IpInfoManager.getInstance(
                "tok",
                dbPath = tmp.resolve("geo.mmdb"),
            )
        val initializer =
            HandlerInitializer(config = config, redisHandler = redis, geoIpHandler = geo)

        initializer.initializeRedisHandlers()

        assertEquals(redis, geo.redisHandler)
        com.guardcore.handlers.IpInfoManager.resetInstance()
      }
    }
  }
}

/** python `Mock(spec=["get_status"])` for the reflection branch of get_initialization_status. */
public class StatusOnlyGeo {
  @Suppress("unused")
  public fun getStatus(): Map<String, Any?> =
      mapOf("ready" to true, "last_refreshed" to null, "entries" to 5)
}

/** python `custom_store = Mock()`: a recording CloudIpStore fake. */
private class RecordingCloudIpStore : com.guardcore.handlers.CloudIpStore {
  override suspend fun get(provider: String): Set<String>? = null

  override suspend fun set(provider: String, ranges: Set<String>, ttl: Int?) {}

  override suspend fun clear() {}
}

private fun fakeMember(): AgentTelemetryMember =
    object : AgentTelemetryMember {
      override suspend fun sendEvent(event: Map<String, Any?>) {}
    }

/** redis whose initialize() raises GuardRedisError (python's initialize side_effect). */
private class FailingInitializeRedis : RedisHandlerProtocol {
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
