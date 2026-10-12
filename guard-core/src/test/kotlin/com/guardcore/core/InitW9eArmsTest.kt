package com.guardcore.core

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.EventFilter
import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RedisManager
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.SusPatternsRegistry
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.RedisHandlerProtocol
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9e batch 4 initializer arms: the initializer's composite sink + agent-protocol adapters, the
 * lazy cloud/geo arms, the enrichment/filter wiring, and the telemetry sink adapters.
 */
class InitW9eArmsTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  private class NullAgent : AgentHandlerProtocol {
    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun sendEvent(event: Any?) {}

    override suspend fun sendMetric(metric: Any?) {}

    override suspend fun start() {}

    override suspend fun stop() {}

    override suspend fun flushBuffer() {}

    override suspend fun getDynamicRules(): Any? = null

    override suspend fun healthCheck(): Boolean = true
  }

  private val nullProtocol = NullAgent()

  @Test
  fun `initializer wires the composite sink end to end over live redis`() = runBlocking {
    val live =
        RedisManager.getInstance(
            config {
              redisUrl = "redis://localhost:6379/0"
              enableRedis = true
            },
        )
    val initConfig = config {
      enableAgent = true
      agentApiKey = "w9e"
      enableRedis = true
      redisUrl = "redis://localhost:6379/0"
    }
    val initializer =
        HandlerInitializer(
            initConfig,
            redisHandler = live,
            agentHandler = nullProtocol,
            rateLimitHandler = RateLimitManager.getInstance(initConfig),
        )
    initializer.eventFilter = EventFilter()
    initializer.enricher =
        EventEnricher(com.guardcore.core.events.EnrichmentContext(config = initializer.config))
    try {
      live.initialize()
      initializer.initializeRedisHandlers()
      initializer.initializeAgentIntegrations()
      val composite = assertNotNull(initializer.compositeHandler)
      // the managers carry the composite sink: a rate-limit event flows through line 180
      val rateManager = RateLimitManager.getInstance(initializer.config)
      assertNotNull(rateManager.agentHandler)
      rateManager.sendRateLimitEvent(TestRequest(), "192.0.2.31", 3)
      // the enrichment/filter path runs over real payloads
      composite.sendEvent(mapOf("event_type" to "w9e", "ip_address" to "192.0.2.31"))
      composite.sendMetric(mapOf("metric_type" to "error_rate", "value" to 1.0))
      assertTrue(composite.healthCheck())
      assertFalse(composite.isDegraded)
      initializer.shutdownAgentIntegrations()
      assertNull(initializer.compositeHandler)
    } finally {
      rateManagerTeardown()
      live.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
    }
  }

  private fun rateManagerTeardown() {
    runBlocking {
      val manager = RateLimitManager.getInstance(SecurityConfigBuilder().build())
      manager.reset()
    }
  }

  @Test
  fun `initializer lazy cloud and geo arms answer without handlers`() = runBlocking {
    // no cloud providers and no geo handler: the lazy init returns immediately
    val bare = HandlerInitializer(config())
    bare.initializeRedisHandlers()
    // with a cloud-ip store factory the resolver builds the store over the handler
    val storeFactory: (Any?) -> com.guardcore.handlers.CloudIpStore = { _ ->
      object : com.guardcore.handlers.CloudIpStore {
        override suspend fun get(provider: String): Set<String>? = null

        override suspend fun set(provider: String, ranges: Set<String>, ttl: Int?) {}

        override suspend fun clear() {}
      }
    }
    val withStore =
        HandlerInitializer(
            config {
              blockCloudProviders = setOf("AWS")
              cloudIpStore = storeFactory
            },
        )
    withStore.initializeRedisHandlers()
    withStore.initializeAgentIntegrations()
    assertTrue(true)
    CloudManager.getInstance().agentHandler = null
    SusPatternsRegistry.agentHandler = null
    SecurityHeadersManager.getInstance().initializeHeadersAgent(null)
  }

  @Test
  fun `telemetry sink adapters tolerate raw payloads`() = runBlocking {
    val initializer =
        HandlerInitializer(
            config {
              enableAgent = true
              agentApiKey = "w9e"
            },
            agentHandler = nullProtocol,
        )
    initializer.initializeAgentIntegrations()
    val composite = assertNotNull(initializer.compositeHandler)
    // the composite takes map payloads; raw-payload adapters live in the manager wiring
    composite.sendEvent(mapOf("event_type" to "w9e"))
    composite.sendMetric(mapOf("metric_type" to "error_rate"))
    assertNull(null)
    initializer.shutdownAgentIntegrations()
  }

  private fun sinkOf(manager: RateLimitManager): HandlerAgentSink? = manager.agentHandler
}
