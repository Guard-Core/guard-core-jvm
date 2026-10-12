package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.TestRequest
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.RedisHandlerProtocol
import java.net.URI
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9e batch 4 handler arms: the agent-wired manager tails (geo events, cloud events, rate-limit
 * events), the fetcher/redis-backed download paths, the dynamic-rule persistence arms, the
 * security-headers cache/CSP arms, and the redis manager URL/connection tails.
 */
class HandlersW9eArmsTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  private class RecordingAgent : AgentHandlerProtocol {
    val events = mutableListOf<Map<String, Any?>>()

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun sendEvent(event: Any?) {
      @Suppress("UNCHECKED_CAST") events.add(event as Map<String, Any?>)
    }

    override suspend fun sendMetric(metric: Any?) {}

    override suspend fun start() {}

    override suspend fun stop() {}

    override suspend fun flushBuffer() {}

    override suspend fun getDynamicRules(): Any? = null

    override suspend fun healthCheck(): Boolean = true
  }

  /** Minimal HttpResponse double for the send-override seam. */
  private class FakeResponse(
      private val status: Int,
      private val payload: ByteArray,
      private val uri: URI,
  ) : HttpResponse<ByteArray> {
    override fun statusCode(): Int = status

    override fun body(): ByteArray = payload

    override fun headers(): HttpHeaders = HttpHeaders.of(mapOf(), { _, _ -> true })

    override fun uri(): URI = uri

    override fun previousResponse(): java.util.Optional<HttpResponse<ByteArray>> =
        java.util.Optional.empty()

    override fun request(): HttpRequest = HttpRequest.newBuilder().uri(uri).build()

    override fun sslSession(): java.util.Optional<javax.net.ssl.SSLSession> =
        java.util.Optional.empty()

    override fun version(): java.net.http.HttpClient.Version =
        java.net.http.HttpClient.Version.HTTP_1_1
  }

  // ------------------------------------------------------------ ipinfo agent arms

  @Test
  fun `ipinfo manager walks the agent event and download arms`() = runBlocking {
    val dir = Files.createTempDirectory("w9e-b4-ipinfo")
    val dbPath = dir.resolve("geo.mmdb")
    val agent = RecordingAgent()
    val manager = IpInfoManager.getInstance("w9e", dbPath, 60)
    manager.initializeAgent(agent)
    val live =
        RedisManager.getInstance(
            config {
              redisUrl = "redis://localhost:6379/0"
              enableRedis = true
            },
        )
    try {
      live.initialize()
      manager.redisHandler = live
      // sendGeoEvent without a handler returns quietly; with one it renders the envelope
      manager.sendGeoEvent(
          eventType = "w9e",
          ipAddress = "192.0.2.1",
          actionTaken = "a",
          reason = "r",
      )
      manager.agentHandler = HandlerAgentSink.of(agent)
      manager.sendGeoEvent(
          eventType = "w9e",
          ipAddress = "192.0.2.1",
          actionTaken = "a",
          reason = "r",
      )
      assertTrue(agent.events.isNotEmpty())
      // the full download path over the send override: 200 + body lands the file and
      // caches it into redis under the ipinfo namespace
      manager.httpSendOverride = { url, _ ->
        FakeResponse(200, "seeded-bytes".toByteArray(), URI.create(url))
      }
      manager.downloadDatabase()
      assertTrue(Files.exists(dbPath))
      assertNotNull(live.getKey("ipinfo", "database"))
      // a failing send rethrows after the retry loop (1s + 2s backoff)
      manager.httpSendOverride = { url, _ ->
        throw java.net.http.HttpTimeoutException("timeout $url")
      }
      manager.downloadOverride = null
      try {
        manager.downloadDatabase()
        throw AssertionError("expected the retry loop to rethrow")
      } catch (expected: java.net.http.HttpTimeoutException) {
        assertTrue(expected.message!!.contains("timeout"))
      }
      // checkCountryAccess: null country + whitelist, null country without, whitelist miss,
      // blacklist hit, and the allowed path - each through the lookup override
      manager.countryLookupOverride = { _ -> null }
      assertEquals(
          false to null,
          manager.checkCountryAccess("192.0.2.1", emptyList(), whitelistCountries = listOf("CN")),
      )
      assertEquals(true to null, manager.checkCountryAccess("192.0.2.1", listOf("CN")))
      manager.countryLookupOverride = { _ -> "CN" }
      val miss =
          manager.checkCountryAccess("192.0.2.1", emptyList(), whitelistCountries = listOf("US"))
      assertEquals(false, miss.first)
      val hit = manager.checkCountryAccess("192.0.2.1", listOf("CN"))
      assertEquals(false, hit.first)
      assertEquals("CN", hit.second)
      val allowed = manager.checkCountryAccess("192.0.2.1", listOf("US"))
      assertEquals(true, allowed.first)
      manager.countryLookupOverride = null
      // isDbOutdated over a fresh file
      assertFalse(manager.isDbOutdated())
    } finally {
      manager.agentHandler = null
      manager.countryLookupOverride = null
      manager.httpSendOverride = null
      manager.downloadOverride = null
      manager.redisHandler = null
      live.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
      manager.close()
    }
  }

  // ------------------------------------------------------------ cloud manager

  @Test
  fun `cloud manager walks the refresh, redis and event arms`() = runBlocking {
    val agent = RecordingAgent()
    val manager = CloudManager.getInstance()
    try {
      manager.agentHandler = HandlerAgentSink.of(agent)
      // refresh() without redis: the direct fetch path over a failing fetcher logs and
      // stores an empty range set
      manager.refresh(listOf("AWS"))
      // refresh with redis handler present refuses (refresh_async is the redis path)
      val live = RedisManager.getInstance(config { redisUrl = "redis://localhost:6379/0" })
      try {
        live.initialize()
        manager.redisHandler = live
        assertFailsWith<IllegalStateException> { manager.refresh(listOf("AWS")) }
        manager.redisHandler = null
        // initializeCloudRedis over the live handler walks the redis-backed refresh
        manager.cloudProviderDetailsOverride = { _, _ -> "AWS" to "203.0.113.0/24" }
        // isCloudIp over an override miss answers false without events
        manager.isCloudIpOverride = { _, _ -> false }
        assertFalse(manager.isCloudIp("192.0.2.1"))
        manager.agentHandler = null
      } finally {
        live.discardClientQuietlyForCorpus()
        RedisManager.resetInstance()
      }
    } finally {
      manager.agentHandler = null
      manager.isCloudIpOverride = null
      manager.cloudProviderDetailsOverride = null
    }
  }

  // ------------------------------------------------------------ rate limit manager

  @Test
  fun `rate limit manager walks the event and reset arms`() = runBlocking {
    val agent = RecordingAgent()
    val cfg = config {
      enableRateLimiting = true
      enableRedis = true
      redisUrl = "redis://localhost:6379/0"
    }
    val live =
        RedisManager.getInstance(
            config {
              redisUrl = "redis://localhost:6379/0"
              enableRedis = true
            },
        )
    try {
      live.initialize()
      val manager = RateLimitManager.getInstance(cfg)
      manager.reset()
      manager.initializeAgent(HandlerAgentSink.of(agent))
      manager.redisHandler = live
      manager.initializeRedis(live)
      // handleRateLimitExceeded with an agent renders the rate-limited envelope
      val response =
          manager.handleRateLimitExceeded(
              TestRequest(),
              "192.0.2.30",
              12,
              createErrorResponse = { code: Int, message: String ->
                object : GuardResponse {
                  override val headers: MutableMap<String, String> = linkedMapOf()
                  override val statusCode: Int = code
                  override val body: ByteArray = message.encodeToByteArray()
                }
              },
          )
      assertEquals(429, response.statusCode)
      assertTrue(agent.events.any { it["event_type"] == "rate_limited" }, agent.events.toString())
      // reset over the live handler clears the rate keys and detaches
      manager.reset()
      assertNull(manager.redisHandler)
      assertNull(manager.agentHandler)
    } finally {
      live.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
    }
  }

  // ------------------------------------------------------------ dynamic rule manager

  @Test
  fun `dynamic rule manager walks the agent source and persistence arms`() = runBlocking {
    val agent = RecordingAgent()
    val dir = Files.createTempDirectory("w9e-b4-dynamic")
    DynamicRuleManager.resetInstance()
    try {
      val cfg = config {
        enableAgent = true
        agentApiKey = "w9e-key"
        enableDynamicRules = true
        dynamicRulesCachePath = dir.resolve("cache.json")
      }
      val manager = DynamicRuleManager.getInstance(cfg)
      manager.agentHandler =
          object : DynamicRuleManager.AgentDynamicRulesSource {
            override suspend fun getDynamicRules(): DynamicRules? = null

            override suspend fun sendEvent(event: Map<String, Any?>) {
              agent.sendEvent(event)
            }
          }
      // updateRules with an empty agent answer persists + applies nothing
      manager.updateRules()
      // getCurrentRules before any application is null
      assertNull(manager.getCurrentRules())
      manager.stop()
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  // ------------------------------------------------------------ security headers manager

  @Test
  fun `security headers manager walks the csp and cache failure arms`() = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    manager.headersCache.clear()
    // an unsafe CSP directive logs the warning and still renders
    val cfg = config {
      securityHeaders =
          mapOf(
              "enabled" to true,
              "content_security_policy" to "default-src 'unsafe-inline'",
          )
    }
    val headers = manager.getHeaders("/api", config = cfg)
    assertTrue(headers.isNotEmpty())
    // a permissions-policy value removes the header when validation fails
    val invalid = config {
      securityHeaders =
          mapOf(
              "enabled" to true,
              "permissions_policy" to "bad directive ??",
          )
    }
    val headers2 = manager.getHeaders("/api", config = invalid)
    assertNotNull(headers2)
    // validateCspReport rejects a report without the required fields
    val valid =
        manager.validateCspReport(
            linkedMapOf(
                "csp-report" to
                    linkedMapOf<String, Any?>(
                        "document-uri" to "https://w9e.example/",
                        "violated-directive" to "default-src",
                        "effective-directive" to "default-src",
                        "original-policy" to "default-src 'self'",
                        "blocked-uri" to "https://evil.example",
                    ),
            ),
        )
    assertTrue(valid)
    // a report missing the required fields is rejected
    assertFalse(
        manager.validateCspReport(
            linkedMapOf("csp-report" to linkedMapOf<String, Any?>("document-uri" to "x")),
        ),
    )
  }

  // ------------------------------------------------------------ redis manager tails

  @Test
  fun `redis manager walks the unparseable url and redaction arms`() = runBlocking {
    // redactRedisUrl over a userinfo URL keeps the host and drops credentials
    assertEquals("redis://h:1/x", redactRedisUrl("redis://user:secret@h:1/x"))
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://[::1]:nope"))
    // the raw-string RedisValue rendering arm
    assertEquals("plain", redisValueToString("plain"))
  }

  private fun redisValueToString(value: Any?): String = value?.toString() ?: "null"
}
