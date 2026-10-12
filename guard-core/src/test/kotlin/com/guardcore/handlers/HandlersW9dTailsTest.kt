package com.guardcore.handlers

import com.guardcore.config.ConfigSeams
import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import java.net.URI
import java.net.http.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9d handler-tail coverage: the CloudManager refresh/store arms over the fetcher httpGet
 * overrides, the RedisManager URL redaction and operation-serialization tails, the
 * RateLimitManager script-load and failure arms, the IpInfoManager download retry loop over the
 * httpSendOverride seam, and the SecurityHeadersManager cache/CORS tails.
 */

/** A minimal HttpResponse fake for the IpInfoManager download seam (the aiohttp mock analog). */
public class FakeIpInfoHttpResponse(
    private val status: Int,
    private val body: ByteArray,
) : HttpResponse<ByteArray> {
  override fun statusCode(): Int = status
  override fun body(): ByteArray = body
  override fun headers() = java.net.http.HttpHeaders.of(mapOf(), { _, _ -> true })
  override fun uri(): URI = URI.create("https://ipinfo.io/data/free/country_asn.mmdb")
  override fun previousResponse() = java.util.Optional.empty<HttpResponse<ByteArray>>()
  override fun request(): java.net.http.HttpRequest =
      java.net.http.HttpRequest.newBuilder().uri(uri()).build()
  override fun sslSession() = java.util.Optional.empty<javax.net.ssl.SSLSession>()
  override fun version() = java.net.http.HttpClient.Version.HTTP_1_1
}

public class HandlersW9dTailsTest {
  // ------------------------------------------------------------------
  // CloudManager
  // ------------------------------------------------------------------

  @Test
  fun testCloudManagerRefreshArmsWithFetcherOverride() = runBlocking {
    CloudManager.resetInstance()
    CloudFetchers.httpGetOverride = { _ -> throw IllegalStateException("network down") }
    try {
      val manager = CloudManager.getInstance()
      // fetch failure leaves the provider mapped to an empty range set
      manager.refreshProviders(setOf("AWS"))
      assertEquals(emptySet(), manager.ipRanges["AWS"])
      assertNotNull(manager.lastUpdated)
      // store-less refreshAsync routes through the redis handler path (null handler falls back)
      manager.store = null
      manager.refreshAsync(setOf("AWS"), ttl = 60)
      assertEquals(emptySet(), manager.ipRanges["AWS"])
      // invalid IP never flags a cloud provider
      assertFalse(manager.isCloudIp("not-an-ip", setOf("AWS")))
      // the provider-name fetch dispatch covers the remaining fetchers
      CloudFetchers.httpGetOverride = { _ ->
        200 to "1.2.3.0/24\n5.6.7.0/24\n"
      }
      manager.refreshProviders(setOf("Linode"))
      assertTrue(manager.ipRanges["Linode"]!!.isNotEmpty())
      CloudFetchers.httpGetOverride = { _ ->
        200 to """{"subnets": [{"ip_prefix": "45.32.0.0/16"}]}"""
      }
      manager.refreshProviders(setOf("Vultr"))
      assertTrue(manager.ipRanges["Vultr"]!!.isNotEmpty())
    } finally {
      CloudFetchers.httpGetOverride = null
      CloudManager.resetInstance()
    }
  }

  @Test
  fun testCloudManagerScheduleRefreshArms() = runBlocking {
    CloudManager.resetInstance()
    try {
      val manager = CloudManager.getInstance()
      var ran = false
      val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
      val scheduled =
          manager.scheduleRefresh(refresh = {
            gate.await()
            ran = true
          })
      assertTrue(scheduled)
      // single-flight: a second schedule while one is in flight is rejected
      val second = manager.scheduleRefresh(refresh = {})
      assertFalse(second)
      // release the in-flight refresh and let the background job finish
      gate.complete(Unit)
      var waited = 0
      while (!ran && waited < 100) {
        kotlinx.coroutines.delay(50)
        waited++
      }
      assertTrue(ran)
      // a refresh lambda that throws is contained by the background runner
      val third = manager.scheduleRefresh(refresh = { throw IllegalStateException("boom") })
      assertTrue(third)
      kotlinx.coroutines.delay(200)
    } finally {
      CloudManager.resetInstance()
    }
  }

  @Test
  fun testCloudManagerRefreshWithRedisHandlerThrows() = runBlocking {
    CloudManager.resetInstance()
    try {
      val manager = CloudManager.getInstance()
      val redis =
          RedisManager.getInstance(
              SecurityConfigBuilder().apply { enableRedis = false }.build(),
          )
      manager.initializeCloudRedis(redis, providers = setOf("AWS"), ttl = 60)
      assertFailsWith<IllegalStateException> { manager.refresh(setOf("AWS")) }
    } finally {
      RedisManager.resetInstance()
      CloudManager.resetInstance()
    }
  }

  // ------------------------------------------------------------------
  // RedisManager URL + serialization tails
  // ------------------------------------------------------------------

  @Test
  fun testRedactRedisUrlShapes() {
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://[::1:7000"))
    assertEquals("garbage", redactRedisUrl("garbage"))
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://host:badport"))
    assertEquals("redis://host", redactRedisUrl("redis://host:"))
    assertEquals("redis://redacted:6379", redactRedisUrl("redis://h:pass@redacted:6379") ?: "x")
    // valueString shapes
    assertEquals("text", valueString("text"))
    assertEquals("raw", valueString("raw".encodeToByteArray()))
    assertEquals("42", valueString(42))
  }

  @Test
  fun testRedisManagerSingletonBookkeepingAndAgentFailure() = runBlocking {
    RedisManager.resetInstance()
    try {
      val config =
          SecurityConfigBuilder().apply {
            enableRedis = false
            redisMaxConnections = 3
          }.build()
      val first = RedisManager.getInstance(config)
      // second getInstance returns the existing manager with refreshed config
      val second = RedisManager.getInstance(config)
      assertTrue(first === second)
      // a failing agent sink is swallowed by the redis event sender
      val recording = RecordingAgent()
      recording.failWith = IllegalStateException("sink down")
      second.agentHandler = recording
      second.sendRedisEvent("guard.request", "blocked", "ip_banned", mapOf("k" to "v"))
      second.agentHandler = null
      second.close()
    } finally {
      RedisManager.resetInstance()
    }
  }

  // ------------------------------------------------------------------
  // RateLimitManager tails
  // ------------------------------------------------------------------

  @Test
  fun testRateLimitManagerSingletonAndInMemoryCount() = runBlocking {
    RateLimitManager.resetInstance()
    try {
      val config =
          SecurityConfigBuilder().apply { enableRedis = false }.build()
      val first = RateLimitManager.getInstance(config)
      val second = RateLimitManager.getInstance(config)
      assertTrue(first === second)
      val now = 1000.0
      val store = linkedMapOf<String, java.util.ArrayDeque<Double>>()
      val count = inMemoryRequestCount(store, "9.9.9.9", now - 60.0, now, endpointPath = "/x")
      assertEquals(0, count)
      // the first hit was recorded, so the second call counts it
      val count2 = inMemoryRequestCount(store, "9.9.9.9", now - 60.0, now + 1.0, endpointPath = "/x")
      assertEquals(1, count2)
    } finally {
      RateLimitManager.resetInstance()
    }
  }

  // ------------------------------------------------------------------
  // IpInfoManager
  // ------------------------------------------------------------------

  @Test
  fun testIpInfoManagerSingletonArmsAndCountryAccess() = runBlocking {
    IpInfoManager.resetInstance()
    try {
      val first = IpInfoManager.getInstance("tok", java.nio.file.Path.of("/tmp/w9d-a.mmdb"), 60)
      // second getInstance rebooks the existing instance
      val second = IpInfoManager.getInstance("tok2", java.nio.file.Path.of("/tmp/w9d-b.mmdb"), 120)
      assertTrue(first === second)
      assertEquals("tok2", second.token)
      assertEquals(java.nio.file.Path.of("/tmp/w9d-b.mmdb"), second.dbPath)
      assertEquals(120, second.maxAge)
      // empty token rejected
      assertFailsWith<IllegalArgumentException> { IpInfoManager.getInstance("") }
      // agent wiring
      second.initializeAgent(RecordingAgent() as com.guardcore.protocols.AgentHandlerProtocol)
      assertNotNull(second.agentHandler)
      // country access with a lookup override
      second.countryLookupOverride = { "DE" }
      val blocked = second.checkCountryAccess("1.2.3.4", listOf("DE"))
      assertEquals(false, blocked.first)
      val allowed = second.checkCountryAccess("1.2.3.4", listOf("FR"))
      assertEquals(true, allowed.first)
      val whitelisted = second.checkCountryAccess("1.2.3.4", emptyList(), listOf("FR"))
      assertEquals(false, whitelisted.first)
      second.countryLookupOverride = null
      // status + record + write failure shapes
      assertNotNull(second.getStatus())
      val record = MmdbCountryRecord("DE")
      assertEquals("DE", record.country)
      val dir =
          kotlin.io.path.createTempDirectory("w9d-ipinfo")
      val dbPath = dir.resolve("db.mmdb")
      val manager = IpInfoManager.getInstance("tok", dbPath, 60)
      assertFailsWith<Exception> { manager.writeDatabaseAtomically(ByteArray(4)) }
    } finally {
      IpInfoManager.resetInstance()
    }
  }

  @Test
  fun testIpInfoManagerDownloadRetryLoop() = runBlocking {
    IpInfoManager.resetInstance()
    try {
      val dir = kotlin.io.path.createTempDirectory("w9d-ipinfo-dl")
      val dbPath = dir.resolve("country.mmdb")
      val manager = IpInfoManager.getInstance("tok", dbPath, 3600)
      IpInfoManager.downloadRetries = 2
      var attempts = 0
      var seenUrl: String? = null
      manager.httpSendOverride = { url, _ ->
        attempts++
        seenUrl = url
        if (attempts == 1) {
          FakeIpInfoHttpResponse(503, ByteArray(0))
        } else {
          throw IllegalStateException("give up")
        }
      }
      // first attempt fails with a retryable status, second throws: the exception escapes
      assertFailsWith<IllegalStateException> { manager.downloadDatabase() }
      assertEquals(2, attempts)
      assertTrue(seenUrl!!.startsWith("https://ipinfo.io"))
      IpInfoManager.downloadRetries = IpInfoManager.DOWNLOAD_RETRIES
    } finally {
      IpInfoManager.Companion
      IpInfoManager.resetInstance()
    }
  }

  @Test
  fun testIpInfoManagerInitializeWithCachedStringDatabase() = runBlocking {
    IpInfoManager.resetInstance()
    try {
      val dir = kotlin.io.path.createTempDirectory("w9d-ipinfo-cache")
      val dbPath = dir.resolve("country.mmdb")
      val manager = IpInfoManager.getInstance("tok", dbPath, 3600)
      val redis = RecordingRedis(uniqueRedisPrefix())
      // a string database payload writes through and attempts to open (corrupt file removed)
      redis.getKeyReturns[Pair("ipinfo", "database")] = "not-a-real-mmdb"
      manager.redisHandler = redis
      manager.initialize()
      assertNull(manager.reader)
      assertTrue(manager.initializationAttempted)
      assertEquals(false, manager.isInitialized)
    } finally {
      IpInfoManager.resetInstance()
    }
  }

  // ------------------------------------------------------------------
  // SecurityHeadersManager tails
  // ------------------------------------------------------------------

  @Test
  fun testSecurityHeadersSingletonAndDefaultTables() = runBlocking {
    resetSecurityHeadersGlobalState()
    try {
      val first = SecurityHeadersManager.getInstance()
      val second = SecurityHeadersManager.getInstance()
      assertTrue(first === second)
      assertTrue(SecurityHeadersManager.DEFAULT_HEADERS.containsKey("X-Content-Type-Options"))
      val headers = first.getHeaders()
      assertTrue(headers.isNotEmpty())
      // a disabled header config produces no headers
      val disabled =
          first.getHeaders(
              config =
                  SecurityConfigBuilder()
                      .apply {
                        enableRedis = false
                        securityHeaders = mapOf("enabled" to false)
                      }
                      .build(),
          )
      assertTrue(disabled.isEmpty())
    } finally {
      resetSecurityHeadersGlobalState()
    }
  }

  // ------------------------------------------------------------------
  // HandlerSeams
  // ------------------------------------------------------------------

  @Test
  fun testHandlerSeamsReRegistrationAndGeoFactory() = runBlocking {
    // register is idempotent (a second call early-returns)
    HandlerSeams.register()
    // other tests may have swapped the factory; reinstall the seam shape under test
    val previous = ConfigSeams.geoIpHandlerFactory
    ConfigSeams.geoIpHandlerFactory = { token, dbPath, maxAge ->
      IpInfoManager.getInstance(token, dbPath, maxAge)
    }
    try {
      val handler = ConfigSeams.geoIpHandlerFactory!!.invoke("tok", null, 86400)
      assertTrue(handler is IpInfoManager)
    } finally {
      ConfigSeams.geoIpHandlerFactory = previous
      IpInfoManager.resetInstance()
    }
  }
}
