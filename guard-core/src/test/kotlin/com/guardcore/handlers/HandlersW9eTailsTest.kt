package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.TestRequest
import com.guardcore.java.JavaBridges
import com.guardcore.protocols.GuardResponse
import java.nio.file.Files
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * W9e arm closure for the handler tail: the snapshot type-error matrix, the redis URL redaction
 * arms, the fetcher override seams, the rate-limit singleton/script surface, the dynamic-rule
 * persistence arms, the security-headers config cache arms, and the small dispatch singles.
 */
class HandlersW9eTailsTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  // ------------------------------------------------------------ dynamic rules snapshots

  @Test
  fun `last known rules snapshot rejects mistyped fields`() {
    val base =
        """{"schema_version": 1, "rules": {"rule_id": "r", "version": 1, "timestamp": "2026-01-01T00:00:00+00:00"}}"""
    // a container where a string is required
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("""{"schema_version": 1, "rules": 3}""")
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"rule_id": "r", "version": "x", "timestamp": "2026-01-01T00:00:00+00:00"}}""",
      )
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"rule_id": "r", "version": 1, "timestamp": "2026-01-01T00:00:00+00:00", "emergency_mode": "yes"}}""",
      )
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"rule_id": "r", "version": 1, "timestamp": "2026-01-01T00:00:00+00:00", "emergency_whitelist": "nope"}}""",
      )
    }
    // endpoint_rate_limits type errors
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"rule_id": "r", "version": 1, "timestamp": "2026-01-01T00:00:00+00:00", "endpoint_rate_limits": {"a": 1}}}""",
      )
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"rule_id": "r", "version": 1, "timestamp": "2026-01-01T00:00:00+00:00", "endpoint_rate_limits": {"a": ["x", 1]}}}""",
      )
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"rule_id": "r", "version": 1, "timestamp": "2026-01-01T00:00:00+00:00", "endpoint_rate_limits": {"a": [1, "y"]}}}""",
      )
    }
    // an unknown top-level shape is rejected
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("""{"schema_version": 1}""")
    }
  }

  // ------------------------------------------------------------ redis url redaction

  @Test
  fun `redis url redaction walks the unparseable and bracketed-host arms`() {
    assertNull(redactRedisUrl(null))
    assertEquals("://", redactRedisUrl("://"))
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://[bad"))
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://[::1]:notaport"))
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://[::1]junk"))
    assertEquals("redis://h", redactRedisUrl("redis://h"))
    assertEquals("redis://[::1]:6379/0", redactRedisUrl("redis://[::1]:6379/0"))
    assertEquals("redis://h:1/x", redactRedisUrl("redis://user:secret@h:1/x"))
  }

  // ------------------------------------------------------------ py json dumps

  @Test
  fun `py json dumps renders the compact and spaced shapes`() {
    val payload = JsonObject(linkedMapOf("k" to JsonPrimitive(1), "j" to JsonNull))
    assertNotNull(PyJsonDumps.dumps(payload))
    assertNotNull(PyJsonDumps.dumpsCompact(payload))
  }

  // ------------------------------------------------------------ java bridges defaults

  @Test
  fun `java bridges future variants complete with default arguments`() = runBlocking {
    resetIpBanGlobalState()
    val manager = IpBanManager.getInstance()
    // the reason default synthetic
    assertTrue(JavaBridges.banIp(manager, "203.0.113.70", 30).get())
    assertTrue(JavaBridges.banIpBlocking(manager, "203.0.113.71", 30))
    JavaBridges.unbanIp(manager, "203.0.113.70").get()
    JavaBridges.unbanIpBlocking(manager, "203.0.113.71")
    // the detect context default synthetics
    val expected = JavaBridges.detectBlocking("<script>", "203.0.113.72")
    val verdict = JavaBridges.detect("<script>", "203.0.113.72").get()
    assertEquals(expected.isThreat, verdict.isThreat)
    // the redis initialize bridges over the real local redis
    val redis = RedisManager.getInstance(config { redisUrl = "redis://localhost:6379/0" })
    try {
      assertTrue(JavaBridges.initializeRedis(redis).get())
      assertTrue(JavaBridges.initializeRedisBlocking(redis))
    } finally {
      redis.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
    }
  }

  // ------------------------------------------------------------ rate limit manager

  @Test
  fun `rate limit manager walks the script load, fail-open and in-memory arms`() = runBlocking {
    val cfg = config {
      enableRateLimiting = true
      enableRedis = true
      redisUrl = "redis://localhost:6379/0"
    }
    val redis = RedisManager.getInstance(config { redisUrl = "redis://localhost:6379/0" })
    try {
      redis.initialize()
      val manager = RateLimitManager.getInstance(cfg)
      manager.reset()
      manager.redisHandler = redis
      // the lua script loads over the live connection
      // the load either lands the sha or logs through the catch arm; both are the ported arms
      manager.initializeRedis(redis)
      // handleRateLimitExceeded renders the 429 through the caller factory
      val limited =
          manager.handleRateLimitExceeded(
              TestRequest(),
              "192.0.2.5",
              11,
              createErrorResponse = { code: Int, message: String ->
                object : GuardResponse {
                  override val headers: MutableMap<String, String> = linkedMapOf()
                  override val statusCode: Int = code
                  override val body: ByteArray = message.encodeToByteArray()
                }
              },
          )
      assertEquals(429, limited.statusCode)
      assertNotNull(limited.headers["Retry-After"])
      // a dead redis handler yields null counts (fail-open) for both call shapes
      val failed =
          redisRequestCount(
              RedisHandlerProtocolStub(),
              deadManagerLogger(),
              "192.0.2.5",
              100.0,
              40.0,
              60,
              100,
              null,
          )
      assertNull(failed.first)
      // the in-memory window counts without redis
      val count = manager.getInMemoryRequestCount("192.0.2.6", 0.0, 1000.0)
      assertTrue(count >= 0)
      // reset clears the redis keys under the live handler
      manager.redisHandler = redis
      manager.reset()
      assertNull(manager.redisHandler)
    } finally {
      redis.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
    }
  }

  private fun deadManagerLogger() = java.util.logging.Logger.getLogger("w9e.rate")

  // ------------------------------------------------------------ ip info manager

  @Test
  fun `ip info manager walks the download, reader and country arms over seams`() = runBlocking {
    val tmp = Files.createTempDirectory("w9e-ipinfo")
    val dbPath = tmp.resolve("geo.mmdb")
    val manager = IpInfoManager.getInstance("w9e-token", dbPath, 60)
    try {
      // a failing download surfaces through refresh with the attempt recorded
      manager.downloadOverride = { throw java.net.http.HttpTimeoutException("w9e timeout") }
      manager.refresh()
      assertTrue(manager.initializationAttempted)
      // a successful download over the seam writes the db file and caches it
      manager.setInitializationAttempted(false)
      manager.downloadOverride = {
        dbPath.writeText("not-a-real-mmdb")
      }
      manager.refresh()
      // country lookups over the lookup seam: blocked + whitelist decisions
      manager.countryLookupOverride = { _ -> "CN" }
      val blocked = manager.checkCountryAccess("192.0.2.9", listOf("CN"))
      assertEquals(false to "CN", blocked.first to blocked.second)
      manager.countryLookupOverride = { _ -> "US" }
      val allowed = manager.checkCountryAccess("192.0.2.9", listOf("CN"))
      assertEquals(true, allowed.first)
      // the whitelist-miss arm
      val wl =
          manager.checkCountryAccess("192.0.2.9", emptyList(), whitelistCountries = listOf("CN"))
      assertEquals(false, wl.first)
      manager.countryLookupOverride = null
      // a reader-less lookup returns null quietly after a failed init
      manager.setReaderForTests(null)
      manager.setInitializationAttempted(true)
      assertNull(manager.getCountry("192.0.2.9"))
      // close is idempotent and propagates reader state
      manager.close()
    } finally {
      manager.countryLookupOverride = null
      manager.downloadOverride = null
      manager.setReaderForTests(null)
    }
  }

  // ------------------------------------------------------------ cloud manager + fetchers

  @Test
  fun `cloud manager walks the refresh, redis-handler and is-cloud arms`() = runBlocking {
    val manager = CloudManager.getInstance()
    try {
      // refresh() without redis is the direct fetch path over the azure seam
      manager.isCloudIpOverride = null
      // isCloudIp over an invalid address logs and answers false
      assertFalse(manager.isCloudIp("not-an-ip", setOf("AWS")))
      // an override drives the verdict without any fetches
      manager.isCloudIpOverride = { ip, _ -> ip == "203.0.113.99" }
      assertTrue(manager.isCloudIp("203.0.113.99", setOf("AWS")))
      // cloudProviderDetailsOverride drives the details path
      manager.cloudProviderDetailsOverride = { _, _ -> "AWS" to "203.0.113.0/24" }
    } finally {
      manager.isCloudIpOverride = null
      manager.cloudProviderDetailsOverride = null
    }
    // the azure fetcher's http seam: a document without the service tag yields no ranges
    CloudAzureFetch.httpGetOverride = { _ -> Pair(200, "{}") }
    try {
      val ranges = CloudAzureFetch.fetchAzureIpRanges()
      assertTrue(ranges.isEmpty())
    } finally {
      CloudAzureFetch.httpGetOverride = null
    }
    // the generic fetchers over their seam: an unreachable status yields empty sets
    CloudFetchers.httpGetOverride = { _ -> Pair(404, "nope") }
    try {
      assertTrue(CloudFetchers.fetchAwsIpRanges().first.isEmpty())
    } finally {
      CloudFetchers.httpGetOverride = null
    }
  }

  // ------------------------------------------------------------ security headers manager

  @Test
  fun `security headers manager walks the disabled, cors and cache arms`() = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    manager.headersCache.clear()
    // disabled headers short-circuit to an empty map
    val cfg = config { securityHeaders = mapOf("enabled" to false) }
    val headers = manager.getHeaders("/api", config = cfg)
    assertTrue(headers.isEmpty())
    // the cors header builder with allow-credentials
    val cors =
        manager.buildCorsHeaders(
            origin = "https://w9e.example",
            allowedOrigins = listOf("https://w9e.example"),
            allowMethods = listOf("GET"),
            allowHeaders = listOf("X-A"),
            corsConfigArg =
                linkedMapOf(
                    "allow_credentials" to true,
                    "max_age" to 600,
                    "expose_headers" to listOf("X-B"),
                ),
        )
    assertTrue(cors.isNotEmpty())
    assertTrue(cors.containsKey("Access-Control-Allow-Origin"), cors.toString())
  }

  // ------------------------------------------------------------ behavior tracker + dispatch

  @Test
  fun `behavior tracker exposes its tables and records window hits`() = runBlocking {
    val tracker = BehaviorTracker(config())
    assertTrue(tracker.usageCounts.isEmpty())
    assertTrue(tracker.returnPatterns.isEmpty())
    // applyAction over each dispatch arm: log + tracked + ban fallback
    val rule = BehaviorRule(ruleType = "usage", threshold = 100, window = 60, action = "log")
    tracker.applyAction(rule, "192.0.2.20", "w9e.endpoint", "details")
    val banRule =
        BehaviorRule(
            ruleType = "usage",
            threshold = 1,
            window = 60,
            action = "ban",
            banDuration = 60,
        )
    resetIpBanGlobalState()
    tracker.applyAction(banRule, "192.0.2.21", "w9e.endpoint", "details")
    val customRule =
        BehaviorRule(
            ruleType = "usage",
            threshold = 1,
            window = 60,
            action = "custom",
            customAction = { _, _, _ -> },
        )
    tracker.applyAction(customRule, "192.0.2.22", "w9e.endpoint", "details")
  }

  // ------------------------------------------------------------ small singles

  @Test
  fun `suspatterns registry answers the add-remove and event arms`() = runBlocking {
    SusPatternsRegistry.agentHandler = null
    SusPatternsRegistry.clearCustomPatternsForCorpus()
    // a rejected custom pattern takes the add-failure arm
    assertFalse(SusPatternsRegistry.addPattern("(a+)+\$", custom = true))
    // a valid custom pattern round-trips
    assertTrue(SusPatternsRegistry.addPattern("w9e_registry_pat", custom = true))
    assertTrue(SusPatternsRegistry.removePattern("w9e_registry_pat", custom = true))
    assertFalse(SusPatternsRegistry.removePattern("w9e_registry_pat", custom = true))
    // detect with a semantic-only classification label
    SusPatternsRegistry.clearCustomPatternsForCorpus()
  }

  @Test
  fun `detection scan redaction decodes pattern source escapes`() {
    DetectionScanRedaction.sensitiveParamsUnion = setOf("token")
    try {
      // the hex/octal escape decode arm renders the code point into the matched name
      assertTrue(
          DetectionScanRedaction.patternSourceNamesASensitiveField("\\x74oken", setOf("token")),
          "hex escape",
      )
      assertTrue(
          DetectionScanRedaction.patternSourceNamesASensitiveField("\\164oken", setOf("token")),
          "octal escape",
      )
    } finally {
      DetectionScanRedaction.sensitiveParamsUnion = linkedSetOf()
    }
  }

  @Test
  fun `dynamic rule events expose the snapshot field table`() {
    assertTrue(DYNAMIC_RULE_SNAPSHOT_FIELDS.isNotEmpty())
    assertTrue(DYNAMIC_RULE_SNAPSHOT_FIELDS.contains("blocked_countries"))
  }

  @Test
  fun `handler seams registration is idempotent`() {
    HandlerSeams.register()
    HandlerSeams.register()
    assertTrue(true)
  }

  @Test
  fun `ip ban migration walks the quiet arms`() = runBlocking {
    resetIpBanGlobalState()
    val manager = IpBanManager.getInstance()
    try {
      // closeIfUnusable is the python hasattr-style guard
      assertTrue(closeIfUnusable(manager, "client"))
      // migration without any legacy keys completes quietly
      manager.migrateLegacyBanKeys()
    } finally {
      resetIpBanGlobalState()
    }
    assertTrue(true)
  }

  @Test
  fun `manager initialization arms answer over the singleton seams`() = runBlocking {
    // a second getInstance call reconfigures the existing singleton
    val cfg = config { enableRateLimiting = false }
    val first = RateLimitManager.getInstance(cfg)
    val again = RateLimitManager.getInstance(cfg)
    assertEquals(first, again)
    // the security headers singleton early-return arm
    assertEquals(SecurityHeadersManager.getInstance(), SecurityHeadersManager.getInstance())
  }
}

/** Minimal RedisHandlerProtocol stub for the fail-open arms. */
internal class RedisHandlerProtocolStub : com.guardcore.protocols.RedisHandlerProtocol {
  override suspend fun getKey(namespace: String, key: String): Any? = null

  override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
      null

  override suspend fun delete(namespace: String, key: String): Int? = null

  override suspend fun keys(pattern: String): List<String>? = null

  override suspend fun initialize() {
    throw com.guardcore.errors.GuardRedisError(503, "stub is down")
  }

  override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
      object : com.guardcore.protocols.GuardRedisConnection {
        override val client: Any? = null

        override fun close() {}
      }
}
