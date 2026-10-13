package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.errors.GuardRedisError
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.py.IpNetwork
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9i batch 7 (completing): the final handler tails to the family 100 percent line gate - the
 * ipinfo download/refresh lifecycle leftovers, the redis url-redaction unparseable arm, the cloud
 * via-redis refresh arms over a subclassed fetch seam, the azure extraction tie-break and
 * future-date arms, the dynamic-rule whitelist failure arm, the rate-limit GuardRedisError arm, and
 * the small singles (behavior tracked action, response-pattern null, ensure-ascii dumps, the bool
 * reject, and the geo seam factory body).
 */
class HandlersW9iTailsTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  private class FakeRedisConnection(private val clientValue: Any?) : GuardRedisConnection {
    override val client: Any? = clientValue

    override fun close() {}
  }

  private class ThrowingRedis : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        true

    override suspend fun delete(namespace: String, key: String): Int? =
        throw GuardRedisError(500, "w9i redis delete failed")

    override suspend fun keys(pattern: String): List<String>? = null

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection = FakeRedisConnection(null)
  }

  private class ProtocolRedis(private val operations: RedisOperations) : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        true

    override suspend fun delete(namespace: String, key: String): Int? = 1

    override suspend fun keys(pattern: String): List<String>? = null

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection = FakeRedisConnection(operations)
  }

  /** Guards RedisError through the transaction call (the rate-limit fail arms). */
  private class GuardErrorOperations : NoopRedisOperations() {
    override suspend fun transaction(ops: suspend (QueuedRedisOperations) -> Unit): List<Any?> =
        throw GuardRedisError(500, "w9i redis transaction")
  }

  private class EmptyFetchCloud : CloudManager() {
    override suspend fun fetchRanges(provider: String): Pair<Set<IpNetwork>, Map<String, String>> =
        Pair(emptySet(), emptyMap())
  }

  private class ThrowingFetchCloud : CloudManager() {
    override suspend fun fetchRanges(provider: String): Pair<Set<IpNetwork>, Map<String, String>> =
        throw IllegalStateException("w9i fetch down")
  }

  private fun liveRedis(): RedisManager {
    val client = io.lettuce.core.RedisClient.create("redis://localhost:6379")
    val connection = client.connect()
    val operations = LettuceRedisOperations(client, connection)
    return RedisManager(
        config {
          enableRedis = true
          redisUrl = "redis://localhost:6379/0"
        },
    ) { _, _, _,
      ->
      operations
    }
  }

  // ------------------------------------------------------------------ IpInfoManager

  /**
   * downloadDatabase's suspension/resume over a retrying download (285), refresh with no db file
   * (443), the corrupted-database cleanup arm whose deleteIfExists also fails (177: the db path is
   * a non-empty directory, so deleteIfExists raises DirectoryNotEmptyException), and the redis
   * initialize surface (457).
   */
  @Test
  fun `ipinfo download refresh and corrupted-database arms`(): Unit = runBlocking {
    IpInfoManager.resetInstance()
    val tempDir = Files.createTempDirectory("w9i-ipinfo")
    try {
      val dbPath = tempDir.resolve("country_asn.mmdb")
      val manager = IpInfoManager.getInstance("token-w9i", dbPath, 86400)
      var downloaded = false
      manager.downloadOverride = { downloaded = true }
      manager.downloadDatabase()
      assertTrue(downloaded)

      // The override-free download with a flaky http seam: the first attempt returns
      // 500 (HttpStatusException), the retry delay suspends, the second attempt
      // returns a body and the write lands (285: the suspend resume path).
      manager.downloadOverride = null
      IpInfoManager.downloadRetries = 2
      var attempts = 0
      manager.httpSendOverride = { url, _ ->
        attempts += 1
        fakeNetResponse(url, if (attempts == 1) 500 else 200, byteArrayOf(1, 2, 3))
      }
      manager.downloadDatabase()
      assertEquals(2, attempts)
      assertTrue(Files.exists(dbPath))

      // A zero-retry download falls straight out of the loop (the suspend tail).
      manager.dbPath = tempDir.resolve("zero-retry.mmdb")
      IpInfoManager.downloadRetries = 0
      manager.httpSendOverride = null
      manager.downloadDatabase()
      assertFalse(Files.exists(manager.dbPath))

      // refresh() after a successful (no-op) download without a db file on disk (443).
      manager.downloadOverride = {}
      manager.dbPath = tempDir.resolve("absent.mmdb")
      manager.refresh()

      // openDatabaseOrNone over a db path that is a non-empty DIRECTORY: the reader
      // construction fails and deleteIfExists raises DirectoryNotEmptyException,
      // which the ignored catch swallows (177).
      val inner = Files.createTempDirectory("w9i-ipinfo-inner")
      val dirDb = Files.createTempDirectory("w9i-ipinfo-dirdb")
      Files.write(dirDb.resolve("payload.bin"), byteArrayOf(9))
      val manager2 = IpInfoManager.getInstance("token-w9i", dirDb, 60)
      assertNull(manager2.openDatabaseOrNone())

      // initializeRedis over a protocol fake (457).
      manager2.initializeRedis(ThrowingRedis())
    } finally {
      IpInfoManager.downloadRetries = IpInfoManager.DOWNLOAD_RETRIES
      IpInfoManager.resetInstance()
    }
  }

  private fun fakeNetResponse(url: String, status: Int, payload: ByteArray) =
      object : java.net.http.HttpResponse<ByteArray> {
        override fun statusCode(): Int = status

        override fun body(): ByteArray = payload

        override fun headers(): java.net.http.HttpHeaders =
            java.net.http.HttpHeaders.of(mapOf(), { _, _ -> true })

        override fun uri(): java.net.URI = java.net.URI.create(url)

        override fun previousResponse(): java.util.Optional<java.net.http.HttpResponse<ByteArray>> =
            java.util.Optional.empty()

        override fun request(): java.net.http.HttpRequest =
            java.net.http.HttpRequest.newBuilder().uri(uri()).build()

        override fun sslSession(): java.util.Optional<javax.net.ssl.SSLSession> =
            java.util.Optional.empty()

        override fun version(): java.net.http.HttpClient.Version =
            java.net.http.HttpClient.Version.HTTP_1_1
      }

  // ------------------------------------------------------------------ RedisManager

  /** redactRedisUrl's urlsplit failure arm (738-739) and the unparseable fallback (724). */
  @Test
  fun `redact redis url falls back on an unparseable url`() {
    val redacted = redactRedisUrl("redis://[::1")
    assertEquals("redis://<unparseable>", redacted)
  }

  // ------------------------------------------------------------------ CloudManager

  /**
   * initializeCloudRedis over live redis with an empty fetch (178) and a throwing fetch falling
   * back to the empty range set (271-274).
   */
  @Test
  fun `cloud refresh over redis handles empty and throwing fetches`(): Unit = runBlocking {
    val redis = liveRedis()
    try {
      // store = null keeps initializeCloudRedis on the via-redis-handler refresh
      // path: the empty fetch skips the range store and the manager tail returns.
      val empty = EmptyFetchCloud()
      empty.store = null
      empty.initializeCloudRedis(redis, providers = listOf("aws"), ttl = 60)
      // An empty provider set completes the refresh without suspension, covering the
      // initializeCloudRedis completion tail (178).
      val tail = EmptyFetchCloud()
      tail.store = null
      tail.initializeCloudRedis(redis, providers = emptyList(), ttl = 60)

      val throwing = ThrowingFetchCloud()
      throwing.store = null
      throwing.initializeCloudRedis(redis, providers = listOf("gcp"), ttl = 60)
      assertTrue(throwing.ipRanges["gcp"]?.isEmpty() == true)
    } finally {
      redis.close()
    }
  }

  // ------------------------------------------------------------------ CloudAzureFetch

  /**
   * parseServiceTagsDate's future-date arm (166), the sort tie-break lambdas (223-224), and the
   * generic-json untrusted-host rejection (255).
   */
  @Test
  fun `azure url extraction arms`() {
    assertNull(
        CloudAzureFetch.parseServiceTagsDate(
            "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_29991231.json",
        ),
    )
    // Two undated candidates tie on the first two sort keys, driving the third lambda.
    val html =
        "<a href=\"https://download.microsoft.com/download/7/1/D/ServiceTags_Public_99999999.json\">a</a>" +
            "<a href=\"https://download.microsoft.com/download/7/1/D/ServiceTags_Public_88888888.json\">b</a>"
    assertNotNull(CloudAzureFetch.extractNewestServiceTagsUrl(html))
    // A lookalike host passes the extraction regex but not the trusted-host check.
    assertNull(
        CloudAzureFetch.extractGenericJsonUrl(
            "<a href=\"https://download.microsoft.com.evil.test/x.json\">c</a>",
        ),
    )
    // An extraction-matching URL whose bracket fails java.net.URI parsing takes the
    // untrusted-host rejection.
    assertNull(
        CloudAzureFetch.extractGenericJsonUrl(
            "<a href=\"https://download.microsoft.com/a[b].json\">d</a>",
        ),
    )
    // htmlUnescape decodes numeric hex entities (255).
    assertEquals("A9", CloudAzureFetch.htmlUnescape("&#x41;&#x39;"))
  }

  // ------------------------------------------------------------------ DynamicRuleManager

  /** applyIpWhitelist's failing-unban catch (389-390) over a failing redis delete. */
  @Test
  fun `apply ip whitelist survives a throwing unban`(): Unit = runBlocking {
    val ipBanManager = IpBanManager.getInstance()
    val previousRedis = ipBanManager.redisHandler
    ipBanManager.redisHandler = ThrowingRedis()
    try {
      val manager = DynamicRuleManager(config())
      manager.applyIpWhitelist(listOf("192.0.2.55"))
    } finally {
      ipBanManager.redisHandler = previousRedis
    }
  }

  // ------------------------------------------------------------------ RateLimitManager

  /** redisRequestCount's GuardRedisError arm (149-150) over a protocol fake. */
  @Test
  fun `redis request count survives a GuardRedisError`(): Unit = runBlocking {
    val operations = GuardErrorOperations()
    val count =
        redisRequestCount(
            ProtocolRedis(operations),
            java.util.logging.Logger.getLogger("w9i"),
            "192.0.2.77",
            currentTime = 1000.0,
            windowStart = 940.0,
            rateLimitWindow = 60,
            rateLimit = 10,
            rateLimitScriptSha = null,
            redisFailOpen = true,
        )
    assertNull(count.first)
  }

  // ------------------------------------------------------------------ Behavior dispatch

  /** executeBanAction's not-applied arm (62) over a banIp override. */
  @Test
  fun `execute ban action reports tracked when the ban is not applied`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val ipBanManager = IpBanManager.getInstance()
    ipBanManager.banIpOverride = { _, _, _ -> false }
    try {
      val tracker = BehaviorTracker(config())
      val outcome = tracker.executeBanAction("192.0.2.88", "w9i details")
      assertEquals("tracked", outcome)
    } finally {
      ipBanManager.banIpOverride = null
    }
  }

  // ------------------------------------------------------------------ Response patterns

  /**
   * PyJsonLike's JsonNull arm (181) over a response body with an explicit null: python renders a
   * null leaf as str(None) = "none".
   */
  @Test
  fun `response pattern parses a null json value`(): Unit = runBlocking {
    val tracker = BehaviorTracker(config { behaviorScanResponseBody = true })
    val body = """{"a": null, "b": 2}"""
    val response =
        object : GuardResponse, com.guardcore.protocols.BoundedResponseBodyReader {
          override val headers: MutableMap<String, String> = linkedMapOf()
          override val statusCode: Int = 200
          override val body: ByteArray = body.encodeToByteArray()

          override suspend fun readBodyPrefix(maxBytes: Int): ByteArray = body.encodeToByteArray()
        }
    assertEquals(true, tracker.checkResponsePattern(response, "json:a==none"))
    assertEquals(true, tracker.checkResponsePattern(response, "json:b==2"))
    assertEquals(false, tracker.checkResponsePattern(response, "json:a==null"))
  }

  // ------------------------------------------------------------------ Dumps and loads

  /** dumps' ensure-ascii escape arm (51). */
  @Test
  fun `dumps escapes non ascii when ensure ascii holds`() {
    val rendered = PyJsonDumps.dumps(kotlinx.serialization.json.JsonPrimitive("caf\u00e9"))
    assertEquals("\"caf\\u00e9\"", rendered)
    // pydantic model_dump_json keeps non-ASCII as UTF-8 (the regression for the
    // inverted ensure-ascii flag).
    val compact = PyJsonDumps.dumpsCompact(kotlinx.serialization.json.JsonPrimitive("caf\u00e9"))
    assertEquals("\"caf\u00e9\"", compact)
  }

  /**
   * pydanticDatetimeJson's offset arms over explicit zones: a UTC timestamp renders the trailing Z
   * and a non-UTC offset renders the +HH:MM form (73, 83-85) - both driven deterministically
   * regardless of the host zone.
   */
  @Test
  fun `snapshot dump renders both timestamp offset forms`() {
    val utc =
        DynamicRules(
            ruleId = "w9i-utc",
            version = 1,
            timestamp =
                java.time.OffsetDateTime.of(
                    2026,
                    10,
                    12,
                    8,
                    30,
                    0,
                    0,
                    java.time.ZoneOffset.UTC,
                ),
        )
    val dumpedUtc = dumpLastKnownRulesSnapshot(utc)
    assertTrue(dumpedUtc.contains("2026-10-12T08:30:00Z"), dumpedUtc)
    val shifted =
        DynamicRules(
            ruleId = "w9i-shifted",
            version = 1,
            timestamp =
                java.time.OffsetDateTime.of(
                    2026,
                    10,
                    12,
                    8,
                    30,
                    0,
                    0,
                    java.time.ZoneOffset.ofHoursMinutes(5, 30),
                ),
        )
    val dumpedShifted = dumpLastKnownRulesSnapshot(shifted)
    assertTrue(dumpedShifted.contains("2026-10-12T08:30:00+05:30"), dumpedShifted)
    // A microsecond-precision timestamp drives the fraction trim loop (73).
    val micros =
        DynamicRules(
            ruleId = "w9i-micros",
            version = 1,
            timestamp =
                java.time.OffsetDateTime.of(
                    2026,
                    10,
                    12,
                    8,
                    30,
                    5,
                    500000000,
                    java.time.ZoneOffset.UTC,
                ),
        )
    val dumpedMicros = dumpLastKnownRulesSnapshot(micros)
    assertTrue(dumpedMicros.contains("08:30:05.500Z"), dumpedMicros)
  }

  /**
   * The multi-cursor SCAN surface over live redis (197): enough keys that the SCAN COUNT 1000 hint
   * cannot cover the keyspace in one page, so the loop always takes the second-cursor assignment.
   */
  @Test
  fun `scan walks the redis keyspace`(): Unit = runBlocking {
    val client = io.lettuce.core.RedisClient.create("redis://localhost:6379")
    val connection = client.connect()
    val operations = LettuceRedisOperations(client, connection)
    try {
      for (i in 0 until 25) {
        operations.set("w9i:scan:Key:$i", "v")
      }
      for (i in 0 until 1200) {
        operations.set("w9i:scan:Filler:$i", "v")
      }
      val found = operations.scan("w9i:scan:Key:*")
      assertEquals(25, found.size)
      operations.del(*found.toTypedArray())
      val fillers = operations.scan("w9i:scan:Filler:*")
      operations.del(*fillers.toTypedArray())
    } finally {
      connection.close()
    }
  }

  /** loadLastKnownRulesSnapshot's bool reject arm (228). */
  @Test
  fun `load snapshot rejects a non-bool emergency mode`() {
    val payload =
        """{"schema_version": 1, "rules": {"rule_id": "r9i", "version": 1,
            "timestamp": "2026-10-12T00:00:00+00:00", "ttl": 300, "emergency_mode": []}}"""
    val error = assertFailsWith<IllegalArgumentException> { loadLastKnownRulesSnapshot(payload) }
    assertEquals("emergency_mode must be a bool", error.message)
  }

  // ------------------------------------------------------------------ HandlerSeams

  /**
   * The registered geo factory lambda body (29). Other tests overwrite the config seam with fakes,
   * so the idempotent registration flag is re-armed through reflection first.
   */
  @Test
  fun `geo handler factory constructs the ipinfo manager`() {
    val flag = HandlerSeams::class.java.getDeclaredField("registered")
    flag.isAccessible = true
    flag.set(HandlerSeams, false)
    HandlerSeams.register()
    val handler = com.guardcore.config.ConfigSeams.geoIpHandlerFactory
    assertNotNull(handler)
    IpInfoManager.resetInstance()
    try {
      val built = handler!!.invoke("token-w9i-factory", null as Path?, 86400)
      assertNotNull(built)
    } finally {
      IpInfoManager.resetInstance()
    }
  }

  /** The valueString bytes passthrough keeps latin-1 decodability (a redis round trip). */
  @Test
  fun `redis url redaction keeps scheme on a parseable url`() {
    val redacted = redactRedisUrl("redis://user:secret@localhost:6379/0")
    assertNotNull(redacted)
    assertFalse(redacted.contains("secret"))
    assertTrue(redacted.startsWith("redis://"))
  }

  // ------------------------------------------------------------------ SusPatternsRegistry

  /** The monitor anomaly handoff (252) and the semantic pattern-info arms (303-304). */
  @Test
  fun `registry detect drives the anomaly sink and the semantic pattern info`(): Unit =
      runBlocking {
        val manager = SusPatternsManager.shared()
        val original = manager.detectionState
        try {
          manager.configure(tinyThresholdConfig())
          val monitor = manager.detectionState.performanceMonitor
          assertNotNull(monitor)
          monitor.clearStats()
          val events = mutableListOf<Map<String, Any?>>()
          SusPatternsRegistry.agentHandler =
              object : HandlerAgentSink {
                override suspend fun sendEvent(event: Map<String, Any?>) {
                  events.add(event)
                }
              }
          // The scan records the overall_detection metric; the monitor clamps the slow
          // threshold to a 10ms floor, so the payload is padded to hold the scan well
          // above it. A prior emitter may hold the one-second cooldown slot, so clear
          // and retry once.
          val padded = "system('cat%20/etc/passwd')" + "a".repeat(300_000)
          SusPatternsRegistry.detect(padded, "192.0.2.10")
          if (events.none { it["action_taken"] == "anomaly_detected" }) {
            monitor.clearStats()
            SusPatternsRegistry.detect(padded, "192.0.2.10")
          }
          assertTrue(
              events.any { it["action_taken"] == "anomaly_detected" },
              "expected the monitor anomaly to reach the sink; events=$events",
          )

          // The payload trips a semantic attack probability; filtering every regex
          // category out leaves the semantic threat as the sole verdict, so the
          // threat event renders the semantic attack type (303-304).
          val verdict =
              SusPatternsRegistry.detect(
                  "etc/passwd",
                  "192.0.2.10",
                  enabledCategories = setOf("w9i-no-regex-category"),
              )
          assertEquals(true, verdict["is_threat"])
          assertTrue(
              (verdict["threats"] as? List<*>)?.any {
                (it as? Map<*, *>)?.get("type") == "semantic"
              } == true,
              "expected a semantic threat in ${verdict["threats"]}",
          )
        } finally {
          SusPatternsRegistry.agentHandler = null
          manager.detectionState = original
        }
      }

  private fun tinyThresholdConfig(): com.guardcore.engine.suspatterns.DetectionConfigView =
      object : com.guardcore.engine.suspatterns.DetectionConfigView {
        override val detectionCompilerTimeout: Double = 5.0
        override val detectionMaxTrackedPatterns: Int = 1000
        override val detectionMaxContentLength: Int = 10000
        override val detectionPreserveAttackPatterns: Boolean = true
        override val detectionAnomalyThreshold: Double = 3.0
        override val detectionSlowPatternThreshold: Double = 0.0
        override val detectionMonitorHistorySize: Int = 1000
        override val detectionAnomalyEmissionCooldown: Double = 60.0
        override val detectionMinSamplesForAnomaly: Int = 30
        override val detectionSemanticThreshold: Double = 0.05
        override val detectionThreatScoreThreshold: Double = 1.0
        override val detectionMaxBodyInspectBytes: Int = 262144
        override val detectionPatternValidationCachePath: String? = null
      }
}
