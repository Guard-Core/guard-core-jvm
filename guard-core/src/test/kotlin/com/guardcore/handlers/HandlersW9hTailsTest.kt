package com.guardcore.handlers

import com.guardcore.config.ConfigSeams
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.TestRequest
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.errors.GuardRedisError
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.AccessControl
import io.lettuce.core.RedisException
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * W9h batch 6: the final handler tails to the family 100 percent line gate - the dynamic-rule
 * persistence internals (snapshot load/persist arms), the cloud refresh arms over the fetch seam,
 * the security-headers cache-failure arms, the ipinfo reader-lifecycle leftovers, the redis
 * redaction/connection arms, the rate-limit reset/event arms, the behavior sliding-window protocol
 * path, and the response-pattern decode arms.
 */
class HandlersW9hTailsTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  /** A throwing HandlerAgentSink for the event-failure arms. */
  private class ThrowingAgent : HandlerAgentSink {
    override suspend fun sendEvent(event: Map<String, Any?>) {
      throw IllegalStateException("agent down")
    }
  }

  private class FakeRedisConnection(private val clientValue: Any?) : GuardRedisConnection {
    override val client: Any? = clientValue

    override fun close() {}
  }

  /** A protocol fake whose raw client is the given (possibly non-redis) value. */
  private class ScriptedRedis(private val clientValue: Any?) : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        true

    override suspend fun delete(namespace: String, key: String): Int? = 1

    override suspend fun keys(pattern: String): List<String>? = listOf("a", "b")

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection = FakeRedisConnection(clientValue)
  }

  private class ThrowingRedis : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? =
        throw IllegalStateException("redis read failed")

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        throw IllegalStateException("redis write failed")

    override suspend fun delete(namespace: String, key: String): Int? = 1

    override suspend fun keys(pattern: String): List<String>? =
        throw IllegalStateException("redis keys failed")

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection = FakeRedisConnection(null)
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

  // ------------------------------------------------------------------ DynamicRuleManager

  /** The update-loop generic catch + the interruptible-sleep timeout arm (134-136, 147-150). */
  @Test
  fun `update loop recovers from a throwing agent`(): Unit = runBlocking {
    DynamicRuleManager.resetInstance()
    // validateFields=false mirrors fromConfig: the loop needs a sub-floor interval so the
    // sleep timeout arm fires inside the test budget.
    val builder = SecurityConfigBuilder()
    builder.validateFields = false
    builder.enableDynamicRules = true
    builder.enableAgent = true
    builder.agentApiKey = "w9h"
    builder.dynamicRuleInterval = 1
    val cfg = builder.build()
    val manager = DynamicRuleManager.getInstance(cfg)
    val agent =
        object : DynamicRuleManager.AgentDynamicRulesSource {
          override suspend fun getDynamicRules(): DynamicRules? =
              throw IllegalStateException("agent unavailable")

          override suspend fun sendEvent(event: Map<String, Any?>) {}
        }
    try {
      manager.initializeAgent(agent)
      // One loop pass hits the update catch and then the interval timeout.
      delay(1500)
    } finally {
      manager.stop()
      DynamicRuleManager.resetInstance()
    }
  }

  /** match_event's user_agent_blocked arm (182). */
  @Test
  fun `match event reads blocked user agents`() {
    val manager = DynamicRuleManager(config())
    manager.currentRules =
        DynamicRules(
            ruleId = "r1",
            version = 1,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
            blockedUserAgents = listOf("curl"),
        )
    assertEquals(
        "r1" to 1,
        manager.matchEvent(
            object : DynamicRuleEvent {
              override val ipAddress: String? = null
              override val country: String? = null
              override val eventType: String? = "user_agent_blocked"
            },
        ),
    )
    manager.currentRules =
        DynamicRules(
            ruleId = "r2",
            version = 2,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
        )
    assertNull(
        manager.matchEvent(
            object : DynamicRuleEvent {
              override val ipAddress: String? = null
              override val country: String? = null
              override val eventType: String? = "user_agent_blocked"
            },
        ),
    )
  }

  /** check_rule_expiry's not-yet-expired early return (199). */
  @Test
  fun `check rule expiry keeps unexpired rules`(): Unit = runBlocking {
    val manager = DynamicRuleManager(config())
    manager.currentRules =
        DynamicRules(
            ruleId = "r1",
            version = 1,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
            expiresAt = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).plusHours(1),
        )
    manager.checkRuleExpiry()
    assertNotNull(manager.currentRules)
  }

  /** applyUserAgentRules builds the validation cache when a path is configured (462-465). */
  @Test
  fun `apply user agent rules uses the validation cache path`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ua-cache")
    val manager =
        DynamicRuleManager(
            config {
              detectionPatternValidationCachePath = dir.resolve("cache.json").toString()
            },
        )
    manager.applyUserAgentRules(listOf("safe-agent"))
    assertTrue("safe-agent" in manager.config.blockedUserAgents)
  }

  /** stop() through a cancelled caller: join() raises CancellationException (548). */
  @Test
  fun `stop survives a cancelled caller`(): Unit = runBlocking {
    DynamicRuleManager.resetInstance()
    val manager =
        DynamicRuleManager.getInstance(
            config {
              enableDynamicRules = true
              enableAgent = true
              agentApiKey = "w9h"
            },
        )
    val agent =
        object : DynamicRuleManager.AgentDynamicRulesSource {
          override suspend fun getDynamicRules(): DynamicRules? = null

          override suspend fun sendEvent(event: Map<String, Any?>) {}
        }
    manager.initializeAgent(agent)
    assertNotNull(manager.updateTask)
    val caller = Job()
    val scope = kotlinx.coroutines.CoroutineScope(Dispatchers.Default + caller)
    scope.launch {
      caller.cancel()
      manager.stop()
    }
    delay(500)
    scope.cancel()
    manager.stop()
    DynamicRuleManager.resetInstance()
  }

  /** hydrate catches apply failures (573-574) via a subclass whose apply step raises. */
  @Test
  fun `hydrate survives a throwing apply`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-hydrate")
    val cachePath = dir.resolve("rules.json")
    val base = DynamicRuleManager(config { dynamicRulesCachePath = cachePath })
    val rules =
        DynamicRules(
            ruleId = "r9",
            version = 3,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
        )
    base.persistLastKnownRules(rules)
    assertTrue(Files.exists(cachePath))
    val manager =
        object : DynamicRuleManager(config { dynamicRulesCachePath = cachePath }) {
          override suspend fun applyIpRules(rules: DynamicRules) {
            throw IllegalStateException("apply exploded")
          }
        }
    manager.hydrateLastKnownRules()
  }

  /** readRedisPayload: the read-failure arm (605-607) and the empty-string arm (610). */
  @Test
  fun `read redis payload handles failure and empty`(): Unit = runBlocking {
    val manager = DynamicRuleManager(config())
    val broken =
        object : RedisManager(config()) {
          override suspend fun getKey(namespace: String, key: String): Any? {
            throw IllegalStateException("boom")
          }
        }
    manager.initializeDynamicRuleRedis(broken)
    assertNull(manager.readRedisPayload())

    val empty = DynamicRuleManager(config())
    val emptyRedis =
        object : RedisManager(config()) {
          override suspend fun getKey(namespace: String, key: String): Any? = ""
        }
    empty.initializeDynamicRuleRedis(emptyRedis)
    assertNull(empty.readRedisPayload())
  }

  /** readFilePayload: the not-a-file arm (622) and the read-failure arm (626-627). */
  @Test
  fun `read file payload handles missing and unreadable files`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-file-payload")
    val missing = DynamicRuleManager(config { dynamicRulesCachePath = dir.resolve("nope.json") })
    assertNull(missing.readFilePayload())
    assertNull(missing.loadLastKnownRules())

    val unreadable = dir.resolve("locked.json")
    Files.write(unreadable, "x".toByteArray())
    assertTrue(unreadable.toFile().setReadable(false))
    val manager = DynamicRuleManager(config { dynamicRulesCachePath = unreadable })
    assertNull(manager.readFilePayload())
    assertNull(manager.loadLastKnownRules())
  }

  /** persist: the redis-failure arm (656-657) and the file-failure arm (667-668, 684-688). */
  @Test
  fun `persist last known rules survives redis and file failures`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-persist")
    val rules =
        DynamicRules(
            ruleId = "rx",
            version = 1,
            timestamp = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC),
        )
    val writeBroken =
        object : RedisManager(config()) {
          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = throw IllegalStateException("write boom")
        }
    val redisThrowing = DynamicRuleManager(config())
    redisThrowing.initializeDynamicRuleRedis(writeBroken)
    redisThrowing.persistLastKnownRules(rules)

    // A directory at the cache path forces the atomic write to fail; the tmp cleanup
    // runs (684-688) and persist swallows (667-668).
    val cacheDir = dir.resolve("rules.json")
    Files.createDirectory(cacheDir)
    val fileFailing = DynamicRuleManager(config { dynamicRulesCachePath = cacheDir })
    fileFailing.persistLastKnownRules(rules)
  }

  /** resolveRedisValue is the identity port (693). */
  @Test
  fun `resolve redis value passes values through`(): Unit = runBlocking {
    assertEquals("x", resolveRedisValue("x"))
    assertNull(resolveRedisValue(null))
  }

  // ------------------------------------------------------------------ CloudManager

  /** scheduleRefresh's default refresh=null arm (94, 101) over the fetch seam. */
  @Test
  fun `schedule refresh defaults to refresh async`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedStore = cloud.store
    val savedRedis = cloud.redisHandler
    cloud.redisHandler = null
    fetchProviderRangesOverride = { _ ->
      setOf(com.guardcore.util.py.IpNetwork.parse("10.0.0.0/8")) to mapOf("10.0.0.0/8" to "us-east")
    }
    try {
      assertTrue(cloud.scheduleRefresh(providers = setOf("AWS"), ttl = 60))
      val deadline = System.nanoTime() + 5_000_000_000L
      while (cloud.ipRanges["AWS"]!!.isEmpty() && System.nanoTime() < deadline) {
        delay(100)
      }
      assertTrue(cloud.ipRanges["AWS"]!!.isNotEmpty())
    } finally {
      fetchProviderRangesOverride = null
      cloud.redisHandler = savedRedis
      cloud.store = savedStore
      cloud.agentHandler = null
    }
  }

  /** refreshProviders()/refresh()/refreshAsync() default-arg synthetics (153, 191, 196, 200). */
  @Test
  fun `refresh entry points take their defaults`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedStore = cloud.store
    val savedRedis = cloud.redisHandler
    cloud.redisHandler = null
    cloud.store = InMemoryCloudIpStore()
    fetchProviderRangesOverride = { _ ->
      setOf(com.guardcore.util.py.IpNetwork.parse("10.1.0.0/16")) to linkedMapOf()
    }
    try {
      cloud.refreshProviders()
      assertTrue(cloud.ipRanges["AWS"]!!.isNotEmpty())
      cloud.refreshAsync()
      assertTrue(cloud.ipRanges["GCP"]!!.isNotEmpty())
      cloud.refresh()
      assertTrue(cloud.ipRanges["Azure"]!!.isNotEmpty())
    } finally {
      fetchProviderRangesOverride = null
      cloud.redisHandler = savedRedis
      cloud.store = savedStore
      cloud.agentHandler = null
    }
  }

  /** initializeCloudRedis default providers/ttl (175-176, 183) over live redis. */
  @Test
  fun `initialize cloud redis takes defaults over live redis`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedStore = cloud.store
    val savedRedis = cloud.redisHandler
    val live =
        RedisManager.getInstance(
            config {
              redisUrl = "redis://localhost:6379/0"
              enableRedis = true
            },
        )
    live.initialize()
    fetchProviderRangesOverride = { _ ->
      setOf(com.guardcore.util.py.IpNetwork.parse("10.2.0.0/16")) to linkedMapOf()
    }
    try {
      cloud.initializeCloudRedis(live)
      assertTrue(cloud.ipRanges["AWS"]!!.isNotEmpty())
      assertNotNull(cloud.redisHandler)
    } finally {
      fetchProviderRangesOverride = null
      cloud.redisHandler = savedRedis
      cloud.store = savedStore
      cloud.agentHandler = null
      live.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
    }
  }

  /** The mid-loop store-null arm (211-213): the fetch seam nulls the store under the walk. */
  @Test
  fun `refresh async handles a store dropped mid walk`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedStore = cloud.store
    val savedRedis = cloud.redisHandler
    cloud.redisHandler = null
    cloud.store = InMemoryCloudIpStore()
    fetchProviderRangesOverride = { _ ->
      cloud.store = null
      setOf(com.guardcore.util.py.IpNetwork.parse("10.3.0.0/16")) to linkedMapOf()
    }
    try {
      cloud.refreshAsync(setOf("AWS", "GCP"))
      assertTrue(cloud.ipRanges["GCP"]!!.isNotEmpty())
    } finally {
      fetchProviderRangesOverride = null
      cloud.redisHandler = savedRedis
      cloud.store = savedStore
      cloud.agentHandler = null
    }
  }

  /** The refreshAsync catch arm (232-235) and the via-redis-handler catch arm (276-279). */
  @Test
  fun `refresh catches keep unknown providers empty`(): Unit = runBlocking {
    val cloud = CloudManager.getInstance()
    val savedStore = cloud.store
    val savedRedis = cloud.redisHandler
    cloud.redisHandler = null
    fetchProviderRangesOverride = { _ -> throw IllegalStateException("fetch exploded") }
    try {
      cloud.refreshAsync(setOf("CUSTOM-PROVIDER"))
      assertTrue(cloud.ipRanges.containsKey("CUSTOM-PROVIDER"))

      cloud.store = null
      cloud.refreshAsync(setOf("OTHER-CUSTOM"))
      assertTrue(cloud.ipRanges.containsKey("OTHER-CUSTOM"))
    } finally {
      fetchProviderRangesOverride = null
      cloud.redisHandler = savedRedis
      cloud.store = savedStore
      cloud.agentHandler = null
    }
  }

  /** getCloudProviderDetails' invalid-IP catch (370-371). */
  @Test
  fun `cloud provider details rejects invalid ips`() {
    val cloud = CloudManager.getInstance()
    assertNull(cloud.getCloudProviderDetails("999.999.999.999"))
  }

  // ------------------------------------------------------------------ Cloud fetchers

  /** downloadAzureServiceTags' expired-deadline arm (115). */
  @Test
  fun `azure download respects its deadline`(): Unit = runBlocking {
    assertFailsWith<IllegalStateException> {
      CloudAzureFetch.downloadAzureServiceTags(
          "https://blob.core.windows.net/x.json",
          deadline = 0.0,
      )
    }
  }

  /** parseServiceTagsDate's future-date arm (166) + stale-warn no-date arm (185-189). */
  @Test
  fun `azure service tag date parsing rejects future and missing dates`() {
    val tomorrow =
        java.time.LocalDate.now(java.time.ZoneOffset.UTC)
            .plusDays(1)
            .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd"))
    assertNull(CloudAzureFetch.parseServiceTagsDate("https://blob.core.windows.net/$tomorrow.json"))
    assertNull(CloudAzureFetch.parseServiceTagsDate("https://blob.core.windows.net/nodate.json"))
    CloudAzureFetch.warnIfServiceTagsUrlIsStale("https://blob.core.windows.net/nodate.json")
  }

  /** selectAzureCloudPrefixes' missing-tag arm (288-289) + the bad-prefix filter (318). */
  @Test
  fun `azure prefix selection handles missing tags and bad prefixes`(): Unit = runBlocking {
    val noTag = azureDoc("Other", listOf("10.4.0.0/16"))
    assertTrue(CloudAzureFetch.selectAzureCloudPrefixes(noTag).isEmpty())

    val badPrefix = azureDoc("AzureCloud", listOf("not-a-prefix", "10.4.0.0/16"))
    assertEquals(
        listOf("not-a-prefix", "10.4.0.0/16"),
        CloudAzureFetch.selectAzureCloudPrefixes(badPrefix),
    )
    CloudAzureFetch.httpGetOverride = { url ->
      if (url.endsWith(".json")) {
        200 to badPrefix.toString()
      } else {
        200 to "<html><a href=\"https://download.microsoft.com/servicetags/x.json\">dl</a></html>"
      }
    }
    try {
      val fetched = CloudAzureFetch.fetchAzureIpRanges()
      assertEquals(setOf(com.guardcore.util.py.IpNetwork.parse("10.4.0.0/16")), fetched)
    } finally {
      CloudAzureFetch.httpGetOverride = null
    }
  }

  /** fetchCsvPrefixNetworks' empty-prefix skip (163) + the linode catch arm (188-189). */
  @Test
  fun `csv fetchers skip empty prefixes and survive failures`(): Unit = runBlocking {
    // The linode fetcher parses the CSV through fetchCsvPrefixNetworks; the empty
    // first field takes the skip arm (163).
    CloudFetchers.httpGetOverride = { _ -> 200 to "10.5.0.0/16,us\n,10.6.0.0/24\n#comment\n" }
    val parsed = CloudFetchers.fetchLinodeIpRanges()
    assertEquals(setOf(com.guardcore.util.py.IpNetwork.parse("10.5.0.0/16")), parsed)
    // A throwing body takes the linode catch arm (188-189).
    CloudFetchers.httpGetOverride = { _ -> throw IllegalStateException("linode down") }
    assertTrue(CloudFetchers.fetchLinodeIpRanges().isEmpty())
    CloudFetchers.httpGetOverride = null
  }

  private fun azureDoc(
      tagName: String,
      prefixes: List<String>,
  ): kotlinx.serialization.json.JsonObject =
      kotlinx.serialization.json.JsonObject(
          mapOf(
              "values" to
                  kotlinx.serialization.json.JsonArray(
                      listOf(
                          kotlinx.serialization.json.JsonObject(
                              mapOf(
                                  "name" to kotlinx.serialization.json.JsonPrimitive(tagName),
                                  "properties" to
                                      kotlinx.serialization.json.JsonObject(
                                          mapOf(
                                              "addressPrefixes" to
                                                  kotlinx.serialization.json.JsonArray(
                                                      prefixes.map {
                                                        kotlinx.serialization.json.JsonPrimitive(it)
                                                      },
                                                  ),
                                          ),
                                      ),
                              ),
                          ),
                      ),
                  ),
          ),
      )

  // ------------------------------------------------------------------ SecurityHeadersManager

  /** getInstance's double-check arm (36) + the module-level helper (737). */
  @Test
  fun `security headers manager singleton reentry`(): Unit = runBlocking {
    val first = securityHeadersManager()
    val second = SecurityHeadersManager.getInstance()
    assertTrue(first === second)
    resetSecurityHeadersGlobalState()
    SecurityHeadersManager.resetInstance()
  }

  /** computeCspConfig's unsafe-source warning (118). */
  @Test
  fun `csp config warns on unsafe sources`(): Unit = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    val cfg = manager.computeCspConfig(mapOf("default-src" to listOf("'unsafe-inline'")))
    assertEquals(listOf("'unsafe-inline'"), cfg!!["default-src"])
    SecurityHeadersManager.resetInstance()
  }

  /** computeDefaultHeaders' Permissions-Policy removal arm (244). */
  @Test
  fun `default headers drop permissions policy when null`(): Unit = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    val headers = manager.computeDefaultHeaders(null, null, null, null, null)
    assertFalse(headers.containsKey("Permissions-Policy"))
    SecurityHeadersManager.resetInstance()
  }

  /** getHeaders' disabled-manager arm (413). */
  @Test
  fun `get headers honors the disabled flag`(): Unit = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    manager.enabled = false
    try {
      assertTrue(manager.getHeaders().isEmpty())
    } finally {
      manager.enabled = true
      manager.reset()
      SecurityHeadersManager.resetInstance()
    }
  }

  /** The cache-failure arms: load (488-490), persist (519-520), and reset-clear (544-545). */
  @Test
  fun `security headers redis cache failures are swallowed`(): Unit = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    val broken =
        object : RedisManager(config()) {
          override suspend fun getKey(namespace: String, key: String): Any? {
            throw IllegalStateException("read boom")
          }

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = throw IllegalStateException("write boom")

          override fun getConnection(): GuardRedisConnection {
            throw IllegalStateException("conn boom")
          }
        }
    manager.redisHandler = broken
    try {
      manager.loadCachedConfig()
      manager.cacheConfiguration()
      manager.cspConfig = mapOf("default-src" to listOf("'self'"))
      manager.hstsConfig = linkedMapOf("max_age" to 31536000)
      manager.customHeaders = linkedMapOf("X-Custom" to "v")
      manager.cacheConfiguration()
      manager.reset()
    } finally {
      manager.redisHandler = null
      SecurityHeadersManager.resetInstance()
    }
  }

  /** buildCorsHeaders' default-arg synthetic (593, 598). */
  @Test
  fun `build cors headers takes its defaults`(): Unit = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    val headers =
        manager.buildCorsHeaders(
            "https://x.test",
            listOf("https://x.test"),
            listOf("GET"),
            listOf("*"),
        )
    assertEquals("https://x.test", headers["Access-Control-Allow-Origin"])
    SecurityHeadersManager.resetInstance()
  }

  /** The event-send failure arms (660-661, 707-709) over a throwing sink. */
  @Test
  fun `security headers event failures are swallowed`(): Unit = runBlocking {
    val manager = SecurityHeadersManager.getInstance()
    manager.initializeHeadersAgent(ThrowingAgent())
    try {
      manager.sendHeadersAppliedEvent("/x", linkedMapOf("X" to "y"))
      manager.sendCspViolationEvent(mapOf("document-uri" to "https://x.test/"))
    } finally {
      manager.initializeHeadersAgent(null)
      SecurityHeadersManager.resetInstance()
    }
  }

  /** safeCspLineNumber's Number and string arms (729-730). */
  @Test
  fun `safe csp line number coercion`() {
    assertEquals(7, safeCspLineNumber(7L))
    assertEquals(9, safeCspLineNumber("9"))
    assertNull(safeCspLineNumber("not-a-number"))
    assertNull(safeCspLineNumber(null))
  }

  /** PyJsonSerde.dumpsHstsConfig's string-value arm (782). */
  @Test
  fun `hsts serde passes string values through`() {
    val payload = PyJsonSerde.dumpsHstsConfig(mapOf("max_age" to "3600"))
    assertTrue(payload.contains("3600"))
  }

  // ------------------------------------------------------------------ IpInfoManager

  /** getInstance re-entry updates token/dbPath/maxAge in place (97-102). */
  @Test
  fun `ipinfo manager singleton reentry reconfigures`() {
    val dir = Files.createTempDirectory("w9h-ipinfo-reentry")
    val first = IpInfoManager.getInstance("tok1", dir.resolve("a.mmdb"), 60)
    val second = IpInfoManager.getInstance("tok2", dir.resolve("b.mmdb"), 120)
    assertTrue(first === second)
    assertEquals("tok2", first.token)
    assertEquals(dir.resolve("b.mmdb"), first.dbPath)
    first.setReaderForTests(null)
    first.setInitializationAttempted(false)
    IpInfoManager.resetInstance()
  }

  /** writeDatabaseAtomically's cleanup-failure arm (199) via an undeletable tmp directory. */
  @Test
  fun `write database atomically rethrows when cleanup fails`() {
    val dir = Files.createTempDirectory("w9h-ipinfo-tmp")
    val dbPath = dir.resolve("geo.mmdb")
    val manager = IpInfoManager.getInstance("w9h-tmp", dbPath, 60)
    val tmpDir = dbPath.resolveSibling("geo.mmdb.tmp")
    try {
      // A NON-EMPTY directory at the tmp path: the write fails and the deleteIfExists
      // of the non-empty directory fails too (the ignored arm), then the error rethrows.
      Files.createDirectory(tmpDir)
      Files.write(tmpDir.resolve("blocker"), "x".toByteArray())
      assertFailsWith<Exception> { manager.writeDatabaseAtomically("bytes".toByteArray()) }
      assertTrue(Files.exists(tmpDir))
    } finally {
      val blocker = tmpDir.resolve("blocker")
      if (Files.exists(blocker)) {
        Files.delete(blocker)
      }
      Files.deleteIfExists(tmpDir)
      manager.setReaderForTests(null)
      IpInfoManager.resetInstance()
    }
  }

  /** initialize's cached-value coercion arm (223): a non-ByteArray/String cached value. */
  @Test
  fun `initialize coerces non byte cached database values`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ipinfo-coerce")
    val dbPath = dir.resolve("geo.mmdb")
    val manager = IpInfoManager.getInstance("w9h-coerce", dbPath, 60)
    val scripted = RecordingRedis()
    try {
      manager.redisHandler = scripted
      scripted.getKeyReturns["ipinfo" to "database"] = 12345L
      manager.initialize()
      // The written bytes are the toString of the cached value; the open then fails
      // (not an mmdb) and quarantines the file.
      assertFalse(Files.exists(dbPath))
    } finally {
      manager.redisHandler = null
      manager.setReaderForTests(null)
      IpInfoManager.resetInstance()
    }
  }

  /** sendGeoEvent's catch arm (279-280) over a throwing sink. */
  @Test
  fun `send geo event survives a throwing sink`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ipinfo-geo")
    val manager = IpInfoManager.getInstance("w9h-geo", dir.resolve("g.mmdb"), 60)
    try {
      manager.setAgentSinkForTests(ThrowingAgent())
      manager.sendGeoEvent(
          eventType = "geo_lookup_failed",
          ipAddress = "1.2.3.4",
          actionTaken = "database_download_failed",
          reason = "because",
      )
    } finally {
      manager.setAgentSinkForTests(null)
      manager.setReaderForTests(null)
      manager.setInitializationAttempted(false)
      IpInfoManager.resetInstance()
    }
  }

  /** downloadDatabase falls through silently when retries are zeroed (331). */
  @Test
  fun `download database with zero retries falls through`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ipinfo-noretry")
    val manager = IpInfoManager.getInstance("w9h-noretry", dir.resolve("g.mmdb"), 60)
    try {
      IpInfoManager.downloadRetries = 0
      manager.downloadDatabase()
    } finally {
      IpInfoManager.downloadRetries = IpInfoManager.DOWNLOAD_RETRIES
      manager.setReaderForTests(null)
      manager.setInitializationAttempted(false)
      IpInfoManager.resetInstance()
    }
  }

  /** downloadDatabase's redis-cache failure arm (318-319). */
  @Test
  fun `download database survives a redis cache failure`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ipinfo-rediscache")
    val dbPath = dir.resolve("geo.mmdb")
    val manager = IpInfoManager.getInstance("w9h-rc", dbPath, 60)
    try {
      manager.redisHandler = ThrowingRedis()
      manager.httpSendOverride = { url, _ ->
        fakeNetResponse(url, 200, "not an mmdb".toByteArray())
      }
      manager.downloadDatabase()
      assertTrue(Files.exists(dbPath))
    } finally {
      manager.httpSendOverride = null
      manager.redisHandler = null
      manager.setReaderForTests(null)
      manager.setInitializationAttempted(false)
      IpInfoManager.resetInstance()
    }
  }

  /** refresh's missing-file arm (443): the download seam yields nothing. */
  @Test
  fun `refresh returns quietly when no database lands`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ipinfo-refresh")
    val manager = IpInfoManager.getInstance("w9h-refresh", dir.resolve("g.mmdb"), 60)
    try {
      manager.downloadOverride = { throw java.net.http.HttpTimeoutException("down") }
      manager.refresh()
      assertNull(manager.lastRefreshed)
      assertFalse(Files.exists(manager.dbPath))
    } finally {
      manager.downloadOverride = null
      manager.httpSendOverride = null
      manager.countryLookupOverride = null
      manager.setReaderForTests(null)
      manager.setInitializationAttempted(false)
      IpInfoManager.resetInstance()
    }
  }

  /** close() releases the reader and clears the field (421-422, 426-427). */
  @Test
  fun `close releases the reader`(): Unit = runBlocking {
    val dir = Files.createTempDirectory("w9h-ipinfo-close")
    val dbPath = dir.resolve("geo.mmdb")
    Files.copy(fixture(), dbPath)
    val manager = IpInfoManager.getInstance("w9h-close", dbPath, 60)
    try {
      manager.initialize()
      val reader = manager.reader
      assertNotNull(reader)
      manager.close()
      assertNull(manager.reader)
    } finally {
      manager.setReaderForTests(null)
      IpInfoManager.resetInstance()
    }
  }

  private fun fixture(): java.nio.file.Path =
      java.nio.file.Paths.get("src/test/resources/maxmind/GeoIP2-Country-Test.mmdb")
          .toAbsolutePath()

  // ------------------------------------------------------------------ RedisManager

  /** getInstance re-entry reconfigures the manager in place (339-341). */
  @Test
  fun `redis manager singleton reentry reconfigures`(): Unit = runBlocking {
    RedisManager.resetInstance()
    val first = RedisManager.getInstance(config { enableRedis = false })
    val second =
        RedisManager.getInstance(
            config {
              enableRedis = false
              redisPrefix = "other:"
            },
        )
    assertTrue(first === second)
    assertEquals("other:", first.config.redisPrefix)
    RedisManager.resetInstance()
  }

  /** connectionKwargs' max_connections arm (427). */
  @Test
  fun `connection kwargs carries max connections`() {
    val manager = RedisManager(config { redisMaxConnections = 5 })
    val kwargs = manager.connectionKwargs()
    assertEquals(5, kwargs["max_connections"])
  }

  /** initialize's non-PONG arm (476) over a scripted client factory. */
  @Test
  fun `initialize rejects a non pong ping`(): Unit = runBlocking {
    val manager =
        RedisManager(
            config {
              enableRedis = true
              redisUrl = "redis://localhost:6379/0"
            },
        ) { _, _, _ ->
          object : NoopRedisOperations() {
            override suspend fun ping(): Boolean = false
          }
        }
    assertFailsWith<GuardRedisError> { manager.initialize() }
    manager.discardClientQuietlyForCorpus()
  }

  /** transaction's queued-future unwrap arms (179-181) over a real lettuce connection. */
  @Test
  fun `transaction unwraps queued command failures`() = runBlocking {
    val client = io.lettuce.core.RedisClient.create("redis://localhost:6379")
    val connection = client.connect()
    try {
      // Seed a STRING key, then zadd against it inside MULTI/EXEC: EXEC succeeds but the
      // queued zadd future completes exceptionally (179-181).
      connection.sync().set("w9h:string-key", "plain")
      val operations = LettuceRedisOperations(client, connection)
      val manager = RedisManager(config { enableRedis = false }) { _, _, _ -> operations }
      val outcome =
          kotlinx.coroutines.withTimeout(10_000) {
            kotlinx.coroutines.runBlocking {
              runCatching {
                operations.transaction { tx ->
                  tx.zadd("w9h:string-key", 1.0, "member")
                  tx.zcard("w9h:string-key")
                }
              }
            }
          }
      assertTrue(outcome.isFailure)
    } finally {
      connection.close()
      client.shutdown()
    }
  }

  /** redactRedisUrl: the unparseable-URL arm (738-739) and the bracketed-host arm (772). */
  @Test
  fun `redis url redaction arms`() {
    assertEquals("redis://<unparseable>", redactRedisUrl("redis://[::1"))
    assertEquals("redis://[::1]/0", redactRedisUrl("redis://[::1]/0"))
  }

  // ------------------------------------------------------------------ RateLimitManager

  /** getInstance re-entry reconfigures (347-348). */
  @Test
  fun `rate limit manager singleton reentry reconfigures`() {
    RateLimitManager.resetInstance()
    val first = RateLimitManager.getInstance(config())
    val second = RateLimitManager.getInstance(config { rateLimit = 11 })
    assertTrue(first === second)
    assertEquals(11, first.config.rateLimit)
    RateLimitManager.resetInstance()
  }

  /** inMemoryRequestCount's endpoint-less key arm (178, 183). */
  @Test
  fun `in memory request count keys by ip without endpoint`() {
    val timestamps = linkedMapOf<String, java.util.ArrayDeque<Double>>()
    val now = 1000.0
    // The count is the pruned window size taken before the new timestamp is appended.
    assertEquals(0L, inMemoryRequestCount(timestamps, "1.2.3.4", now - 60, now))
    assertEquals(1L, inMemoryRequestCount(timestamps, "1.2.3.4", now - 60, now))
  }

  /** sendRateLimitEvent's catch arm (596-597) over a throwing sink. */
  @Test
  fun `rate limit event survives a throwing sink`(): Unit = runBlocking {
    RateLimitManager.resetInstance()
    val manager = RateLimitManager.getInstance(config())
    val request = TestRequest()
    manager.agentHandler = ThrowingAgent()
    try {
      manager.sendRateLimitEvent(request, "1.2.3.4", 42)
    } finally {
      manager.agentHandler = null
      RateLimitManager.resetInstance()
    }
  }

  /** reset(): the RedisManager delete-pattern arm (610-611) over live redis. */
  @Test
  fun `reset clears live redis rate keys`(): Unit = runBlocking {
    val live =
        RedisManager.getInstance(
            config {
              redisUrl = "redis://localhost:6379/0"
              enableRedis = true
            },
        )
    live.initialize()
    RateLimitManager.resetInstance()
    val cfg = config {
      enableRedis = true
      redisUrl = "redis://localhost:6379/0"
    }
    val manager = RateLimitManager.getInstance(cfg)
    manager.redisHandler = live
    // Seed at least one rate-limit key through the module entry over the live handler.
    checkRateLimitByIp("1.2.3.4", cfg, live, endpointPath = "/w9h-reset")
    manager.reset()
    assertNull(manager.redisHandler)
    live.discardClientQuietlyForCorpus()
    RedisManager.resetInstance()
    RateLimitManager.resetInstance()
  }

  /** reset(): the protocol-fake delete arm (615) and the keys-failure arm (618-619). */
  @Test
  fun `reset handles protocol fakes and failures`(): Unit = runBlocking {
    RateLimitManager.resetInstance()
    val manager = RateLimitManager.getInstance(config { enableRedis = true })
    val scripted = RecordingRedis()
    scripted.keysReturn = listOf("full:key:1")
    manager.redisHandler = scripted
    manager.reset()
    assertEquals(listOf("rate_limit:rate:*"), scripted.keysCalls)

    val throwing = ThrowingRedis()
    manager.redisHandler = throwing
    manager.reset()
    assertNull(manager.redisHandler)
    RateLimitManager.resetInstance()
  }

  /** redisRequestCount's RedisException and generic catch arms (149-152). */
  @Test
  fun `redis request count resolves failures`(): Unit = runBlocking {
    val logger = java.util.logging.Logger.getLogger("w9h-rate")
    fun fakeWith(txError: Exception): RedisHandlerProtocol =
        object : RedisHandlerProtocol {
          val ops =
              object : NoopRedisOperations() {
                override suspend fun transaction(
                    ops: suspend (QueuedRedisOperations) -> Unit,
                ): List<Any?> = throw txError
              }

          override suspend fun getKey(namespace: String, key: String): Any? = null

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? = 1

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): GuardRedisConnection = FakeRedisConnection(ops)
        }

    // The RedisException arm with fail-open (returns null) and fail-closed (raises).
    val (countFailOpen, _) =
        redisRequestCount(
            fakeWith(RedisException("transaction exploded")),
            logger,
            "1.2.3.4",
            1000.0,
            940.0,
            60,
            10,
            null,
            redisFailOpen = true,
        )
    assertNull(countFailOpen)
    assertFailsWith<GuardRedisError> {
      redisRequestCount(
          fakeWith(RedisException("transaction exploded")),
          logger,
          "1.2.3.4",
          1000.0,
          940.0,
          60,
          10,
          null,
          redisFailOpen = false,
      )
    }
    assertTrue(true)
    // The generic-Exception arm.
    val (countGeneric, _) =
        redisRequestCount(
            fakeWith(IllegalStateException("unexpected")),
            logger,
            "1.2.3.4",
            1000.0,
            940.0,
            60,
            10,
            null,
            redisFailOpen = true,
        )
    assertNull(countGeneric)
  }

  // ------------------------------------------------------------------ BehaviorTracker

  /** The sliding-window protocol path: ops present (225-238) and client unusable (240). */
  @Test
  fun `behavior tracker sliding window over protocol fakes`(): Unit = runBlocking {
    val tracker = BehaviorTracker(config())

    val queued =
        object : QueuedRedisOperations {
          override suspend fun incr(key: String) {}

          override suspend fun expire(key: String, seconds: Long) {}

          override suspend fun zadd(key: String, score: Double, member: String) {}

          override suspend fun zremRangeByScore(key: String, min: String, max: String) {}

          override suspend fun zcard(key: String) {}

          override suspend fun get(key: String) {}

          override suspend fun pTtl(key: String) {}

          override suspend fun setEx(key: String, value: String, ttlSeconds: Long) {}

          override suspend fun del(vararg keys: String) {}

          override fun close() {}
        }
    val ops =
        object : NoopRedisOperations() {
          override suspend fun transaction(
              ops: suspend (QueuedRedisOperations) -> Unit,
          ): List<Any?> {
            ops(queued)
            return listOf("OK", 1L, 3L, true)
          }
        }
    tracker.initializeBehaviorRedis(ScriptedRedis(ops))
    val rule = BehaviorRule(ruleType = "usage", threshold = 2, window = 60)
    assertTrue(tracker.trackEndpointUsage("/e", "1.2.3.4", rule))

    // A client that does not expose RedisOperations short-circuits to zero hits.
    tracker.initializeBehaviorRedis(ScriptedRedis("not-redis-operations"))
    assertFalse(tracker.trackEndpointUsage("/e", "1.2.3.4", rule))
  }

  // ------------------------------------------------------------------ Response patterns

  /** The array-match and traversal miss arms (30, 44) and the match catch (71). */
  @Test
  fun `behavior json pattern decode arms`() {
    assertFalse(handleBehaviorArrayMatch(mapOf("other" to listOf("a")), "items[]", "a"))
    assertNull(traverseBehaviorJsonPath(mapOf("a" to 1), "b"))
    // A value whose toString throws trips the generic catch inside matchBehaviorJsonPattern.
    class Exploding {
      override fun toString(): String = throw IllegalStateException("boom")
    }
    assertFalse(matchBehaviorJsonPattern(mapOf("a" to Exploding()), "a==x"))
  }

  /** logBodyUnavailable's cache-hit arm (79) and the null-prefix arm (113-114). */
  @Test
  fun `body unavailable logging and null prefix`(): Unit = runBlocking {
    val tracker = BehaviorTracker(config { behaviorScanResponseBody = true })
    tracker.logBodyUnavailable("p1")
    tracker.logBodyUnavailable("p1")

    // A bounded reader whose prefix read fails takes the log+null arm
    // (BodyReader.safeRead folds the failure into a null prefix).
    val nullReader =
        object : GuardResponse, com.guardcore.protocols.BoundedResponseBodyReader {
          override val headers: MutableMap<String, String> = linkedMapOf()
          override val statusCode: Int = 200
          override val body: ByteArray = ByteArray(0)

          override suspend fun readBodyPrefix(maxBytes: Int): ByteArray {
            throw IllegalStateException("prefix read failed")
          }
        }
    assertNull(tracker.readResponseBodyPrefix(nullReader, "p2"))
    assertNull(tracker.checkResponsePattern(nullReader, "p2"))
  }

  /** checkResponsePattern's malformed status arm (158-159). */
  @Test
  fun `response pattern survives a malformed status pattern`(): Unit = runBlocking {
    val tracker = BehaviorTracker(config())
    val response =
        object : GuardResponse {
          override val headers: MutableMap<String, String> = linkedMapOf()
          override val statusCode: Int = 200
          override val body: ByteArray = "hello".encodeToByteArray()
        }
    assertEquals(false, tracker.checkResponsePattern(response, "status:not-an-int"))
  }

  /** PyJsonLike: the JsonNull arm (181) and the float arm (188). */
  @Test
  fun `json like parses nulls and floats`(): Unit = runBlocking {
    val tracker = BehaviorTracker(config { behaviorScanResponseBody = true })
    val body = """{"a": null, "f": 1.5, "b": 2}"""
    val response =
        object : GuardResponse, com.guardcore.protocols.BoundedResponseBodyReader {
          override val headers: MutableMap<String, String> = linkedMapOf()
          override val statusCode: Int = 200
          override val body: ByteArray = body.encodeToByteArray()

          override suspend fun readBodyPrefix(maxBytes: Int): ByteArray = body.encodeToByteArray()
        }
    assertEquals(true, tracker.checkResponsePattern(response, "json:b==2"))
  }

  // ------------------------------------------------------------------ SusPatternsRegistry

  /** addPattern's engine-config-null fallback for the max body bytes (94). */
  @Test
  fun `registry add pattern falls back to the default max body bytes`(): Unit = runBlocking {
    val engine = SusPatternsManager.shared()
    val saved = engine.patterns.toList()
    val savedConfig = engine.config
    engine.config = null
    try {
      val added = SusPatternsRegistry.addPattern("w9h-unique-pattern-1", custom = true)
      assertTrue(added)
    } finally {
      engine.config = savedConfig
      engine.patterns.clear()
      engine.patterns.addAll(saved)
      SusPatternsRegistry.removeCustomPattern("w9h-unique-pattern-1")
    }
  }

  /** detect()'s agent-sink performance record (252) over a recording sink. */
  @Test
  fun `detect wires the agent sink into the engine monitor`(): Unit = runBlocking {
    val agent = RecordingAgent()
    val previous = SusPatternsRegistry.agentHandler
    SusPatternsRegistry.agentHandler = agent
    try {
      val result = SusPatternsRegistry.detect("plain harmless content", "1.2.3.4")
      assertNotNull(result)
    } finally {
      SusPatternsRegistry.agentHandler = previous
    }
  }

  // ------------------------------------------------------------------ Seams and small tails

  /** HandlerSeams: the registered lambdas resolve their targets (24, 29). */
  @Test
  fun `handler seams resolve geo and cloud lambdas`(): Unit = runBlocking {
    HandlerSeams.register()
    val geo = ConfigSeams.geoIpHandlerFactory?.invoke("w9h-token", null, 3600)
    assertNotNull(geo)
    val details = AccessControl.cloudIpChecker?.invoke("203.0.113.1", setOf("AWS"))
    assertNull(details)
  }

  /** The snapshot coercers reject wrong-shaped values (208, 218, 228). */
  @Test
  fun `dynamic rules snapshot coercion rejects wrong types`() {
    // A non-primitive rule_id takes the str-else throw (208).
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"timestamp": "2026-01-01T00:00:00+00:00",
             "rule_id": []}}"""
              .replace("\n", " "),
      )
    }
    // A non-primitive version takes the intOf-else throw (218).
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(
          """{"schema_version": 1, "rules": {"timestamp": "2026-01-01T00:00:00+00:00",
             "rule_id": "x", "version": []}}"""
              .replace("\n", " "),
      )
    }
    // An explicit null boolean parses through the JsonNull arm (228) to the default.
    val rules =
        loadLastKnownRulesSnapshot(
            """{"schema_version": 1, "rules": {"timestamp": "2026-01-01T00:00:00+00:00",
               "rule_id": "x", "version": 1, "emergency_mode": null}}"""
                .replace("\n", " "),
        )
    assertFalse(rules.emergencyMode)
  }

  /** IpBanMigration: the unusable-connection arm (38) and the scan-failure arm (47-48). */
  @Test
  fun `legacy ban migration skips unusable connections`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val manager = IpBanManager.getInstance()
    // A protocol fake whose client is unusable AND whose close raises.
    val brokenConnection =
        object : GuardRedisConnection {
          override val client: Any? = "not-operations"

          override fun close() {
            throw IllegalStateException("close boom")
          }
        }
    val fake =
        object : RedisHandlerProtocol {
          override suspend fun getKey(namespace: String, key: String): Any? = null

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? = 1

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): GuardRedisConnection = brokenConnection
        }
    manager.initializeBanRedis(fake)
    manager.migrateLegacyBanKeys()

    // A usable client whose scan raises takes the catch arm.
    val scanThrowing =
        object : NoopRedisOperations() {
          override suspend fun scan(match: String): List<String> =
              throw IllegalStateException("scan boom")
        }
    manager.initializeBanRedis(ScriptedRedis(scanThrowing))
    manager.migrateLegacyBanKeys()
    manager.initializeBanRedis(null)
    resetIpBanGlobalState()
  }

  /** IpBanQueries.reset: the delete arm over a scripted client (101, 104). */
  @Test
  fun `ip ban reset deletes scripted keys`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val manager = IpBanManager.getInstance()
    val deleted = mutableListOf<String>()
    val ops =
        object : NoopRedisOperations() {
          override suspend fun keys(pattern: String): List<String> = listOf("full:key:1")

          override suspend fun del(vararg keys: String): Long {
            deleted.addAll(keys)
            return keys.size.toLong()
          }
        }
    manager.initializeBanRedis(ScriptedRedis(ops))
    manager.reset()
    assertEquals(listOf("full:key:1"), deleted)
    manager.initializeBanRedis(null)
    resetIpBanGlobalState()
  }

  /** BehaviorActionDispatch: the ban arms (52, 55, 62). */
  @Test
  fun `behavior ban action arms`(): Unit = runBlocking {
    IpBanManager.resetInstance()
    val manager = IpBanManager.getInstance()
    manager.initializeBanRedis(null)
    val tracker =
        BehaviorTracker(config { logSuspiciousLevel = com.guardcore.config.LogLevel.WARNING })
    val rule = BehaviorRule(ruleType = "usage", threshold = 1, banDuration = 99)
    val result = tracker.executeBanAction("198.51.100.9", "details", rule)
    assertTrue(result.isNotEmpty())
    tracker.executeBanAction("198.51.100.10", "details")
    manager.unbanIp("198.51.100.9")
    manager.unbanIp("198.51.100.10")
    resetIpBanGlobalState()
  }

  /** PyJsonDumps: the control-char and ensureAscii escape arms (51). */
  @Test
  fun `py json dumps escapes control and high chars`() {
    // json.dumps defaults (ensure_ascii=True): control chars AND non-ASCII escape.
    val payload = PyJsonDumps.dumps(kotlinx.serialization.json.JsonPrimitive("\u0001\u00e9"))
    assertTrue(payload.contains("\\u0001"))
    assertTrue(payload.contains("\\u00e9"))
    // pydantic model_dump_json keeps non-ASCII as UTF-8 (W9i: the ensure-ascii
    // flag was inverted; the escape path is the dumps default).
    val compact = PyJsonDumps.dumpsCompact(kotlinx.serialization.json.JsonPrimitive("\u00e9"))
    assertTrue(compact.contains("é"))
  }
}
