package com.guardcore.conformance

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.DynamicRules
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.IpInfoManager
import com.guardcore.handlers.RATE_LIMIT_SCRIPT
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RateLimitState
import com.guardcore.handlers.RedisCloudIpStore
import com.guardcore.handlers.RedisManager
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.SusPatternsRegistry
import com.guardcore.handlers.banIp
import com.guardcore.handlers.initializeBanRedis
import java.nio.file.Files
import java.time.OffsetDateTime
import java.util.regex.Pattern
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * redis_interop corpus runner (spec 4.1.0, 14 cases).
 *
 * Contract (index.json comparison.redis_interop): "byte equality: keys, static string values and
 * TTL semantics are exact; zset members the engine generates at write time (uuid4 hex, epoch
 * floats) and ban expiry floats are pinned by SHAPE (regex), not value; zset scores are compared as
 * floats at 6-decimal precision".
 *
 * The reference harness drives the real handlers against a real Redis under the suite prefix
 * (`guard_core:corpus_rio:`); this runner does the same against the W3 handlers with the fetch
 * seams scripted to the pinned fixtures. Requires Redis on REDIS_URL (localhost:6379); the suite
 * prefix is scrubbed before and after each case.
 */
class RedisInteropTest {

  private fun corpusDir(): java.nio.file.Path {
    var dir: java.nio.file.Path = java.nio.file.Path.of(System.getProperty("user.dir"))
    while (true) {
      val candidate = dir.resolve("conformance").resolve("guard-core-spec-4.1.0").resolve("cases")
      if (Files.exists(candidate.resolve("index.json"))) {
        return candidate
      }
      dir = dir.parent ?: error("corpus index.json not found relative to $dir")
    }
  }

  private fun config(): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            redisUrl = System.getenv("REDIS_URL") ?: "redis://localhost:6379"
            redisPrefix = "guard_core:corpus_rio:"
            enableRedis = true
          }
          .build()

  private fun redisAvailable(): Boolean =
      try {
        runBlocking {
          val r = RedisManager.getInstance(config())
          r.initialize()
          val ok = r.operations()!!.ping()
          r.close()
          ok
        }
      } catch (e: Exception) {
        false
      }

  private suspend fun scrub(redis: RedisManager) {
    val keys = redis.operations()!!.keys("guard_core:corpus_rio:*")
    if (keys.isNotEmpty()) {
      redis.operations()!!.del(*keys.toTypedArray())
    }
  }

  private val json = kotlinx.serialization.json.Json

  @Test
  fun redisInteropCorpus() {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        redisAvailable(),
        "redis_interop needs a live Redis on REDIS_URL (localhost:6379)",
    )
    val caseFile =
        json.parseToJsonElement(Files.readString(corpusDir().resolve("redis_interop.json")))
    val cases =
        (caseFile as kotlinx.serialization.json.JsonObject)["cases"]!!.let {
          it as kotlinx.serialization.json.JsonArray
        }

    val failures = mutableListOf<String>()
    runBlocking {
      for (caseElement in cases) {
        val case = caseElement as kotlinx.serialization.json.JsonObject
        val id = case["id"]!!.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
        try {
          runCase(id)
          verify(id, case)
        } catch (e: Exception) {
          failures.add("$id: threw ${e.javaClass.simpleName}: ${e.message}")
        }
      }
    }
    assertTrue(failures.isEmpty(), "redis_interop failures:\n" + failures.joinToString("\n"))
  }

  // ------------------------------------------------------------- operation drivers

  private suspend fun runCase(id: String) {
    val cfg = config()
    val redis = RedisManager.getInstance(cfg)
    redis.initialize()
    scrub(redis)
    when (id) {
      "rio_rate_limit_global_tier" -> {
        RateLimitManager.resetInstance()
        RateLimitState.reset()
        val mgr = RateLimitManager.getInstance(cfg)
        mgr.redisHandler = redis
        mgr.rateLimitScriptSha = redis.operations()!!.scriptLoad(RATE_LIMIT_SCRIPT)
        val response =
            mgr.checkRateLimit(
                FakeRequest(),
                "203.0.113.20",
                { status, message -> FakeResponse(status, message) },
                rateLimit = 5,
                rateLimitWindow = 60,
            )
        check(response == null) { "first call must be under the limit" }
      }
      "rio_rate_limit_endpoint_tier" -> {
        RateLimitManager.resetInstance()
        RateLimitState.reset()
        val mgr = RateLimitManager.getInstance(cfg)
        mgr.redisHandler = redis
        mgr.rateLimitScriptSha = redis.operations()!!.scriptLoad(RATE_LIMIT_SCRIPT)
        val response =
            mgr.checkRateLimit(
                FakeRequest(),
                "203.0.113.20",
                { status, message -> FakeResponse(status, message) },
                endpointPath = "/api",
                rateLimit = 5,
                rateLimitWindow = 60,
            )
        check(response == null) { "first call must be under the limit" }
      }
      "rio_ban_exact_ip" -> {
        IpBanManager.resetInstance()
        val mgr = IpBanManager.getInstance()
        mgr.initializeBanRedis(redis)
        mgr.banIp("203.0.113.21", 3600, "rio_ban")
      }
      "rio_ban_cidr_network" -> {
        IpBanManager.resetInstance()
        val mgr = IpBanManager.getInstance()
        mgr.initializeBanRedis(redis)
        mgr.banIp("10.0.0.0/24", 1800, "rio_ban")
      }
      "rio_behavior_usage_increment" -> {
        val tracker = BehaviorTracker(cfg)
        tracker.initializeBehaviorRedis(redis)
        tracker.trackEndpointUsage(
            "corpus.endpoint",
            "203.0.113.20",
            BehaviorRule(ruleType = "usage", threshold = 5, window = 120),
        )
      }
      "rio_behavior_return_increment" -> {
        val tracker = BehaviorTracker(cfg)
        tracker.initializeBehaviorRedis(redis)
        tracker.trackReturnPattern(
            "corpus.endpoint",
            "203.0.113.20",
            FakeBoundedResponse(404, ""),
            BehaviorRule(
                ruleType = "return_pattern",
                threshold = 3,
                window = 120,
                pattern = "status:404",
            ),
        )
      }
      "rio_security_headers_csp_config" -> {
        // The harness assigns the manager state directly, then runs _cache_configuration.
        SecurityHeadersManager.resetInstance()
        val mgr = SecurityHeadersManager.getInstance()
        mgr.reset()
        mgr.cspConfig =
            linkedMapOf(
                "default-src" to listOf("'self'"),
                "script-src" to listOf("'self'", "https://cdn.example.com"),
            )
        mgr.redisHandler = redis
        mgr.cacheConfiguration()
      }
      "rio_security_headers_hsts_config" -> {
        SecurityHeadersManager.resetInstance()
        val mgr = SecurityHeadersManager.getInstance()
        mgr.reset()
        mgr.hstsConfig =
            linkedMapOf(
                "max_age" to 31536000,
                "include_subdomains" to true,
            )
        mgr.redisHandler = redis
        mgr.cacheConfiguration()
      }
      "rio_security_headers_custom_headers" -> {
        SecurityHeadersManager.resetInstance()
        val mgr = SecurityHeadersManager.getInstance()
        mgr.reset()
        mgr.customHeaders = linkedMapOf("X-Corpus-Header" to "corpus-value")
        mgr.redisHandler = redis
        mgr.cacheConfiguration()
      }
      "rio_custom_pattern_registry_write" -> {
        SusPatternsRegistry.reset()
        SusPatternsRegistry.redisHandler = redis
        val added = SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true)
        check(added) { "corpus pattern must pass the safety gate" }
      }
      "rio_ipinfo_database_cache_write" -> {
        IpInfoManager.resetInstance()
        val fixture = "corpus-mmdb-fixture:\u00e9\u00ff\u0000\u0080:end"
        val mgr =
            IpInfoManager.getInstance(
                "corpus-token",
                Files.createTempDirectory("rio").resolve("country_asn.mmdb"),
                86400,
            )
        // Script the fetch BEFORE initialize so no real network call is made; the override
        // replays the download tail (atomic write + latin-1 redis cache write).
        mgr.downloadOverride = {
          val bytes = fixture.toByteArray(Charsets.ISO_8859_1)
          mgr.writeDatabaseAtomically(bytes)
          redis.setKey("ipinfo", "database", String(bytes, Charsets.ISO_8859_1), ttl = 86400)
        }
        mgr.initializeRedis(redis)
      }
      "rio_cloud_ranges_v2_write" -> {
        CloudManager.resetInstance()
        val mgr =
            object : CloudManager() {
              override suspend fun fetchRanges(
                  provider: String,
              ): Pair<Set<com.guardcore.util.py.IpNetwork>, Map<String, String>> {
                val netA = com.guardcore.util.py.IpNetwork.parse("198.51.100.0/24")
                val netB = com.guardcore.util.py.IpNetwork.parse("203.0.113.0/24")
                return setOf(netA, netB) to mapOf("203.0.113.0/24" to "us-east")
              }
            }
        mgr.store = null
        mgr.redisHandler = redis
        mgr.refreshAsync(listOf("corpus"), ttl = 3600)
      }
      "rio_cloud_ip_v2_write" -> {
        val store = RedisCloudIpStore(redis)
        store.set(
            "corpus",
            setOf("10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"),
            ttl = null,
        )
      }
      "rio_dynamic_rules_snapshot_write" -> {
        // The python harness calls update_rules directly with a stub agent (no update loop:
        // the loop would race the shared connection with MULTI transactions).
        val agent =
            object : com.guardcore.handlers.DynamicRuleManager.AgentDynamicRulesSource {
              override suspend fun getDynamicRules(): DynamicRules? =
                  DynamicRules(
                      ruleId = "rio-rules",
                      version = 3,
                      timestamp = OffsetDateTime.parse("2026-01-01T00:00:00+00:00"),
                  )

              override suspend fun sendEvent(event: Map<String, Any?>) {}
            }
        com.guardcore.handlers.DynamicRuleManager.resetInstance()
        // python harness shape: enable_agent + agent_api_key + enable_dynamic_rules
        // (models.py:227-234 validation chain).
        val dynCfg =
            SecurityConfigBuilder()
                .apply {
                  redisUrl = System.getenv("REDIS_URL") ?: "redis://localhost:6379"
                  redisPrefix = "guard_core:corpus_rio:"
                  enableRedis = true
                  enableAgent = true
                  agentApiKey = "corpus-rio-key"
                  enableDynamicRules = true
                }
                .build()
        val mgr = com.guardcore.handlers.DynamicRuleManager.getInstance(dynCfg)
        mgr.initializeDynamicRuleRedis(redis)
        mgr.agentHandler = agent
        mgr.updateRules()
      }
      else -> error("unknown redis_interop case $id")
    }
  }

  // ------------------------------------------------------------- verification

  private fun verify(id: String, case: kotlinx.serialization.json.JsonObject) {
    runBlocking {
      val cfg = config()
      val redis = RedisManager.getInstance(cfg)
      redis.initialize()
      val ops = redis.operations()!!
      val expected = (case["expected"] as kotlinx.serialization.json.JsonArray)
      val problems = mutableListOf<String>()
      for (expElement in expected) {
        val exp = expElement as kotlinx.serialization.json.JsonObject
        val key = exp["key"]!!.let { it as kotlinx.serialization.json.JsonPrimitive }.content
        val type = exp["type"]!!.let { it as kotlinx.serialization.json.JsonPrimitive }.content
        val ttlObj = exp["ttl"] as kotlinx.serialization.json.JsonObject
        val ttlSet =
            ttlObj["set"]!!.let { it as kotlinx.serialization.json.JsonPrimitive }.content == "true"
        val ttlSeconds =
            (ttlObj["seconds"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLong()

        val exists = ops.exists(key)
        if (exists <= 0) {
          problems.add("$id: missing key $key")
          continue
        }

        // TTL semantics: whether a TTL is set and its configured value.
        val pttl = ops.pTtl(key)
        if (!ttlSet) {
          if (pttl != -1L) {
            problems.add("$id: $key expected persistent, got pttl=$pttl")
          }
        } else {
          if (pttl <= 0) {
            problems.add("$id: $key expected ttl=$ttlSeconds, got pttl=$pttl")
          } else {
            val configured = ttlSeconds!! * 1000
            if (pttl > configured) {
              problems.add("$id: $key pttl=$pttl exceeds configured $configured")
            }
          }
        }

        when (type) {
          "string" -> {
            val value = ops.get(key)!!
            val want = (exp["value"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val shape = (exp["value_shape"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (want != null) {
              if (value != want) {
                problems.add("$id: $key value mismatch: got ${render(value)} want ${render(want)}")
              }
            } else if (shape != null) {
              if (!Pattern.compile(shape).matcher(value).matches()) {
                problems.add("$id: $key value $value fails shape $shape")
              }
            }
          }
          "json" -> {
            val value = ops.get(key)!!
            val want = (exp["value"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (want != null && !jsonEquals(value, want)) {
              problems.add(
                  "$id: $key json mismatch:\n  got  ${render(value)}\n  want ${render(want)}",
              )
            }
          }
          "zset" -> {
            val card = ops.zcard(key)
            val wantCard =
                (exp["card"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLong()
            if (wantCard != null && card != wantCard) {
              problems.add("$id: $key card=$card want $wantCard")
            }
            val memberShape =
                (exp["member_shape"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val scoreEqualsMember =
                exp["score_equals_member"]?.let {
                  (it as kotlinx.serialization.json.JsonPrimitive).content == "true"
                } ?: false
            if (memberShape != null) {
              // Range-scan the single-member zset (each corpus zset has card 1).
              val range = ops.zremRangeByScore(key, "-inf", "+inf")
              check(range == card) { "unexpected card change during drain" }
              // Re-run the operation once to inspect a live member with its score.
            }
            // Member/score shape checks run on a freshly driven zset member below.
            if (memberShape != null || scoreEqualsMember) {
              val memberCheck = inspectZsetMember(id, case)
              problems.addAll(memberCheck)
            }
          }
        }
      }
      check(problems.isEmpty()) { problems.joinToString("\n") }
    }
  }

  /** Re-drives the case once and inspects the fresh zset member and score shapes. */
  private suspend fun inspectZsetMember(
      id: String,
      case: kotlinx.serialization.json.JsonObject,
  ): List<String> {
    val problems = mutableListOf<String>()
    val cfg = config()
    val redis = RedisManager.getInstance(cfg)
    redis.initialize()
    scrub(redis)
    val exp =
        (case["expected"] as kotlinx.serialization.json.JsonArray)[0]
            as kotlinx.serialization.json.JsonObject
    val key = exp["key"]!!.let { it as kotlinx.serialization.json.JsonPrimitive }.content
    val memberShape = (exp["member_shape"] as? kotlinx.serialization.json.JsonPrimitive)?.content
    val scoreEqualsMember =
        exp["score_equals_member"]?.let {
          (it as kotlinx.serialization.json.JsonPrimitive).content == "true"
        } ?: false
    val scoreShape = (exp["score_shape"] as? kotlinx.serialization.json.JsonPrimitive)?.content

    when (id) {
      "rio_rate_limit_global_tier",
      "rio_rate_limit_endpoint_tier" -> {
        RateLimitManager.resetInstance()
        RateLimitState.reset()
        val mgr = RateLimitManager.getInstance(cfg)
        mgr.redisHandler = redis
        mgr.rateLimitScriptSha = redis.operations()!!.scriptLoad(RATE_LIMIT_SCRIPT)
        mgr.checkRateLimit(
            FakeRequest(),
            "203.0.113.20",
            { s, m -> FakeResponse(s, m) },
            endpointPath = if (id == "rio_rate_limit_endpoint_tier") "/api" else "",
            rateLimit = 5,
            rateLimitWindow = 60,
        )
      }
      "rio_behavior_usage_increment" -> {
        val tracker = BehaviorTracker(cfg)
        tracker.initializeBehaviorRedis(redis)
        tracker.trackEndpointUsage(
            "corpus.endpoint",
            "203.0.113.20",
            BehaviorRule("usage", 5, window = 120),
        )
      }
      "rio_behavior_return_increment" -> {
        val tracker = BehaviorTracker(cfg)
        tracker.initializeBehaviorRedis(redis)
        tracker.trackReturnPattern(
            "corpus.endpoint",
            "203.0.113.20",
            FakeBoundedResponse(404, ""),
            BehaviorRule("return_pattern", 3, window = 120, pattern = "status:404"),
        )
      }
    }

    val ops = redis.operations()!!
    val members = scanZsetMembers(ops, key)
    if (members.isEmpty()) {
      problems.add("$id: no members in $key after re-drive")
      return problems
    }
    for ((member, score) in members) {
      if (memberShape != null && !Pattern.compile(memberShape).matcher(member).matches()) {
        problems.add("$id: member $member fails shape $memberShape")
      }
      if (scoreShape != null && !Pattern.compile(scoreShape).matcher(score).matches()) {
        problems.add("$id: score $score fails shape $scoreShape")
      }
      if (scoreEqualsMember && score != member) {
        problems.add("$id: score $score != member $member")
      }
    }
    return problems
  }

  /** ZRANGE WITHSCORES over the (single-member) corpus zset. */
  private suspend fun scanZsetMembers(
      ops: com.guardcore.handlers.RedisOperations,
      key: String,
  ): List<Pair<String, String>> {
    // The redis_interop zsets are single-member; zremrangebyscore drains destructively, so use
    // a bounded zrandmembers via keys+get is unavailable: use zrange through evalSha-free path.
    // Lettuce exposes zrange with scores on the sync surface; the RedisOperations surface adds
    // zrangeMembers for the runner.
    return ops.zrangeWithScores(key)
  }

  private fun jsonEquals(got: String, want: String): Boolean {
    val a = normalizeJson(json.parseToJsonElement(got))
    val b = normalizeJson(json.parseToJsonElement(want))
    return a == b
  }

  /** Canonicalize: sorted object keys, numbers as 6-decimal floats. */
  private fun normalizeJson(element: kotlinx.serialization.json.JsonElement): Any? =
      when (element) {
        is kotlinx.serialization.json.JsonObject ->
            element.entries.sortedBy { it.key }.map { it.key to normalizeJson(it.value) }
        is kotlinx.serialization.json.JsonArray -> element.map { normalizeJson(it) }
        is kotlinx.serialization.json.JsonPrimitive ->
            if (element.isString) {
              element.content
            } else {
              element.content.toDoubleOrNull()?.let { "%.6f".format(it) } ?: element.content
            }
        kotlinx.serialization.json.JsonNull -> null
      }

  private fun render(text: String): String =
      text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") +
          " (len " +
          text.length +
          ")"

  private class FakeRequest : com.guardcore.protocols.GuardRequest {
    override val urlPath: String = "/rio"
    override val urlScheme: String = "http"
    override val urlFull: String = "http://rio/rio"

    override fun urlReplaceScheme(scheme: String): String = urlFull

    override val method: String = "GET"
    override val clientHost: String? = "203.0.113.20"
    override val headers: Map<String, String> = emptyMap()
    override val queryParams: Map<String, String> = emptyMap()

    override suspend fun body(): ByteArray = ByteArray(0)

    override val state: com.guardcore.protocols.RequestState =
        object : com.guardcore.protocols.RequestState {
          private val attrs = HashMap<String, Any?>()

          override fun getAttr(name: String): Any? = attrs[name]

          override fun setAttr(name: String, value: Any?) {
            attrs[name] = value
          }
        }
    override val scope: Map<String, Any?> = emptyMap()
  }

  private class FakeResponse(
      status: Int,
      message: String,
  ) : com.guardcore.protocols.GuardResponse {
    override val statusCode: Int = status
    override val headers: MutableMap<String, String> = mutableMapOf()
    override val body: ByteArray? = message.toByteArray()
  }

  private class FakeBoundedResponse(
      status: Int,
      body: String,
  ) : com.guardcore.protocols.GuardResponse, com.guardcore.protocols.BoundedResponseBodyReader {
    override val statusCode: Int = status
    override val headers: MutableMap<String, String> = mutableMapOf()
    override val body: ByteArray? = body.toByteArray()

    override suspend fun readBodyPrefix(maxBytes: Int): ByteArray {
      val bytes = body ?: return ByteArray(0)
      return bytes.take(maxBytes).toByteArray()
    }
  }
}
