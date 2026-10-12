package com.guardcore.conformance

import com.guardcore.decorators.RouteConfig
import com.guardcore.engine.suspatterns.DetectResult
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.engine.suspatterns.Threat
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * W9e arm closure for the conformance harnesses: the seeded scratch arms the pinned corpus never
 * drives (PipelineHarness members, EventsHarness config/route keys and redis ops) plus the
 * comparison-runner failure tables. The pinned corpus under conformance/guard-core-spec-4.1.0/ is
 * never touched; every seeded corpus lives in a temp directory.
 */
class HarnessArmsW9eTest {
  private class NullRedisHandler : com.guardcore.protocols.RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
        null

    override suspend fun delete(namespace: String, key: String): Int? = null

    override suspend fun keys(pattern: String): List<String>? = null

    override suspend fun initialize() {}

    override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
        object : com.guardcore.protocols.GuardRedisConnection {
          override val client: Any? = null

          override fun close() {}
        }
  }

  /** Minimal agent double: every lifecycle member is a no-op. */
  private class NullAgentHandler : com.guardcore.protocols.AgentHandlerProtocol {
    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun sendEvent(event: Any?) {}

    override suspend fun sendMetric(metric: Any?) {}

    override suspend fun start() {}

    override suspend fun stop() {}

    override suspend fun flushBuffer() {}

    override suspend fun getDynamicRules(): Any? = null

    override suspend fun healthCheck(): Boolean = true
  }

  // ------------------------------------------------------------ PipelineHarness

  @Test
  fun `pipeline harness event bus and stub members answer directly`() = runBlocking {
    val bus = PipelineHarness.RecordingEventBus()
    val request = PipelineHarness.PipelineRequest.of(mapOf("client_ip" to "203.0.113.7"))
    bus.sendHttpsViolationEvent(request, null)
    assertEquals(listOf("https_enforced" to "https_redirect"), bus.events)

    val route = RouteConfig()
    route.blockCloudProviders = linkedSetOf("AWS")
    bus.sendCloudDetectionEvents(request, "203.0.113.7", listOf("AWS"), route, null, false)
    bus.sendCloudDetectionEvents(request, "203.0.113.7", listOf("AWS"), route, null, true)
    bus.sendCloudDetectionEvents(request, "203.0.113.7", listOf("AWS"), null, null, false)
    assertEquals(
        listOf(
            "https_enforced" to "https_redirect",
            "decorator_violation" to "request_blocked",
            "decorator_violation" to "logged_only",
        ),
        bus.events,
    )

    val geo = PipelineHarness.StubGeoHandler(mapOf("203.0.113.7" to "US"))
    assertEquals("US", geo.getCountry("203.0.113.7"))
    geo.initialize()
    geo.initializeRedis(NullRedisHandler())
    geo.initializeAgent(NullAgentHandler())
    geo.refresh()
    geo.close()

    val bypassed = RouteConfig()
    bypassed.bypassedChecks = mutableSetOf("rate_limit")
    val resolver = PipelineHarness.StubRouteResolver(mapOf("/api" to route))
    assertEquals(listOf("AWS"), resolver.getCloudProvidersToCheck(route))
    assertNull(resolver.getCloudProvidersToCheck(RouteConfig()))
    assertNull(resolver.getCloudProvidersToCheck("not-a-route-config"))
    assertTrue(resolver.shouldBypassCheck("rate_limit", bypassed))

    val factory = PipelineHarness.HarnessResponseFactory()
    val redirect = factory.createRedirectResponse("http://example.com/api", 301)
    assertEquals(301, redirect.statusCode)
    assertEquals("http://example.com/api", redirect.headers["Location"])
    val httpsRedirect = factory.createHttpsRedirect(request)
    assertEquals(301, httpsRedirect.statusCode)
    assertEquals("https://example.com", httpsRedirect.headers["Location"])
    val modified = factory.applyModifier(factory.createResponse("ok", 200))
    assertEquals(200, modified.statusCode)
  }

  @Test
  fun `pipeline harness middleware surface members answer`() = runBlocking {
    val case = PipelineHarness.HarnessCase(mapOf("drives" to emptyList<Any?>()))
    val middleware = case.middleware
    val saved = middleware.lastCloudIpRefresh
    middleware.lastCloudIpRefresh = saved + 5
    assertEquals(saved + 5, middleware.lastCloudIpRefresh)
    assertEquals(null, middleware.guardResponseFactory)
    middleware.refreshCloudIpRanges()
    assertEquals(null, middleware.agentHandler)
  }

  @Test
  fun `pipeline harness case insensitive headers expose the full map surface`() {
    val headers =
        PipelineHarness.CaseInsensitiveHeaders(mapOf("User-Agent" to "ua", "Accept" to "text"))
    assertEquals(2, headers.size)
    assertEquals(setOf("user-agent", "accept"), headers.keys)
    assertEquals(listOf("ua", "text"), headers.values.toList())
    assertFalse(headers.isEmpty())
    assertTrue(headers.containsKey("USER-AGENT"))
    assertFalse(headers.containsKey("x-missing"))
    assertTrue(headers.containsValue("text"))
    assertFalse(headers.containsValue("nope"))
    assertEquals("ua", headers["user-agent"])
    assertEquals(null, headers["X-MISSING"])
    assertTrue(headers.entries.isNotEmpty())
    val empty = PipelineHarness.CaseInsensitiveHeaders(emptyMap())
    assertEquals(0, empty.size)
    assertTrue(empty.isEmpty())
  }

  @Test
  fun `pipeline harness case builder walks every seeded route and config key`() {
    val case =
        PipelineHarness.HarnessCase(
            mapOf(
                "geo_countries" to mapOf("203.0.113.7" to "CN"),
                "config" to
                    mapOf(
                        "cors_allow_methods" to listOf("GET", "POST"),
                        "cors_allow_headers" to listOf("X-Custom"),
                        "enable_penetration_detection" to true,
                        "enable_rate_limit_auto_ban" to false,
                        "global_behavior_rules" to
                            listOf(mapOf("rule_type" to "usage", "threshold" to 5)),
                    ),
                "routes" to
                    mapOf(
                        "/api" to
                            mapOf(
                                "ip_whitelist" to listOf("203.0.113.8"),
                                "ip_blacklist" to listOf("203.0.113.9"),
                                "blocked_countries" to listOf("CN"),
                                "whitelist_countries" to listOf("US"),
                                "bypassed_checks" to listOf("rate_limit"),
                                "excluded_detection_params" to listOf("q"),
                                "excluded_detection_body_fields" to listOf("secret"),
                                "geo_rate_limits" to mapOf("CN" to listOf(5, 60)),
                            ),
                    ),
            ),
        )
    assertEquals("CN", case.geo.getCountry("203.0.113.7"))
    val route = assertNotNull(case.routes["/api"])
    assertEquals(listOf("203.0.113.8"), route.ipWhitelist)
    assertEquals(listOf("203.0.113.9"), route.ipBlacklist)
    assertEquals(listOf("CN"), route.blockedCountries)
    assertEquals(listOf("US"), route.whitelistCountries)
    assertEquals(setOf("rate_limit"), route.bypassedChecks)
    assertEquals(setOf("q"), route.excludedDetectionParams)
    assertEquals(setOf("secret"), route.excludedDetectionBodyFields)
    assertEquals(mapOf("CN" to (5 to 60)), route.geoRateLimits)
    assertEquals(listOf("GET", "POST"), case.config.corsAllowMethods)
    assertEquals(listOf("X-Custom"), case.config.corsAllowHeaders)
    assertTrue(case.config.enablePenetrationDetection)
    assertFalse(case.config.enableRateLimitAutoBan)
    assertEquals(1, case.config.globalBehaviorRules.size)
    // a rule without "action" defaults to RuleAction.LOG
    assertEquals(com.guardcore.config.RuleAction.LOG, case.config.globalBehaviorRules[0].action)

    // the routes-elvis arm: a case without "routes" keeps an empty table
    val bare = PipelineHarness.HarnessCase(mapOf("drives" to emptyList<Any?>()))
    assertTrue(bare.routes.isEmpty())
    assertTrue(bare.config.enablePenetrationDetection)
  }

  @Test
  fun `pipeline harness runCase drives process_response and rejects unknown stages`() {
    val seed =
        PipelineHarness.runCase(
            mapOf(
                "drives" to
                    listOf(
                        mapOf(
                            "stage" to "process_response",
                            "url_path" to "/api",
                            "client_ip" to "203.0.113.7",
                            "response_status" to 200,
                            "response_body" to "fine",
                        ),
                    ),
            ),
        )
    assertEquals(1, seed.size)
    assertEquals(200, seed[0]["status"])

    val error =
        assertFailsWith<IllegalArgumentException> {
          PipelineHarness.runCase(
              mapOf(
                  "drives" to listOf(mapOf("stage" to "wat", "client_ip" to "203.0.113.7")),
              ),
          )
        }
    assertTrue(error.message!!.contains("unknown drive stage wat"), error.message)
  }

  @Test
  fun `pipeline harness config key applier walks the remaining keys`() {
    val geo = PipelineHarness.StubGeoHandler(emptyMap())
    val builder = com.guardcore.config.SecurityConfigBuilder()
    PipelineHarness.applyPipelineConfigKey(builder, "cors_allow_methods", listOf("PUT"), geo)
    PipelineHarness.applyPipelineConfigKey(builder, "cors_allow_headers", listOf("X-A"), geo)
    PipelineHarness.applyPipelineConfigKey(
        builder,
        "global_behavior_rules",
        listOf(mapOf("rule_type" to "return_pattern", "threshold" to 3, "pattern" to "pw")),
        geo,
    )
    PipelineHarness.applyPipelineConfigKey(builder, "behavior_scan_response_body", true, geo)
    PipelineHarness.applyPipelineConfigKey(builder, "enable_rate_limiting", false, geo)
    PipelineHarness.applyPipelineConfigKey(builder, "enable_penetration_detection", false, geo)
    PipelineHarness.applyPipelineConfigKey(builder, "enable_ip_banning", true, geo)
    PipelineHarness.applyPipelineConfigKey(builder, "enable_rate_limit_auto_ban", true, geo)
    val config = builder.build()
    assertEquals(listOf("PUT"), config.corsAllowMethods)
    assertEquals(listOf("X-A"), config.corsAllowHeaders)
    assertEquals(com.guardcore.config.RuleAction.LOG, config.globalBehaviorRules[0].action)
    assertFalse(config.enableRateLimiting)
    assertFalse(config.enablePenetrationDetection)
    assertTrue(config.enableIpBanning)
    assertTrue(config.enableRateLimitAutoBan)
  }

  // ------------------------------------------------------------ EventsHarness

  @Test
  fun `events harness case builder walks the seeded config and route keys`() {
    val case =
        EventsHarness.EventsCase(
            mapOf(
                "geo_countries" to mapOf("203.0.113.7" to "CN"),
                "config" to
                    mapOf(
                        "blocked_countries" to listOf("CN"),
                        "auto_ban_duration" to 120,
                        "block_cloud_providers" to listOf("AWS"),
                        "detection_anomaly_threshold" to 3.0,
                        "detection_min_samples_for_anomaly" to 12,
                        "detection_slow_pattern_threshold" to 0.5,
                        "emergency_whitelist" to listOf("203.0.113.1"),
                    ),
                "routes" to
                    mapOf(
                        "/api" to
                            mapOf(
                                "require_https" to true,
                                "rate_limit" to 7,
                                "rate_limit_window" to 42,
                                "ip_whitelist" to listOf("203.0.113.8"),
                                "ip_blacklist" to listOf("203.0.113.9"),
                                "blocked_countries" to listOf("CN"),
                                "whitelist_countries" to listOf("US"),
                                "blocked_user_agents" to listOf("curl"),
                                "enable_suspicious_detection" to false,
                                "excluded_detection_headers" to listOf("x-internal"),
                                "excluded_detection_params" to listOf("q"),
                                "excluded_detection_body_fields" to listOf("secret"),
                                "geo_rate_limits" to mapOf("CN" to listOf(5, 60)),
                            ),
                    ),
            ),
        )
    assertEquals(120, case.config.autoBanDuration)
    assertEquals(setOf("AWS"), case.config.blockCloudProviders)
    assertEquals(3.0, case.config.detectionAnomalyThreshold)
    assertEquals(12, case.config.detectionMinSamplesForAnomaly)
    assertEquals(0.5, case.config.detectionSlowPatternThreshold)
    assertEquals(listOf("203.0.113.1"), case.config.emergencyWhitelist)
    assertNotNull(case.config.geoIpHandler)
    assertEquals(null, case.middleware.guardResponseFactory)
    val route = assertNotNull(case.routes["/api"])
    assertEquals(true, route.requireHttps)
    assertEquals(7, route.rateLimit)
    assertEquals(42, route.rateLimitWindow)
    assertEquals(listOf("203.0.113.8"), route.ipWhitelist)
    assertEquals(listOf("203.0.113.9"), route.ipBlacklist)
    assertEquals(listOf("CN"), route.blockedCountries)
    assertEquals(listOf("US"), route.whitelistCountries)
    assertEquals(listOf("curl"), route.blockedUserAgents)
    assertEquals(false, route.enableSuspiciousDetection)
    assertEquals(setOf("x-internal"), route.excludedDetectionHeaders)
    assertEquals(setOf("q"), route.excludedDetectionParams)
    assertEquals(setOf("secret"), route.excludedDetectionBodyFields)
    assertEquals(mapOf("CN" to (5 to 60)), route.geoRateLimits)

    // the routes-elvis arm: a case without routes keeps an empty table
    val bare = EventsHarness.EventsCase(mapOf("config" to emptyMap<String, Any?>()))
    assertTrue(bare.routes.isEmpty())
  }

  @Test
  fun `events harness runCase rejects unknown decorator senders`() {
    val error =
        assertFailsWith<IllegalStateException> {
          runBlocking {
            EventsHarness.runCase(
                mapOf(
                    "drives" to
                        listOf(
                            mapOf(
                                "call" to "decorator_event",
                                "send" to "send_unknown_event",
                                "client_ip" to "203.0.113.7",
                                "url_path" to "/api",
                            ),
                        ),
                ),
            )
          }
        }
    assertTrue(error.message!!.contains("unknown decorator sender"), error.message)
  }

  @Test
  fun `events harness redis connect error arm fails closed on a dead url`() = runBlocking {
    val sink =
        EventsHarness.runCase(mapOf("drives" to listOf(mapOf("call" to "redis_connect_error"))))
    // initialize() emits the redis_error envelope before rethrowing the GuardRedisError.
    val errors = sink.filter { it["event_type"] == "redis_error" }
    assertEquals(1, errors.size, sink.toString())
    assertEquals("connection_failed", errors[0]["action_taken"], sink.toString())
  }

  @Test
  fun `events harness redis connect error arm surfaces the guard when init succeeds`() =
      runBlocking {
        val error =
            assertFailsWith<IllegalStateException> {
              EventsHarness.runCase(
                  mapOf(
                      "drives" to
                          listOf(
                              mapOf(
                                  "call" to "redis_connect_error",
                                  // Simulate the guard's failure scenario: initialize() succeeds
                                  // against a LIVE redis where the corpus expects a dead one.
                                  "error_redis_url" to EventsHarness.EVENTS_REDIS_URL,
                              ),
                          ),
                  ),
              )
            }
        assertTrue(
            error.message!!.contains("corpus expected redis connection failure"),
            error.message,
        )
      }

  @Test
  fun `events harness script reload op produces the 429 through the harness error factory`() {
    val sink =
        EventsHarness.runCase(
            mapOf(
                "drives" to
                    listOf(
                        mapOf(
                            "call" to "rate_limit_script_reload",
                            "client_ip" to "203.0.113.61",
                            "url_path" to "/api",
                            "rate_limit" to 0,
                            "rate_limit_window" to 60,
                        ),
                    ),
            ),
        )
    val limited = sink.filter { it["event_type"] == "rate_limited" }
    assertTrue(limited.isNotEmpty(), sink.toString())
    assertEquals("request_blocked", limited[0]["action_taken"])
  }

  @Test
  fun `temp corpus dir helper returns a fresh directory`() {
    val dir = tempCorpusDir()
    assertTrue(Files.isDirectory(dir))
  }

  // ------------------------------------------------------------ comparison runners

  @Test
  fun `pattern safety runner chain module table resolves the probe arms`() {
    assertEquals(
        "guard-core-engine PatternCompiler.runPatternSafetyProbe " +
            "(python anchor: compiler._run_pattern_safety_probe_subprocess)",
        PatternSafetyRunner.chainModuleOf("probe_subprocess_timeout"),
    )
    assertEquals(
        "guard-core-engine CostArbiter/ReachProbe " +
            "(python anchor: _redos_cost_arbiter._reach_probe_cost_verdict)",
        PatternSafetyRunner.chainModuleOf("over_budget"),
    )
    // the CaseFailure default-value path
    val failure = PatternSafetyRunner.CaseFailure("case", "reason", observedSafe = true)
    assertEquals("", failure.observedClass)
  }

  @Test
  fun `pattern safety runner rejects a vacuous corpus`() {
    val root = Files.createTempDirectory("w9e-safety-vacuous")
    root
        .resolve("index.json")
        .writeText("""{"suites": {}, "config_knobs": {}, "fixed_ip": "203.0.113.1"}""")
    root
        .resolve("safety_gates.json")
        .writeText("""{"kind": "pattern_safety", "suite": "s", "cases": []}""")
    val error = assertFailsWith<IllegalStateException> { PatternSafetyRunner.runAll(root) }
    assertTrue(
        error.message!!.contains("matched zero cases: a vacuous pass is a failure"),
        error.message,
    )
  }

  @Test
  fun `cost budget runner default-arg loaders read the pinned corpus and reject empty budgets`() {
    // the default-parameter path: no corpus argument -> the vendored corpus
    val (k, floor, budgets) = CostBudgetRunner.loadBudgets()
    assertTrue(k > 0.0)
    assertTrue(floor >= 0.0)
    assertTrue(budgets.containsKey("cost_prose_8kib"))
    val cases = CostBudgetRunner.loadCases()
    assertTrue(cases.isNotEmpty())
    // an empty budgets map fails the load
    val root = Files.createTempDirectory("w9e-cost-empty")
    root
        .resolve("index.json")
        .writeText(
            """{"suites": {}, "config_knobs": {}, "fixed_ip": "203.0.113.1",
           "cost_budgets": {"k": 1.0, "floor_ms": 0.0, "budgets": {}}}""",
        )
    val error = assertFailsWith<IllegalStateException> { CostBudgetRunner.loadBudgets(root) }
    assertTrue(error.message!!.contains("no cost_budgets block"), error.message)
  }

  // ------------------------------------------------------------ detect runner

  private fun threatJson(t: Threat): JsonObject {
    val fields = LinkedHashMap<String, JsonElement>()
    fields["type"] = JsonPrimitive(t.type)
    if (t.type == "semantic") {
      fields["attack_type"] = JsonPrimitive(t.attackType ?: "suspicious")
      t.probability?.let { fields["probability"] = JsonPrimitive(it) }
    } else {
      fields["pattern"] = JsonPrimitive(t.pattern)
      fields["match"] = JsonPrimitive(t.match)
      fields["position"] = JsonPrimitive(t.position)
      fields["category"] = JsonPrimitive(t.category)
      fields["weight"] = JsonPrimitive(t.weight)
    }
    return JsonObject(fields)
  }

  private fun verdictJson(verdict: DetectResult): JsonObject =
      JsonObject(
          linkedMapOf(
              "is_threat" to JsonPrimitive(verdict.isThreat),
              "threat_score" to JsonPrimitive(DetectRunner.round6(verdict.threatScore)),
              "threats" to
                  JsonArray(DetectRunner.canonicalThreats(verdict.threats).map { threatJson(it) }),
              "original_length" to JsonPrimitive(verdict.originalLength),
              "processed_length" to JsonPrimitive(verdict.processedLength),
              "detection_method" to JsonPrimitive(verdict.detectionMethod),
          ),
      )

  private fun withField(base: JsonObject, key: String, value: JsonElement): JsonObject =
      JsonObject(LinkedHashMap(base).also { it[key] = value })

  private fun withThreatMutated(
      base: JsonObject,
      index: Int,
      mutate: (MutableMap<String, JsonElement>) -> Unit,
  ): JsonObject {
    val arr = (base.getValue("threats") as JsonArray).toMutableList()
    val first = LinkedHashMap(arr[index].jsonObject)
    mutate(first)
    arr[index] = JsonObject(first)
    return withField(base, "threats", JsonArray(arr))
  }

  @Test
  fun `detect runner comparison walks every threat-field mismatch arm`() {
    val shared = SusPatternsManager.shared()
    shared.configure(
        DetectRunner.asDetectionConfigView(com.guardcore.config.SecurityConfigBuilder().build()),
    )
    try {
      val regexVerdict = shared.detect("<script>alert(1)</script>", "203.0.113.7", "body")
      val semanticVerdict =
          shared.detect(
              "\${x} <t> (y) [z] {w} a://b c://d <b>call(f(x))</b> union select " +
                  "concat(database(),table_name) from information_schema.tables where 1=1 " +
                  "{{render(jinja(template(mustache(handlebars(ejs(pug(twig)))))))}}",
              "203.0.113.7",
              "request_body",
          )
      val cleanVerdict = shared.detect("hello world", "203.0.113.7", "body")
      val regexJson = verdictJson(regexVerdict)
      val semanticJson = verdictJson(semanticVerdict)
      val cleanJson = verdictJson(cleanVerdict)

      val regexIndex =
          DetectRunner.canonicalThreats(regexVerdict.threats).indexOfFirst { it.type == "regex" }
      val semanticIndex =
          DetectRunner.canonicalThreats(semanticVerdict.threats).indexOfFirst {
            it.type == "semantic"
          }
      assertTrue(regexIndex >= 0, "seeded regex content produced no regex threat")
      assertTrue(semanticIndex >= 0, "seeded semantic content produced no semantic threat")

      val cases: List<Pair<String, JsonObject>> =
          listOf(
              // threat-count mismatch (message renders the actual patterns)
              "count" to withField(regexJson, "threats", JsonArray(emptyList())),
              // per-field regex arms
              "type" to
                  withThreatMutated(regexJson, regexIndex) {
                    it["type"] = JsonPrimitive("semantic")
                  },
              "match" to
                  withThreatMutated(regexJson, regexIndex) {
                    it["match"] = JsonPrimitive(it.getValue("match").jsonPrimitive.content + "!")
                  },
              "position" to
                  withThreatMutated(regexJson, regexIndex) {
                    it["position"] =
                        JsonPrimitive(it.getValue("position").jsonPrimitive.content.toInt() + 1)
                  },
              "category" to
                  withThreatMutated(regexJson, regexIndex) {
                    it["category"] = JsonPrimitive("w9e_wrong_category")
                  },
              "weight" to
                  withThreatMutated(regexJson, regexIndex) {
                    it["weight"] = JsonPrimitive(it.getValue("weight").jsonPrimitive.double + 1.0)
                  },
              // semantic arms
              "attack_type" to
                  withThreatMutated(semanticJson, semanticIndex) {
                    it["attack_type"] = JsonPrimitive("w9e_wrong_attack")
                  },
              "probability" to
                  withThreatMutated(semanticJson, semanticIndex) {
                    it["probability"] =
                        JsonPrimitive(it.getValue("probability").jsonPrimitive.double + 0.5)
                  },
              // verdict-metadata arms over a clean verdict
              "original" to withField(cleanJson, "original_length", JsonPrimitive(-1)),
              "processed" to withField(cleanJson, "processed_length", JsonPrimitive(-1)),
              "method" to withField(cleanJson, "detection_method", JsonPrimitive("w9e_method")),
          )

      val root = Files.createTempDirectory("w9e-detect")
      root
          .resolve("index.json")
          .writeText(
              """{"suites": {"w9e_detect": {"kind": "detect", "description": "seeded"}},
             "config_knobs": {}, "fixed_ip": "203.0.113.7"}""",
          )
      val inputs =
          mapOf(
              "count" to regexVerdict,
              "type" to regexVerdict,
              "match" to regexVerdict,
              "position" to regexVerdict,
              "category" to regexVerdict,
              "weight" to regexVerdict,
              "attack_type" to semanticVerdict,
              "probability" to semanticVerdict,
              "original" to cleanVerdict,
              "processed" to cleanVerdict,
              "method" to cleanVerdict,
          )
      val semanticContent =
          "\${x} <t> (y) [z] {w} a://b c://d <b>call(f(x))</b> union select " +
              "concat(database(),table_name) from information_schema.tables where 1=1 " +
              "{{render(jinja(template(mustache(handlebars(ejs(pug(twig)))))))}}"
      val body =
          cases.joinToString(",", "[", "]") { (id, expected) ->
            val content =
                when (inputs[id]) {
                  regexVerdict -> "<script>alert(1)</script>"
                  semanticVerdict -> semanticContent
                  else -> "hello world"
                }
            val context = if (inputs[id] === semanticVerdict) "request_body" else "body"
            // JsonObject.toString() is valid JSON: embed it verbatim.
            """{"id": "$id", "input": {"content": "$content", "context": "$context"}, "expected": $expected}"""
          }
      root.resolve("w9e_detect.json").writeText("""{"cases": $body}""")

      val failures = DetectRunner.runAll(root)
      val byId = failures.associateBy { it.caseId }
      for ((id, _) in cases) {
        val failure =
            assertNotNull(byId[id], "missing failure for $id in ${failures.map { it.caseId }}")
        assertTrue(failure.reason.isNotEmpty(), id)
        assertEquals("w9e_detect", failure.suite, id)
      }
      assertTrue(byId.getValue("count").reason.startsWith("threat count:"))
      assertTrue(byId.getValue("type").reason.startsWith("threat[0] type:"))
      assertTrue(byId.getValue("match").reason.startsWith("threat[${regexIndex}] match:"))
      assertTrue(byId.getValue("position").reason.startsWith("threat[${regexIndex}] position:"))
      assertTrue(byId.getValue("category").reason.startsWith("threat[${regexIndex}] category:"))
      assertTrue(byId.getValue("weight").reason.startsWith("threat[${regexIndex}] weight:"))
      assertTrue(
          byId.getValue("attack_type").reason.startsWith("threat[${semanticIndex}] attack_type:"),
      )
      assertTrue(
          byId.getValue("probability").reason.startsWith("threat[${semanticIndex}] probability:"),
      )
      assertTrue(byId.getValue("original").reason.startsWith("original_length:"))
      assertTrue(byId.getValue("processed").reason.startsWith("processed_length:"))
      assertTrue(byId.getValue("method").reason.startsWith("detection_method:"))
    } finally {
      shared.configure(null)
    }
  }

  // ------------------------------------------------------------ events comparison

  @Test
  fun `events comparison renders diffs for absent and mismatched fields`() {
    assertEquals(
        listOf("event 0: no observed envelope"),
        EventsComparison.envelopeDiffs(0, mapOf("a" to 1), null),
    )
    val diffs =
        EventsComparison.envelopeDiffs(
            2,
            mapOf("missing" to "x", "absent_ok" to null),
            mapOf<String, Any?>(),
        )
    assertEquals(1, diffs.size)
    assertTrue(diffs[0].contains("field missing: want \"x\", got <absent>"), diffs[0])
    assertEquals(
        emptyList<String>(),
        EventsComparison.envelopeDiffs(0, mapOf("absent_ok" to null), mapOf<String, Any?>()),
    )
    val mismatch = EventsComparison.envelopeDiffs(1, mapOf("n" to 1.5), mapOf("n" to 2.5))
    assertEquals(1, mismatch.size)
    assertTrue(mismatch[0].contains("want 1.5, got 2.5"), mismatch[0])
    assertEquals(
        listOf("event count: want 2, got 1"),
        EventsComparison.streamDiffs(
            listOf(mapOf<String, Any?>("a" to 1), mapOf<String, Any?>("a" to 2)),
            listOf(mapOf<String, Any?>("a" to 1)),
        ),
    )
    assertEquals("\"s\"", EventsComparison.render("s"))
    assertEquals("42", EventsComparison.render(42))
    assertEquals("null", EventsComparison.render(null))
    assertEquals("[1,2]", EventsComparison.render(listOf(1, 2)))
    assertEquals("{a: 1}", EventsComparison.render(mapOf("a" to 1)))
    assertTrue(EventsComparison.valuesEqual(1, 1.0))
    assertFalse(EventsComparison.valuesEqual(1, 2.0))
  }
}
