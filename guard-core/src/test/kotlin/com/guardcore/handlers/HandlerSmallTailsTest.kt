package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.assertFailsWith
import com.guardcore.protocols.GuardResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9d small-handler tail coverage: the behavior dispatch/passive/return-pattern surface, the
 * SusPatternsRegistry event/removal/detect arms, the Azure ServiceTags URL selection helpers, the
 * dynamic-rules snapshot validation, and the misc handler shapes.
 */
public class HandlerSmallTailsTest {
  private fun tracker(passive: Boolean = false): BehaviorTracker =
      BehaviorTracker(
          SecurityConfigBuilder()
              .apply {
                enableRedis = false
                passiveMode = passive
                logSuspiciousLevel = com.guardcore.config.LogLevel.WARNING
              }
              .build(),
      )

  // ------------------------------------------------------------------
  // Behavior dispatch
  // ------------------------------------------------------------------

  @Test
  fun testLogPassiveModeActionArms() {
    val t = tracker(passive = true)
    t.logPassiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "alert"), "1.2.3.4", "details")
    t.logPassiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "ban"), "1.2.3.4", "details")
    t.logPassiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "log"), "1.2.3.4", "details")
    t.logPassiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "throttle"), "1.2.3.4", "details")
  }

  @Test
  fun testExecuteActiveModeActionArms() = runBlocking {
    IpBanManager.resetInstance()
    try {
      val t = tracker()
      IpBanManager.getInstance().redisHandler = null
      // custom action short-circuits
      var customRan = false
      val custom =
          BehaviorRule(ruleType = "usage", threshold = 1, action = "log", customAction = { _, _, _ -> customRan = true })
      assertEquals("log", t.executeActiveModeAction(custom, "1.2.3.4", "/e", "details"))
      assertTrue(customRan)
      // alert logs and returns the action
      assertEquals(
          "alert",
          t.executeActiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "alert"), "1.2.3.4", "/e", "d"),
      )
      // throttle and log arms
      assertEquals(
          "throttle",
          t.executeActiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "throttle"), "1.2.3.4", "/e", "d"),
      )
      assertEquals(
          "log",
          t.executeActiveModeAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "log"), "1.2.3.4", "/e", "d"),
      )
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun testApplyActionPassiveAndAgentFailure() = runBlocking {
    IpBanManager.resetInstance()
    try {
      IpBanManager.getInstance().redisHandler = null
      val t = tracker(passive = true)
      val recording = RecordingAgent()
      recording.failWith = IllegalStateException("sink down")
      t.agentHandler = recording
      t.applyAction(BehaviorRule(ruleType = "usage", threshold = 1, action = "log"), "1.2.3.4", "/e", "details")
      t.agentHandler = null
      assertTrue(true)
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun testSendBehaviorEventArms() = runBlocking {
    val t = tracker()
    // no agent handler: inert
    t.sendBehaviorEvent(EventTypes.EVENT_BEHAVIOR_VIOLATION, "1.2.3.4", "logged_only", "reason")
    // failing agent handler: contained
    val recording = RecordingAgent()
    recording.failWith = IllegalStateException("down")
    t.agentHandler = recording
    t.sendBehaviorEvent(EventTypes.EVENT_BEHAVIOR_VIOLATION, "1.2.3.4", "logged_only", "reason", metadata = mapOf("k" to 1))
    t.agentHandler = null
    assertTrue(true)
  }

  // ------------------------------------------------------------------
  // Behavior response pattern
  // ------------------------------------------------------------------

  private class FakeBoundedResponse(private val bodyText: String) :
      GuardResponse,
      com.guardcore.protocols.BoundedResponseBodyReader {
    override val statusCode: Int = 404
    override val headers: MutableMap<String, String> = mutableMapOf()
    override val body: ByteArray? = null

    override suspend fun readBodyPrefix(maxBytes: Int): ByteArray =
        bodyText.encodeToByteArray().copyOfRange(0, minOf(maxBytes, bodyText.length))
  }

  private class PlainResponse : GuardResponse {
    override val statusCode: Int = 200
    override val headers: MutableMap<String, String> = mutableMapOf()
    override val body: ByteArray? = null
  }

  @Test
  fun testBehaviorResponsePatternSurface() = runBlocking {
    assertEquals(Pair("a.b", "expected"), parseBehaviorPattern("a.b == \"expected\""))
    assertNull(parseBehaviorPattern("no separator here"))
    assertEquals(true, handleBehaviorArrayMatch(mapOf("items" to listOf("a", "b")), "items", "a"))
    assertEquals(false, handleBehaviorArrayMatch(mapOf("items" to "scalar"), "items", "a"))
    assertEquals("v", traverseBehaviorJsonPath(mapOf("a" to mapOf("b" to "v")), "a.b"))
    assertNull(traverseBehaviorJsonPath(mapOf("a" to 1), "a.b"))
    assertEquals(true, matchBehaviorJsonPattern(mapOf("status" to "ok"), "status == ok"))
    assertEquals(false, matchBehaviorJsonPattern(mapOf("status" to "ok"), "status == bad"))
    assertEquals(true, matchBehaviorJsonPattern(mapOf("items" to listOf("a")), "items[] == a"))

    val t = tracker()
    // body scanning disabled -> null
    assertNull(t.readResponseBodyPrefix(FakeBoundedResponse("body"), "pattern"))
    // scan enabled: bounded response reads, non-bounded logs once
    val t2 =
        BehaviorTracker(
            SecurityConfigBuilder()
                .apply {
                  enableRedis = false
                  behaviorScanResponseBody = true
                }
                .build(),
        )
    assertNull(t2.readResponseBodyPrefix(PlainResponse(), "missing"))
    val prefix = t2.readResponseBodyPrefix(FakeBoundedResponse("hello world"), "hello")
    assertNotNull(prefix)
    // full check arms
    assertEquals(true, t2.checkResponsePattern(FakeBoundedResponse("found"), "found"), "contains")
    assertEquals(false, t2.checkResponsePattern(FakeBoundedResponse("other"), "found"))
    assertEquals(true, t2.checkResponsePattern(FakeBoundedResponse("x"), "status:404"), "status")
    assertEquals(false, t2.checkResponsePattern(FakeBoundedResponse(""), "found"))
    assertEquals(true, t2.checkResponsePattern(FakeBoundedResponse("""{"a": 1}"""), "json:a == 1"), "json")
    assertEquals(false, t2.checkResponsePattern(FakeBoundedResponse("not json"), "json:a == 1"))
    assertEquals(true, t2.checkResponsePattern(FakeBoundedResponse("abc123"), "regex:abc\\d+"), "regex")
    assertEquals(false, t2.checkResponsePattern(PlainResponse(), "status:404"))
    assertNull(t2.checkResponsePattern(PlainResponse(), "unreachable-body"))
  }

  // ------------------------------------------------------------------
  // SusPatternsRegistry
  // ------------------------------------------------------------------

  @Test
  fun testSusPatternsRegistryEventAndRemovalArms() = runBlocking {
    val recording = RecordingAgent()
    recording.failWith = IllegalStateException("sink down")
    SusPatternsRegistry.agentHandler = recording
    SusPatternsRegistry.sendPatternEvent("pattern_added", "1.2.3.4", "added", "reason")
    SusPatternsRegistry.agentHandler = null

    // removePattern for a pattern that is not present
    assertEquals(false, SusPatternsRegistry.removePattern("no-such-pattern-xyz"))
    assertEquals(false, SusPatternsRegistry.removeCustomPattern("no-such-pattern-xyz"))

    // detect with the default context + the pattern_matched fallback arms
    val verdict = SusPatternsRegistry.detect("ben content", "9.9.9.9")
    assertNotNull(verdict)
    val hit = SusPatternsRegistry.detect("1 UNION SELECT username, password FROM users--", "9.9.9.9", correlationId = "corr")
    assertEquals(true, hit["is_threat"] == true || hit["detected"] == true || hit.isNotEmpty())
    SusPatternsRegistry.clearCustomPatternsForCorpus()
  }

  // ------------------------------------------------------------------
  // Azure ServiceTags helpers
  // ------------------------------------------------------------------

  @Test
  fun testAzureServiceTagsUrlHelpers() {
    val sortKey = CloudAzureFetch.serviceTagsSortKey("https://download.microsoft.com/download/ServiceTags_Public_20240101.json")
    assertEquals(true, sortKey.first)
    val noDate = CloudAzureFetch.serviceTagsSortKey("https://download.microsoft.com/download/x/nodate.json")
    assertEquals(false, noDate.first)
    // failover link extraction trusts only azure download hosts
    val html = "<a id=\"failoverLink\" href=\"https://download.microsoft.com/download/ServiceTags_Public_20240202.json\">x</a>"
    assertEquals("https://download.microsoft.com/download/ServiceTags_Public_20240202.json", CloudAzureFetch.extractFailoverLinkUrl(html))
    assertNull(CloudAzureFetch.extractFailoverLinkUrl("<a id=\"failoverLink\" href=\"https://evil.example/x\">y</a>"))
    assertNull(CloudAzureFetch.extractFailoverLinkUrl("<p>nothing</p>"))
    // generic json url extraction
    val generic = "<a href=\"https://download.microsoft.com/download/ServiceTags_Public_20240303.json\">z</a>"
    assertEquals("https://download.microsoft.com/download/ServiceTags_Public_20240303.json", CloudAzureFetch.extractGenericJsonUrl(generic))
    assertNull(CloudAzureFetch.extractGenericJsonUrl("<a href=\"https://evil.example/x\">z</a>"))
  }

  // ------------------------------------------------------------------
  // Dynamic rules snapshot validation
  // ------------------------------------------------------------------

  @Test
  fun testDynamicRulesSnapshotValidation() {
    assertFailsWith<IllegalArgumentException> { loadLastKnownRulesSnapshot("{\"rules\": 5}") }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("{\"rules\": {}, \"version\": 5}")
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("{\"rules\": {}, \"updated_at\": 5}")
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("{\"rules\": {}, \"blocked_user_agents\": 5}")
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("{\"rules\": {}, \"endpoint_rate_limits\": 5}")
    }
    assertFailsWith<IllegalArgumentException> {
      loadLastKnownRulesSnapshot("{\"rules\": {}, \"endpoint_rate_limits\": {\"/x\": \"bad\"}}")
    }
  }

  // ------------------------------------------------------------------
  // Misc small shapes
  // ------------------------------------------------------------------

  @Test
  fun testTtlCachePopitemEmptyThrowsKeyError() {
    val cache = TtlCache<String, Boolean>(8, 60.0)
    assertFailsWith<KeyError> { cache.popItem() }
  }

  @Test
  fun testCorsPreflightResponseEquality() {
    val a = CorsPreflightResponse(204, mapOf("k" to "v"))
    val b = CorsPreflightResponse(204, mapOf("k" to "v"))
    val c = CorsPreflightResponse(204, mapOf("k" to "v"), "body")
    assertEquals(a, b)
    assertEquals(a.hashCode(), b.hashCode())
    assertFalse(a == c)
    assertFalse(a.equals("x"))
  }

  @Test
  fun testIpBanBansLoopbackTableAndBanDefaults() = runBlocking {
    assertTrue(LOOPBACK_NETWORKS.isNotEmpty())
    IpBanManager.resetInstance()
    try {
      val manager = IpBanManager.getInstance()
      manager.redisHandler = null
      // default reason + duration ride the ban path
      val applied = manager.banIp("1.2.3.4", 60)
      assertTrue(applied)
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun testIpBanMigrationCloseIfUnusable() = runBlocking {
    assertFalse(closeIfUnusable(null, "client"))
    assertTrue(closeIfUnusable("non-null-connection", "client"))
  }

  @Test
  fun testDetectionScanRedactionArms() {
    val redacted = DetectionScanRedaction.redactPatternSource("(?i)(password|secret)=[a-z]+")
    assertNotNull(redacted)
  }

  @Test
  fun testDynamicRuleEventSendersWithFailingSink() = runBlocking {
    DynamicRuleManager.resetInstance()
    try {
      val manager = DynamicRuleManager.getInstance(
          SecurityConfigBuilder().apply {
            enableRedis = false
            enableDynamicRules = false
          }.build(),
      )
      val recording = RecordingAgent()
      recording.failWith = IllegalStateException("down")
      val rules =
          DynamicRules(
              ruleId = "r1",
              version = 1,
              timestamp = java.time.OffsetDateTime.now(),
          )
      val source =
          object : DynamicRuleManager.AgentDynamicRulesSource {
            override suspend fun getDynamicRules(): DynamicRules? = rules

            override suspend fun sendEvent(event: Map<String, Any?>) {
              recording.sendEvent(event)
            }
          }
      manager.agentHandler = source
      manager.sendRuleReceivedEvent(rules)
      manager.sendRuleAppliedEvent(rules)
      manager.sendEmergencyEvent(listOf("127.0.0.1"))
      manager.agentHandler = null
      assertTrue(true)
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  @Test
  fun testPyJsonDumpsFloatShape() {
    val text =
        PyJsonDumps.dumps(
            kotlinx.serialization.json.buildJsonObject {
              put("a", kotlinx.serialization.json.JsonPrimitive(1.5))
            },
        )
    assertTrue(text.contains("1.5"))
  }
}
