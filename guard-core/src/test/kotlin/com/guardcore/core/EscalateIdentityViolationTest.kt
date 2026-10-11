package com.guardcore.core

import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.MiddlewareEventBusProtocol
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_escalate_identity_violation.py: the shared escalation helper's
 * counter, threshold-ban, event, and failure-isolation contract.
 *
 * Seam mapping: python monkeypatches `detect_penetration_patterns` and passes an AsyncMock ban
 * manager. The JVM drives the real engine (the request body carries the payload: the detected
 * categories ARE the real ones, which is exactly what the file pins) and the real [IpBanManager]
 * with its `banIpOverride` fault-injection seam as the recording ban mock. The
 * `_MAX_TRACKED_SUSPICIOUS_IPS` cap is a constant here (10,000), so the two capacity halves run at
 * real scale over a prefilled map (the python tests prefill the counts map too; only the cap value
 * differs).
 */
public class EscalateIdentityViolationTest {
  /**
   * python rebuilds every mock per test; the ban fault-injection seam lives on the process
   * singleton, so it is dropped after each test or it intercepts real bans in later classes.
   */
  @org.junit.jupiter.api.AfterEach
  fun dropBanOverride() {
    com.guardcore.handlers.IpBanManager.getInstance().banIpOverride = null
  }

  /** The payload rides the request path: the scan surface the real engine fires on. */
  private val xssPath = "/?q=<script>alert(1)</script>"
  private val mixedPath = "/?q=<script>alert(1)</script> UNION SELECT * FROM users"

  /** The python MagicMock(logger) analog: counts severe logs, optionally throwing. */
  private class RecordingLogger : Logger("test.escalate", null) {
    var severeCount: Int = 0
    var severeMessages: MutableList<String> = mutableListOf()
    var throwOnLog: Throwable? = null

    override fun log(level: Level, msg: String, thrown: Throwable) {
      if (level == Level.SEVERE) {
        severeCount += 1
        severeMessages.add(msg)
        throwOnLog?.let { throw it }
      }
    }
  }

  /** python's selective-failure event bus: ip_ban_failed emissions raise. */
  private class BanFailedFailingBus : MiddlewareEventBusProtocol {
    val events: MutableList<Map<String, Any?>> = mutableListOf()

    override suspend fun sendMiddlewareEvent(
        eventType: String,
        request: GuardRequest,
        actionTaken: String,
        reason: String,
        metadata: Map<String, Any?>,
    ) {
      if (eventType == "ip_ban_failed") {
        throw java.io.IOException("event bus down too")
      }
      events.add(
          linkedMapOf(
              "event_type" to eventType,
              "action_taken" to actionTaken,
              "reason" to reason,
          ) + metadata,
      )
    }

    override suspend fun sendHttpsViolationEvent(request: GuardRequest, routeConfig: Any?) {}

    override suspend fun sendCloudDetectionEvents(
        request: GuardRequest,
        clientIp: String,
        cloudProvidersToCheck: List<String>,
        routeConfig: Any?,
        cloudHandler: Any?,
        passiveMode: Boolean,
    ) {}
  }

  private fun middleware(
      config: com.guardcore.config.SecurityConfig,
      bus: com.guardcore.core.RecordingBus = com.guardcore.core.RecordingBus(),
  ): TestMiddleware = TestMiddleware(config, bus)

  private fun request(
      urlPath: String = xssPath,
      isWhitelisted: Boolean = false,
      routeConfig: RouteConfig? = null,
  ): TestRequest {
    val req = TestRequest(clientHost = "192.0.2.99", urlPath = urlPath)
    req.state.setAttr("is_whitelisted", isWhitelisted)
    req.state.setAttr("route_config", routeConfig)
    return req
  }

  private suspend fun escalate(
      mw: TestMiddleware,
      config: com.guardcore.config.SecurityConfig,
      clientIp: String,
      logger: Logger = Logger.getLogger("test.escalate.noop"),
      violationCategory: String = "ip_restriction",
      triggerInfo: String = "trigger",
      req: GuardRequest? = null,
  ) {
    ChecksHelpers.escalateIdentityViolation(
        mw,
        config,
        IpBanManager.getInstance(),
        req ?: request(),
        clientIp,
        logger,
        "ip_security",
        emptySet(),
        violationCategory,
        triggerInfo,
    )
  }

  private fun recordingBan(
      banCalls: MutableList<Triple<String, Int, String>>,
      failWith: Throwable? = null,
  ) {
    val manager = IpBanManager.getInstance()
    manager.banIpOverride = { ip, duration, reason ->
      // python's AsyncMock(side_effect=...) records the call, then raises.
      banCalls.add(Triple(ip, duration, reason))
      failWith?.let { throw it }
      true
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:50-73

  @Test
  fun whitelistedIpIsNeverEscalated() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "1.1.1.1", req = request(isWhitelisted = true))

      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
      assertEquals(0, mw.bus.events.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:76-97

  @Test
  fun falsyClientIpIsNoop() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "")

      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:99-123
  // python fakes the not_enabled detection verdict; the JVM reaches the identical verdict
  // through the real helper with penetration detection disabled.

  @Test
  fun noThreatNoCounterChangeNoBan() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "1.1.1.1")

      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
      assertEquals(0, mw.bus.events.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:125-146

  @Test
  fun disabledByDecoratorIsNoop() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = true
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = RouteConfig().apply { enableSuspiciousDetection = false }

      escalate(mw, config, "1.1.1.1", req = request(routeConfig = rc))

      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:148-176
  // python asserts the detection scan is never reached (a patched detect_penetration_attempt
  // raising AssertionError); the JVM observable for the same config is the full no-op triple.

  @Test
  fun neverReadsTheDetectionPipelineWhenNotConfigured() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "3.3.3.3")

      assertEquals(0, banCalls.size)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, mw.bus.events.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:179-201

  @Test
  fun incrementsTheRealDetectedThreatCategoryNotTheSyntheticLabel() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(
          mw,
          config,
          "2.2.2.2",
          violationCategory = "user_agent",
          triggerInfo = "Blocked user agent: curl",
      )

      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["2.2.2.2"])
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:204-225

  @Test
  fun incrementsEveryRealDetectedCategoryInOneCall() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(
          mw,
          config,
          "2.2.2.3",
          violationCategory = "ip_blocked",
          triggerInfo = "t",
          req = request(urlPath = mixedPath),
      )

      assertEquals<Map<String, Int>?>(
          mapOf("xss" to 1, "sqli" to 1),
          mw.suspiciousRequestCounts["2.2.2.3"],
      )
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:228-249
  // python fakes a threat verdict with no categories (unreachable through the real engine,
  // where every is_threat verdict carries at least one threat); the uncategorized fallback is
  // the defensive branch behind that mock and has no real-seam drive on the JVM.

  // ------------------------------- test_escalate_identity_violation.py:252-272

  @Test
  fun ipBanningDisabledNoBan() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = false
        autoBanThreshold = 1
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "3.3.3.3")

      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["3.3.3.3"])
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:275-295

  @Test
  fun belowFlatThresholdNoBan() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 5
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "4.4.4.4")

      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["4.4.4.4"])
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:298-334

  @Test
  fun flatThresholdMetAfterRepeatedViolations() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 2
        autoBanDuration = 300
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "7.7.7.7", violationCategory = "user_agent")
      assertEquals(0, banCalls.size)

      escalate(mw, config, "7.7.7.7", violationCategory = "user_agent")
      assertEquals(listOf(Triple("7.7.7.7", 300, "penetration_attempt")), banCalls)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:337-360

  @Test
  fun firstViolationBansImmediatelyWhenThresholdIsOne() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 60
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "11.0.0.1", violationCategory = "ip_blocked")

      assertEquals(listOf(Triple("11.0.0.1", 60, "penetration_attempt")), banCalls)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:363-389

  @Test
  fun perCategoryBanConfigOverridesAHighFlatThreshold() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1000
        threatBanConfig =
            mapOf(
                "xss" to com.guardcore.config.ThreatBanConfig(threshold = 1, duration = 99999),
            )
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(
          mw,
          config,
          "9.9.9.9",
          violationCategory = "ip_blocked",
          triggerInfo = "IP blocked by blocked_countries",
      )

      assertEquals(
          listOf(Triple("9.9.9.9", 99999, "penetration_attempt:xss")),
          banCalls,
      )
      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["9.9.9.9"])
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:392-418

  @Test
  fun perCategoryBanTakesPriorityOverFlatBan() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 60
        threatBanConfig =
            mapOf(
                "xss" to com.guardcore.config.ThreatBanConfig(threshold = 1, duration = 99999),
            )
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "9.9.9.10", violationCategory = "ip_blocked")

      assertEquals(
          listOf(Triple("9.9.9.10", 99999, "penetration_attempt:xss")),
          banCalls,
      )
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:421-446
  // python asserts log_activity received muted_check_logs={"ip_security"}; the JVM drives the
  // real log pass: muted suppresses the suspicious record, and the unmuted contrast shows the
  // pass-through is live.

  @Test
  fun mutedCheckLogsSuppressesLog() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 60
      }
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      // Muted: the threshold-ban activity log is suppressed.
      val mutedMiddleware = TestMiddleware(config)
      val mutedCapture = com.guardcore.handlers.LogCapture(mutedMiddleware.logger, Level.CONFIG)
      try {
        ChecksHelpers.escalateIdentityViolation(
            mutedMiddleware,
            config,
            IpBanManager.getInstance(),
            request(),
            "12.0.0.1",
            mutedMiddleware.logger,
            "ip_security",
            setOf("ip_security"),
            "user_agent",
            "t",
        )
        assertEquals(1, banCalls.size)
        assertEquals(
            0,
            mutedCapture.records
                .filter { it.level == Level.WARNING || it.level == Level.SEVERE }
                .size,
        )
      } finally {
        mutedCapture.release()
      }

      // Unmuted contrast: the same escalation logs the ban.
      banCalls.clear()
      val loudMiddleware = TestMiddleware(config)
      val loudCapture = com.guardcore.handlers.LogCapture(loudMiddleware.logger, Level.CONFIG)
      try {
        ChecksHelpers.escalateIdentityViolation(
            loudMiddleware,
            config,
            IpBanManager.getInstance(),
            request(),
            "12.0.0.2",
            loudMiddleware.logger,
            "ip_security",
            emptySet(),
            "user_agent",
            "t",
        )
        assertEquals(1, banCalls.size)
        assertTrue(
            loudCapture.records.isNotEmpty(),
            "the unmuted escalation must log the ban",
        )
      } finally {
        loudCapture.release()
      }
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:449-476

  @Test
  fun penetrationAttemptEventEmittedWhenBanned() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 60
      }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "13.0.0.1", triggerInfo = "hit")

      val event = mw.bus.events.last()
      assertEquals("penetration_attempt", event["event_type"])
      assertEquals("banned", event["action_taken"])
      assertEquals("hit", event["trigger_info"])
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:478-502

  @Test
  fun penetrationAttemptEventEmittedWhenNotBanned() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "14.0.0.1", triggerInfo = "hit")

      val event = mw.bus.events.last()
      assertEquals("penetration_attempt", event["event_type"])
      assertEquals("tracked", event["action_taken"])
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:504-527

  @Test
  fun penetrationAttemptEventStillCarriesTheSyntheticIdentityLabel() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "14.0.0.2", violationCategory = "ip_restriction", triggerInfo = "hit")

      val event = mw.bus.events.last()
      assertEquals("ip_restriction", event["violation_category"])
      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["14.0.0.2"])
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:530-563

  @Test
  fun banFailureIsSwallowedLoggedAndMadeVisible() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 300
      }
      val mw = middleware(config)
      val logger = RecordingLogger()
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = IllegalStateException("duration exceeds local cap"))

      escalate(mw, config, "40.0.0.1", logger = logger)

      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["40.0.0.1"])
      assertEquals(listOf(Triple("40.0.0.1", 300, "penetration_attempt")), banCalls)
      assertEquals(1, logger.severeCount)
      assertTrue(
          logger.severeMessages[0].contains("40.0.0.1"),
          "the failure log must carry the ip: ${logger.severeMessages[0]}",
      )
      val event = mw.bus.events.last()
      assertEquals("ip_ban_failed", event["event_type"])
      assertEquals("40.0.0.1", event["ip_address"])
      assertTrue(
          (event["reason"] as String).contains("duration exceeds local cap"),
          "reason must carry the error: ${event["reason"]}",
      )
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:566-594

  @Test
  fun redisErrorDuringBanIsSwallowedLoggedAndMadeVisible() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 300
      }
      val mw = middleware(config)
      val logger = RecordingLogger()
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = java.io.IOException("redis unavailable"))

      escalate(mw, config, "42.0.0.1", logger = logger)

      assertEquals(1, logger.severeCount)
      val event = mw.bus.events.last()
      assertEquals("ip_ban_failed", event["event_type"])
      assertTrue(
          (event["reason"] as String).contains("redis unavailable"),
          "reason must carry the error: ${event["reason"]}",
      )
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:597-630

  @Test
  fun banAndEventBusBothFailingDoesNotRaise() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 300
      }
      val mw = middleware(config)
      mw.eventBusOverride = BanFailedFailingBus()
      val logger = RecordingLogger()
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = IllegalStateException("redis down, ban not applied"))

      escalate(mw, config, "43.0.0.1", logger = logger)

      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["43.0.0.1"])
      assertEquals(1, banCalls.size)
      assertEquals(2, logger.severeCount)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:633-666

  @Test
  fun aBrokenLogSinkNeverEscapes() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 300
      }
      val logger = RecordingLogger()
      logger.throwOnLog = java.io.IOException("log sink unavailable")
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = IllegalStateException("redis down"))
      // python also breaks the event bus here, so the report-failure log is the second call.
      val mw = middleware(config)
      mw.eventBusOverride = BanFailedFailingBus()

      ChecksHelpers.escalateIdentityViolation(
          mw,
          config,
          IpBanManager.getInstance(),
          request(),
          "44.0.0.1",
          logger,
          "ip_security",
          emptySet(),
          "ip_restriction",
          "t",
      )

      assertEquals(2, logger.severeCount)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:669-694
  // python shrinks _MAX_TRACKED_SUSPICIOUS_IPS to 2; the JVM cap is the production constant
  // (10,000), so the eviction property runs at real scale over a prefilled map.

  @Test
  fun boundsSuspiciousRequestCountsSize() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val counts = mw.suspiciousRequestCounts
      counts["1.1.1.1"] = mutableMapOf("ip_restriction" to 1)
      for (i in 0 until 9998) {
        counts["10.$i.0.1"] = mutableMapOf("x" to 1)
      }
      counts["2.2.2.2"] = mutableMapOf("x" to 1)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      escalate(mw, config, "3.3.3.3")

      assertTrue("1.1.1.1" !in counts)
      assertTrue("2.2.2.2" in counts)
      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), counts["3.3.3.3"])
      assertEquals(ChecksHelpers.MAX_TRACKED_SUSPICIOUS_IPS, counts.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:697-736

  @Test
  fun touchingAnEntryProtectsItFromAFreshIpFlood() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val counts = mw.suspiciousRequestCounts
      // Fill the map to capacity; the touched entry is moved to the youngest position on
      // every touch, exactly like the reference's OrderedDict move-to-end.
      for (i in 0 until 9999) {
        counts["10.$i.0.1"] = mutableMapOf("x" to 1)
      }
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      suspend fun touch(clientIp: String) {
        escalate(mw, config, clientIp, violationCategory = "ip_blocked")
      }

      repeat(9) { touch("9.9.9.9") }
      assertEquals(9, counts["9.9.9.9"]!!["xss"])

      val floodSize = 200
      for (i in 0 until floodSize) {
        touch("203.0.${i / 256}.${i % 256}")
        if (i % 5 == 0) {
          touch("9.9.9.9")
        }
      }

      assertTrue("9.9.9.9" in counts, "a touched entry must survive the flood")
      assertEquals(9 + floodSize / 5, counts["9.9.9.9"]!!["xss"])
      assertTrue("10.0.0.1" !in counts, "untouched filler entries are evicted first")
      assertEquals(ChecksHelpers.MAX_TRACKED_SUSPICIOUS_IPS, counts.size)
    }
  }

  // ------------------------------- test_escalate_identity_violation.py:739-789

  @Test
  fun untouchedEntryIsTheFirstEvictedWhenOverCapacity() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig { enableIpBanning = false }
      val mw = middleware(config)
      val counts = mw.suspiciousRequestCounts
      // The three entries the test reasons about go in FIRST (a is the untouched oldest),
      // then fillers bring the map to capacity.
      for (ip in listOf("a", "b", "c")) {
        counts[ip] = mutableMapOf("xss" to 1)
      }
      for (i in 0 until 9997) {
        counts["10.$i.0.1"] = mutableMapOf("x" to 1)
      }
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      suspend fun touch(ip: String) {
        escalate(mw, config, ip, violationCategory = "ip_blocked")
      }

      touch("b")
      touch("d")

      assertTrue("a" !in counts, "the untouched oldest entry is evicted first")
      for (ip in listOf("b", "c", "d")) {
        assertTrue(ip in counts, "$ip must survive")
      }
    }
  }
}
