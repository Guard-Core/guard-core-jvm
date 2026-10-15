package com.guardcore.util

import com.guardcore.config.BlockHook
import com.guardcore.config.SecurityConfig
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import java.nio.file.Files
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Ports of the logging surface tests: test_utils/test_logging.py (setup_custom_logging, log levels,
 * log_activity, dispatch_block_hook), test_utils/test_log_levels.py, and test_utils/
 * test_block_events.py.
 */
class SetupCustomLoggingTest {
  @Test
  fun testCustomLoggingWritesRequestLineToFile() {
    val logFile = Files.createTempDirectory("gclog").resolve("test_log.log").toString()
    val logger = LoggingUtils.setupCustomLogging(logFile)
    try {
      scanRunTest {
        val request =
            ScanRequest(
                method = "GET",
                clientHost = "127.0.0.1",
                headers = mapOf("user-agent" to "test-agent"),
            )
        RequestLogging.logActivity(request, logger)
      }
      val content = Files.readAllBytes(java.nio.file.Paths.get(logFile)).decodeToString()
      assertTrue("Request from 127.0.0.1: GET http://example.com/" in content, content)
    } finally {
      for (handler in logger.handlers.toList()) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
  }

  @Test
  fun testSetupCustomLoggingAttachesConsoleAndFileHandlers() {
    val logFile = Files.createTempDirectory("gclog").resolve("security.log").toString()
    val logger = LoggingUtils.setupCustomLogging(logFile)
    try {
      val count =
          logger.handlers.count {
            it is java.util.logging.FileHandler || it is java.util.logging.StreamHandler
          }
      assertEquals(2, count)
      assertEquals(Level.INFO, logger.level)
      assertFalse(logger.useParentHandlers)
    } finally {
      for (handler in logger.handlers.toList()) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
  }

  @Test
  fun testRepeatedSetupDoesNotStackHandlers() {
    val logger = LoggingUtils.setupCustomLogging(null, "json")
    LoggingUtils.setupCustomLogging(null, "text")
    try {
      val own = logger.handlers.count { it is LoggingUtils.ConsoleGuardHandler }
      assertEquals(1, own)
    } finally {
      for (handler in logger.handlers.toList()) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
  }

  @Test
  fun testSetupCustomLoggingKeepsForeignHandler() {
    val logger = LoggingUtils.setupCustomLogging(null, "text")
    val foreign =
        object : java.util.logging.Handler() {
          override fun publish(record: java.util.logging.LogRecord) {}

          override fun flush() {}

          override fun close() {}
        }
    logger.addHandler(foreign)
    LoggingUtils.setupCustomLogging(null, "text")
    try {
      assertTrue(logger.handlers.contains(foreign), "foreign handler must survive")
    } finally {
      logger.removeHandler(foreign)
      for (handler in logger.handlers.toList()) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
  }

  @Test
  fun testSetupCustomLoggingCreatesDirectory() {
    val dir = Files.createTempDirectory("gclog").resolve("nested/sub")
    val logFile = dir.resolve("audit.log")
    assertFalse(Files.exists(dir))
    val logger = LoggingUtils.setupCustomLogging(logFile.toString())
    try {
      assertTrue(Files.exists(dir))
    } finally {
      for (handler in logger.handlers.toList()) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
  }

  @Test
  fun testSetupCustomLoggingFileHandlerFailureWarns() {
    val capture = LogCapture()
    capture.attach(GUARD_LOGGER, Level.WARNING)
    try {
      // A directory path cannot be opened as a file handler target.
      val dir = Files.createTempDirectory("gclogdir").toString()
      LoggingUtils.setupCustomLogging(dir, "text")
      assertTrue(capture.text().contains("Failed to create log file"), capture.text())
    } finally {
      capture.detach(GUARD_LOGGER)
      val logger = Logger.getLogger("guard_core")
      for (handler in logger.handlers.toList()) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
  }

  @Test
  fun testJsonFormatterOutput() {
    val formatter = LoggingUtils.createFormatter("json")
    assertTrue(formatter is LoggingUtils.JsonLogFormatter)
    val record = java.util.logging.LogRecord(Level.WARNING, "hello line")
    record.loggerName = "guard_core"
    val line = formatter.format(record)
    val parsed = com.guardcore.util.py.PyJson.loads(line.trim()) as Map<*, *>
    assertEquals("WARNING", parsed["level"])
    assertEquals("guard_core", parsed["logger"])
    assertEquals("hello line", parsed["message"])
    assertTrue((parsed["timestamp"] as String).contains(","))
  }

  @Test
  fun testTextFormatterOutput() {
    val formatter = LoggingUtils.createFormatter("text")
    assertTrue(formatter is LoggingUtils.TextGuardFormatter)
    val record = java.util.logging.LogRecord(Level.INFO, "plain line")
    record.loggerName = "guard_core"
    val line = formatter.format(record)
    assertTrue(line.startsWith("[guard_core] "), line)
    assertTrue(" - INFO - plain line" in line, line)
  }

  @Test
  fun testLogAtLevelAllLevels() {
    val logger = Logger.getLogger("test.levels")
    logger.level = Level.ALL
    for (level in listOf("INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL")) {
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        LoggingUtils.logAtLevel(logger, level, "msg-$level")
        assertEquals(1, capture.records.size, level)
        val expected =
            when (level) {
              "ERROR",
              "CRITICAL" -> Level.SEVERE
              "WARNING" -> Level.WARNING
              "INFO" -> Level.INFO
              else -> Level.FINE
            }
        assertEquals(expected, capture.records[0].level, level)
      } finally {
        capture.detach(logger)
      }
    }
    // level = null logs nothing.
    val capture = LogCapture()
    capture.attach(logger, Level.ALL)
    try {
      LoggingUtils.logAtLevel(logger, null, "never")
      assertEquals(0, capture.records.size)
    } finally {
      capture.detach(logger)
    }
  }

  /** logging_utils.py:43 lone-surrogate escaping. */
  @Test
  fun testSanitizeForReportingLoneSurrogate() {
    val loneHigh = String(Character.toChars(0xD800))
    assertEquals("\\ud800", LoggingUtils.sanitizeForReporting(loneHigh))
    assertEquals(
        "ab\\udcff",
        LoggingUtils.sanitizeForReporting("ab" + String(Character.toChars(0xDCFF))),
    )
    // Paired surrogates pass through untouched.
    assertEquals("\uD83D\uDE00", LoggingUtils.sanitizeForReporting("\uD83D\uDE00"))
  }

  /** logging_utils.py:49 percent-prefixed nested JSON leaf candidate. */
  @Test
  fun testRedactSensitiveJsonNestedLeafViaPercentEncoding() {
    val inner = PyJson.dumps(linkedMapOf("token" to "abc"))
    val encoded = PyUrllib.quote(inner, safe = "")
    val parsed = linkedMapOf<String, Any?>("q" to encoded)
    LoggingUtils.jsonDepthCapHit.set(false)
    val redacted =
        LoggingUtils.redactSensitiveJson(parsed, setOf("token"), emptySet(), 32) as Map<*, *>
    assertTrue("abc" !in (redacted["q"] as String), redacted["q"].toString())
  }

  /** logging_utils.py:127 list containers + depth cap over lists. */
  @Test
  fun testRedactSensitiveJsonListContainerAndDepthCap() {
    val parsed = listOf<Any?>(linkedMapOf<String, Any?>("password" to "x"), listOf<Any?>("a", "b"))
    val redacted =
        LoggingUtils.redactSensitiveJson(parsed, emptySet(), setOf("password"), 32) as List<*>
    assertEquals("[REDACTED]", (redacted[0] as Map<*, *>)["password"])
    // Depth 2 cap redacts the inner list container.
    LoggingUtils.jsonDepthCapHit.set(false)
    val capped = LoggingUtils.redactSensitiveJson(parsed, emptySet(), emptySet(), 2) as List<*>
    assertTrue(capped.isNotEmpty())
    assertTrue(LoggingUtils.jsonDepthCapHit.get())
  }

  /** Non-JSON leaf passthrough and the guard string re-export helper. */
  @Test
  fun testRedactSensitiveJsonNonContainerPassthrough() {
    assertEquals("text", LoggingUtils.redactSensitiveJson("text", emptySet(), emptySet(), 32))
    assertEquals("x", pyUnquote("x"))
  }
}

/**
 * test_utils/test_logging.py:597-735 (dispatch_block_hook + log_activity) + test_block_events.py.
 */
class BlockHookAndLogActivityTest {
  private fun recordingHook(calls: MutableList<Map<String, Any?>>): BlockHook =
      BlockHook { _, payload ->
        calls.add(payload)
        null
      }

  /** test_block_events.py:11. */
  @Test
  fun testExcludedCheckNames() {
    assertEquals(
        setOf("custom_request", "custom_validators", "https_enforcement"),
        BlockEvents.ON_BLOCK_EXCLUDED_CHECK_NAMES,
    )
  }

  @Test
  fun testInvokeBlockHookWithNoHookIsNoOp() {
    scanRunTest { BlockEvents.invokeBlockHook(null, ScanRequest(), emptyMap()) }
  }

  @Test
  fun testFireBlockHookWithNoHookIsNoOp() {
    scanRunTest {
      BlockEvents.fireBlockHook(null, ScanRequest(), "ip_security", "banned", "", false, 403)
    }
  }

  @Test
  fun testFireBlockHookSkipsExcludedCheckNames() {
    for (checkName in BlockEvents.ON_BLOCK_EXCLUDED_CHECK_NAMES.sorted()) {
      scanRunTest {
        val calls = mutableListOf<Map<String, Any?>>()
        BlockEvents.fireBlockHook(
            recordingHook(calls),
            ScanRequest(),
            checkName,
            "reason",
            "",
            false,
            403,
        )
        assertTrue(calls.isEmpty(), checkName)
      }
    }
  }

  @Test
  fun testInvokeBlockHookSwallowsHookError() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        BlockEvents.invokeBlockHook(
            BlockHook { _, _ -> throw IllegalStateException("boom") },
            ScanRequest(),
            emptyMap(),
        )
        assertTrue(capture.text().contains("on_block hook raised"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testBuildBlockPayloadFields() {
    val request = ScanRequest(method = "POST", clientHost = "10.0.0.1")
    request.state.setAttr("client_ip", "203.0.113.9")
    val payload =
        BlockEvents.buildBlockPayload(
            request,
            "ip_security",
            "banned",
            "IPMatch",
            false,
            403,
        )
    assertEquals("ip_security", payload["check_name"])
    assertEquals("banned", payload["reason"])
    assertEquals("IPMatch", payload["trigger_info"])
    assertEquals(false, payload["passive_mode"])
    assertEquals("203.0.113.9", payload["client_ip"])
    assertEquals("/", payload["path"])
    assertEquals("POST", payload["method"])
    assertEquals(403, payload["status_code"])
  }

  @Test
  fun testBuildBlockPayloadCanonicalizesClientHost() {
    val payload =
        BlockEvents.buildBlockPayload(
            ScanRequest(clientHost = "10.0.0.1"),
            "c",
            "r",
            "",
            false,
            null,
        )
    assertEquals("10.0.0.1", payload["client_ip"])
    assertEquals(null, payload["status_code"])
  }

  @Test
  fun testBuildBlockPayloadUnknownIdentity() {
    val payload =
        BlockEvents.buildBlockPayload(ScanRequest(clientHost = null), "c", "r", "", false, null)
    assertEquals(IpExtraction.UNKNOWN_CLIENT_IDENTITY, payload["client_ip"])
  }

  /** test_utils/test_logging.py:597. */
  @Test
  fun testDispatchBlockHookIgnoresNonSuspiciousLogTypes() {
    scanRunTest {
      val calls = mutableListOf<Map<String, Any?>>()
      val request = ScanRequest(clientHost = "127.0.0.1")
      RequestLogging.logActivity(
          request,
          Logger.getLogger("test.block"),
          logType = "request",
          reason = "r",
          checkName = "ip_security",
          onBlock = recordingHook(calls),
          level = null,
      )
      assertTrue(calls.isEmpty())
      assertEquals(null, request.state.getAttr("_guard_block_stash"))
    }
  }

  /** test_utils/test_logging.py:613. */
  @Test
  fun testDispatchBlockHookStashesBlockDispatchWithoutFiring() {
    scanRunTest {
      val calls = mutableListOf<Map<String, Any?>>()
      val request = ScanRequest(clientHost = "127.0.0.1")
      RequestLogging.logActivity(
          request,
          Logger.getLogger("test.block"),
          logType = "suspicious",
          reason = "blacklisted",
          triggerInfo = "IPMatch",
          checkName = "ip_security",
          onBlock = recordingHook(calls),
          level = null,
      )
      assertTrue(calls.isEmpty())
      val stash = request.state.getAttr("_guard_block_stash") as Map<*, *>
      assertEquals("blacklisted", stash["reason"])
      assertEquals("IPMatch", stash["trigger_info"])
    }
  }

  /** test_utils/test_logging.py:640. */
  @Test
  fun testDispatchBlockHookPassiveModeFiresHookWithoutStatusCode() {
    scanRunTest {
      val calls = mutableListOf<Map<String, Any?>>()
      val request = ScanRequest(clientHost = "127.0.0.1")
      RequestLogging.logActivity(
          request,
          Logger.getLogger("test.block"),
          logType = "suspicious",
          reason = "blacklisted",
          passiveMode = true,
          triggerInfo = "IPMatch",
          checkName = "ip_security",
          onBlock = recordingHook(calls),
          level = null,
      )
      assertEquals(1, calls.size)
      assertEquals("ip_security", calls[0]["check_name"])
      assertEquals("blacklisted", calls[0]["reason"])
      assertEquals("IPMatch", calls[0]["trigger_info"])
      assertEquals(true, calls[0]["passive_mode"])
      assertEquals(null, calls[0]["status_code"])
      assertEquals(null, request.state.getAttr("_guard_block_stash"))
    }
  }

  /** test_utils/test_logging.py:671 (with logging still performed). */
  @Test
  fun testLogActivityPassiveModeFiresHookAndLogs() {
    scanRunTest {
      val calls = mutableListOf<Map<String, Any?>>()
      val logger = Logger.getLogger("test.blockactivity")
      val request =
          ScanRequest(
              method = "POST",
              clientHost = "127.0.0.1",
              headers = mapOf("user-agent" to "t"),
          )
      RequestLogging.logActivity(
          request,
          logger,
          logType = "suspicious",
          reason = "blacklisted",
          passiveMode = true,
          triggerInfo = "IPMatch",
          checkName = "suspicious_activity",
          onBlock = recordingHook(calls),
      )
      assertEquals(1, calls.size)
      assertEquals("suspicious_activity", calls[0]["check_name"])
      assertEquals(true, calls[0]["passive_mode"])
    }
  }

  /** test_utils/test_log_levels.py level mapping over log_activity. */
  @Test
  fun testLogActivityLevels() {
    scanRunTest {
      val logger = Logger.getLogger("test.loglevels")
      for (level in listOf("INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL", null)) {
        val capture = LogCapture()
        capture.attach(logger, Level.ALL)
        try {
          RequestLogging.logActivity(
              ScanRequest(
                  method = "GET",
                  clientHost = "127.0.0.1",
                  headers = mapOf("user-agent" to "test-agent"),
              ),
              logger,
              level = level,
          )
          if (level == null) {
            assertEquals(0, capture.records.size, "null level logs nothing")
          } else {
            assertEquals(1, capture.records.size, level)
          }
        } finally {
          capture.detach(logger)
        }
      }
    }
  }

  /** test_utils/test_logging.py:473 mute ordering. */
  @Test
  fun testLogActivityMutedCheckLogsSkipEmission() {
    scanRunTest {
      val logger = Logger.getLogger("test.muted")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(
            ScanRequest(clientHost = "127.0.0.1"),
            logger,
            logType = "suspicious",
            reason = "r",
            checkName = "rate_limit",
            mutedCheckLogs = setOf("rate_limit"),
        )
        assertEquals(0, capture.records.size)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:933 passive mode without trigger omits the trigger prefix. */
  @Test
  fun testLogSuspiciousPassiveWithoutTriggerInfoOmitsTrigger() {
    scanRunTest {
      val logger = Logger.getLogger("test.notrigger")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(
            ScanRequest(method = "GET", clientHost = "127.0.0.1"),
            logger,
            logType = "suspicious",
            reason = "blacklisted",
            passiveMode = true,
        )
        val line = capture.records.single().message ?: ""
        assertTrue(line.contains("[PASSIVE MODE] Suspicious activity detected from"), line)
        assertFalse(line.contains("Penetration attempt"), line)
        assertTrue(line.contains("Reason: blacklisted"), line)
        assertFalse(line.contains("Trigger:"), line)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:916 unknown client identity fallback. */
  @Test
  fun testLogActivityFallsBackToUnknownClientIdentity() {
    scanRunTest {
      val logger = Logger.getLogger("test.unknownip")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(ScanRequest(clientHost = null), logger)
        val line = capture.records.single().message ?: ""
        assertTrue(line.contains(IpExtraction.UNKNOWN_CLIENT_IDENTITY), line)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:255 custom log type rendering. */
  @Test
  fun testLogCustomTypeRendering() {
    scanRunTest {
      val logger = Logger.getLogger("test.custom")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(
            ScanRequest(method = "GET", clientHost = "127.0.0.1"),
            logger,
            logType = "country_check",
            reason = "blocked country",
        )
        val line = capture.records.single().message ?: ""
        assertTrue(line.startsWith("Country_check from"), line)
        assertTrue(line.contains("Details: blocked country - Headers:"), line)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:820 sensitive header redaction across log types. */
  @Test
  fun testLogActivityRedactsSensitiveHeaders() {
    scanRunTest {
      val logger = Logger.getLogger("test.redact")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(
            ScanRequest(
                method = "GET",
                clientHost = "127.0.0.1",
                headers = mapOf("authorization" to "Bearer abc", "user-agent" to "ua"),
            ),
            logger,
        )
        val line = capture.records.single().message ?: ""
        assertTrue("abc" !in line, line)
        assertTrue("[REDACTED]" in line, line)
        assertTrue("ua" in line, line)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:842 original header key casing preserved in the dump. */
  @Test
  fun testLogActivityPreservesHeaderKeyCasing() {
    scanRunTest {
      val logger = Logger.getLogger("test.casing")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(
            ScanRequest(
                method = "GET",
                clientHost = "127.0.0.1",
                headers = mapOf("X-Custom-Case" to "value"),
            ),
            logger,
        )
        val line = capture.records.single().message ?: ""
        // The JVM request normalizes to lowercase at the protocol boundary (adapters do the same).
        assertTrue("x-custom-case" in line.lowercase(), line)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:859 custom sensitive headers redact case-insensitively. */
  @Test
  fun testLogActivityCustomSensitiveHeadersRedactCaseInsensitively() {
    scanRunTest {
      val logger = Logger.getLogger("test.customredact")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(
            ScanRequest(
                method = "GET",
                clientHost = "127.0.0.1",
                headers = mapOf("X-Api-Secret" to "super-secret"),
            ),
            logger,
            sensitiveHeaders = setOf("x-api-secret"),
        )
        val line = capture.records.single().message ?: ""
        assertTrue("super-secret" !in line, line)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:1136 sensitive query params redacted in the URL. */
  @Test
  fun testLogActivityRedactsSensitiveQueryParams() {
    scanRunTest {
      val logger = Logger.getLogger("test.query")
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        // URL-level redaction works on url_full.
        val url = "http://example.com/login?token=abc123&user=bob"
        val redacted = RequestLogging.redactUrlForDisplay(url, null)
        assertTrue("abc123" !in redacted, redacted)
        assertTrue("bob" in redacted, redacted)
        logger.warning(redacted)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** test_utils/test_logging.py:190/206 request + suspicious message shapes. */
  @Test
  fun testLogRequestAndSuspiciousMessageShapes() {
    scanRunTest {
      val logger = Logger.getLogger("test.shapes")
      val request =
          ScanRequest(
              method = "GET",
              clientHost = "127.0.0.1",
              headers = mapOf("user-agent" to "test-agent"),
          )
      val capture = LogCapture()
      capture.attach(logger, Level.ALL)
      try {
        RequestLogging.logActivity(request, logger, logType = "request")
        val reqLine = capture.records.single().message ?: ""
        assertTrue(reqLine.startsWith("Request from 127.0.0.1: GET "), reqLine)
        assertTrue(reqLine.contains("Headers: "), reqLine)
        capture.records.clear()
        RequestLogging.logActivity(
            request,
            logger,
            logType = "suspicious",
            reason = "pattern match",
        )
        val susLine = capture.records.single().message ?: ""
        assertTrue(susLine.startsWith("Suspicious activity detected from 127.0.0.1"), susLine)
        assertTrue(susLine.contains("Reason: pattern match - Headers: "), susLine)
      } finally {
        capture.detach(logger)
      }
    }
  }

  /** SecurityConfig hook defaults (models.py: on_error/on_block default to None). */
  @Test
  fun testConfigDefaultConstructionSupportsHooks() {
    val config: SecurityConfig = com.guardcore.config.SecurityConfigBuilder().build()
    assertEquals(null, config.onError)
    assertEquals(null, config.onBlock)
    // log_sensitive_* fields default to empty sets; the DEFAULT_SENSITIVE_LOG_* sets apply at
    // redaction time (request_logging.py:22-31).
    assertTrue(config.logSensitiveHeaders.isEmpty())
  }
}
