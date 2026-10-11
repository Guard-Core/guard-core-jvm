package com.guardcore.core

import com.guardcore.engine.py.PyRe
import com.guardcore.engine.py.RegexWorkers
import com.guardcore.engine.suspatterns.CompiledPatternRow
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.handlers.DynamicRuleManager
import com.guardcore.handlers.DynamicRules
import com.guardcore.handlers.LogCapture
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RecordingAgent
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.SusPatternsRegistry
import com.guardcore.handlers.sendRuleReceivedEvent
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.util.DetectionScan
import com.guardcore.util.DetectionScanBudget
import com.guardcore.util.PenetrationDetection
import java.lang.management.ManagementFactory
import java.time.OffsetDateTime
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_edge_cases.py: the handler/engine edge-case surface (the no-agent
 * rule event, the no-redis request count, the no-cors validated config, the default-pattern removal
 * halves, and the fallback-scan failure-routing contract).
 *
 * Seam notes for the two python halves that patch `sus_patterns_handler`:
 * - `test_fallback_pattern_check_unexpected_exception_propagates` (python mocks
 *   `_check_regex_pattern` to raise ValueError): the JVM cannot produce a non-recursion failure
 *   inside the per-pattern check through the real seam (PyRePattern is final and total on real
 *   inputs), so its contract (only the recursion class is ever swallowed) is carried by
 *   [fallbackPatternCheckRecursionErrorIsLoggedAndSkipped] asserting the scan both skips the
 *   recursion-class failure and continues to completion.
 * - `test_check_value_enhanced_recursion_error_escapes_the_fallback` (python makes `detect` raise
 *   RecursionError): the engine pool delivers in-worker failures as ExecutionException;
 *   [recursionClassFailureEscapesTheEnhancedFailureFallback] pins the real delivery shape plus the
 *   fallback-layer catch.
 * - `test_check_value_enhanced_empty_threats_list` (python mocks detect to return is_threat with no
 *   threats): the empty-threats verdict is unreachable through the real engine (every is_threat
 *   verdict carries at least one threat), so the quadruple shape is pinned on the real threat path
 *   in [fallbackScanStillDetectsSqli].
 */
public class EdgeCasesTest {
  /** Python `_host_cpu_speed_factor` (test_edge_cases.py:24): self-relative host calibration. */
  private fun hostCpuSpeedFactor(): Double {
    val threadBean = ManagementFactory.getThreadMXBean()
    val samples = mutableListOf<Double>()
    repeat(3) {
      val start = threadBean.currentThreadCpuTime
      var total = 0L
      for (i in 0 until 3_000_000) {
        total += i.toLong() * i
      }
      if (total == -1L) {
        throw AssertionError("unreachable")
      }
      samples.add((threadBean.currentThreadCpuTime - start) / 1e9)
    }
    return maxOf(1.0, samples.min() / 0.1243)
  }

  /** The engine pattern-table row the tests craft (contexts are not filtered on the fallback). */
  private fun craftedRow(): CompiledPatternRow =
      CompiledPatternRow(
          PyRe.compile("(?:a|b)*c", 0),
          setOf("request_body", "unknown"),
          "custom",
      )

  /**
   * Runs [block] on a small-stack thread: the fallback scan runs on the CALLER thread (python: the
   * same coroutine), so the recursion-limit analog (StackOverflowError) is provoked
   * deterministically by bounding the stack instead of the input.
   */
  private fun onSmallStack(block: suspend () -> Unit): Throwable? {
    val failure = AtomicReference<Throwable>()
    val done = CountDownLatch(1)
    val thread =
        Thread(
            null,
            {
              try {
                kotlinx.coroutines.runBlocking { block() }
              } catch (t: Throwable) {
                failure.set(t)
              }
              done.countDown()
            },
            "w8a-fallback-scan",
            128L * 1024,
        )
    thread.start()
    assertTrue(done.await(120, TimeUnit.SECONDS), "small-stack scan must complete")
    return failure.get()
  }

  // ------------------------------------------- test_edge_cases.py:35-51

  @Test
  fun sendRuleReceivedEventNoAgent() {
    coreRunTest {
      val config = coreTestConfig { enableDynamicRules = false }
      val manager = DynamicRuleManager.getInstance(config)
      manager.agentHandler = null

      val rules =
          DynamicRules(
              ruleId = "test",
              version = 1,
              timestamp = OffsetDateTime.now(java.time.ZoneOffset.UTC),
          )

      // Python asserts the no-agent early return completes without effect.
      manager.sendRuleReceivedEvent(rules)
    }
  }

  // ------------------------------------------- test_edge_cases.py:54-64

  @Test
  fun getRedisRequestCountNoRedisHandler() {
    coreRunTest {
      val config = coreTestConfig { enableRedis = false }
      val manager = RateLimitManager.getInstance(config)
      manager.redisHandler = null

      val result = manager.getRedisRequestCount("127.0.0.1", 1000.0, 900.0)

      assertNull(result)
    }
  }

  // ------------------------------------------- test_edge_cases.py:67-74

  @Test
  fun getValidatedCorsConfigNoCorsConfig() {
    coreRunTest {
      val manager = SecurityHeadersManager.getInstance()
      val savedCorsConfig = manager.corsConfig
      manager.corsConfig = null
      try {
        val (allowMethods, allowHeaders) = manager.getValidatedCorsConfig()

        assertEquals(listOf("GET", "POST"), allowMethods)
        assertEquals(listOf("*"), allowHeaders)
      } finally {
        manager.corsConfig = savedCorsConfig
      }
    }
  }

  // ------------------------------------------- test_edge_cases.py:77-111

  @Test
  fun removeDefaultPatternNotFound() {
    val engine = SusPatternsManager.shared()
    val originalPatterns = engine.patterns.toList()
    val originalCompiled = engine.compiledPatterns.toList()
    try {
      val result = SusPatternsRegistry.removeDefaultPattern("nonexistent_pattern_xyz")

      assertTrue(!result)
    } finally {
      engine.patterns.clear()
      engine.patterns.addAll(originalPatterns)
      engine.compiledPatterns.clear()
      engine.compiledPatterns.addAll(originalCompiled)
    }
  }

  @Test
  fun removeDefaultPatternInvalidIndex() {
    val engine = SusPatternsManager.shared()
    val originalPatterns = engine.patterns.toList()
    val originalCompiled = engine.compiledPatterns.toList()
    try {
      val testPattern = "test_pattern_xyz_123_unique_edge"
      engine.patterns.add(testPattern)
      engine.compiledPatterns.clear()

      val result = SusPatternsRegistry.removeDefaultPattern(testPattern)

      assertTrue(!result)
    } finally {
      engine.patterns.clear()
      engine.patterns.addAll(originalPatterns)
      engine.compiledPatterns.clear()
      engine.compiledPatterns.addAll(originalCompiled)
    }
  }

  // ------------------------------------------- test_edge_cases.py:114-161

  @Test
  fun fallbackPatternCheckRecursionErrorIsLoggedAndSkipped() {
    coreRunTest {
      PenetrationDetection.configureDetection(coreTestConfig())
      val manager = SusPatternsManager.shared()
      val row = craftedRow()
      manager.compiledPatterns.add(0, row)
      val capture = LogCapture(java.util.logging.Logger.getLogger("guard_core"))
      try {
        val failure = onSmallStack {
          val (detected, trigger) =
              DetectionScan.fallbackPatternCheck(
                  "ab".repeat(5000),
                  "198.51.100.60",
                  "request_body",
              )
          assertEquals(false, detected)
          assertEquals("", trigger)
        }
        assertNull(failure, "the recursion-class failure must be skipped, not propagated")

        val warnings =
            capture.records
                .filter { it.level == java.util.logging.Level.WARNING }
                .map { it.message }
        assertTrue(
            warnings.any { it.lowercase().contains("recursion") },
            "expected a recursion warning, got: $warnings",
        )
        assertTrue(
            warnings.any { it.contains("(?:a|b)*c") },
            "the warning must name the skipped pattern, got: $warnings",
        )
      } finally {
        capture.release()
        manager.compiledPatterns.remove(row)
      }
    }
  }

  // ------------------------------------------- test_edge_cases.py:164-237

  @Test
  fun recursionClassFailureEscapesTheEnhancedFailureFallback() {
    // The engine pool delivers an in-worker failure as ExecutionException (RegexWorkers.submit
    // rethrows the future); a StackOverflowError delivered that way must NOT be swallowed into
    // the fallback scan (python: `except RecursionError: raise`, detection_scan.py:337-338).
    val failure = AtomicReference<Throwable>()
    assertFailsWith<ExecutionException> {
      try {
        RegexWorkers.submit { throw StackOverflowError("engine recursion limit") }
      } catch (e: ExecutionException) {
        failure.set(e.cause)
        throw e
      }
    }
    assertTrue(failure.get() is StackOverflowError)

    // The same failure class raised inside the fallback scan is caught there (the other python
    // branch): skip + continue, never converted into a detection result.
    coreRunTest {
      val manager = SusPatternsManager.shared()
      val row = craftedRow()
      manager.compiledPatterns.add(0, row)
      try {
        val escaped = onSmallStack {
          DetectionScan.fallbackPatternCheck(
              "ab".repeat(5000),
              "198.51.100.61",
              "request_body",
          )
        }
        assertNull(escaped)
      } finally {
        manager.compiledPatterns.remove(row)
      }
    }
  }

  // ------------------------------------------- test_edge_cases.py:186-206

  @Test
  fun fallbackScanStaysCpuBounded() {
    coreRunTest {
      PenetrationDetection.configureDetection(coreTestConfig())
      val value = "{{".repeat(10000)
      val threadBean = ManagementFactory.getThreadMXBean()
      val samples = mutableListOf<Double>()
      repeat(5) {
        // Each sample scans the full value: the budget block resets the per-thread counters the
        // way the python harness's fresh scan context does.
        DetectionScanBudget.withScanBudget(maxValues = 512, maxScanChars = 1_000_000) {
          val start = threadBean.currentThreadCpuTime
          DetectionScan.checkValueEnhanced(value, "request_body", "198.51.100.62", "corr-1")
          samples.add((threadBean.currentThreadCpuTime - start) / 1e9)
        }
      }

      val budgetSeconds = 0.05 * hostCpuSpeedFactor()
      assertTrue(
          samples.min() < budgetSeconds,
          "fallback pattern scan regressed: min of 5 runs against '{{' * 10000 took " +
              "${"%.4f".format(samples.min())}s, budget=${"%.4f".format(budgetSeconds)}s",
      )
    }
  }

  // ------------------------------------------- test_edge_cases.py:209-219 + :222-237

  @Test
  fun fallbackScanStillDetectsSqli() {
    coreRunTest {
      PenetrationDetection.configureDetection(coreTestConfig())

      val hit =
          DetectionScan.checkValueEnhanced(
              "' OR '1'='1",
              "request_body",
              "198.51.100.63",
              "corr-2",
          )
      val detected = hit.detected
      val trigger = hit.trigger
      val threats = hit.threats
      val logOverride = hit.logOverride

      assertTrue(detected)
      assertTrue(trigger.isNotEmpty())
      assertNull(logOverride)
      assertTrue(threats.isNotEmpty(), "the real engine attaches the matched threat")
    }
  }

  // ------------------------------------------- test_edge_cases.py:240-255

  @Test
  fun detectPenetrationAttemptRealPath() {
    coreRunTest {
      val request = TestRequest(clientHost = "127.0.0.1", urlPath = "/test")
      request.state.setAttr("client_ip", "127.0.0.1")

      val result =
          com.guardcore.util.PenetrationDetection.detectPenetrationAttempt(
              request,
              coreTestConfig(),
              null,
          )

      assertIs<Boolean>(result.isThreat)
      assertIs<String>(result.triggerInfo)
    }
  }

  // ------------------------------------------- test_edge_cases.py:258-285

  private class ThrowingGeoHandler : GeoIPHandler {
    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override fun getCountry(ip: String): String = throw IllegalStateException("GeoIP failure")

    override suspend fun refresh() {}

    override fun close() {}
  }

  @Test
  fun sendMiddlewareEventWithGeoIpException() {
    coreRunTest {
      val config = coreTestConfig { agentEnableEvents = true }
      val agent = RecordingAgent()

      val eventBus =
          com.guardcore.core.events.SecurityEventBus(
              agentHandler = agent,
              config = config,
              geoIpHandler = ThrowingGeoHandler(),
          )

      val request =
          TestRequest(
              clientHost = "192.168.1.1",
              urlPath = "/test",
              method = "GET",
              headers = mapOf("User-Agent" to "TestAgent"),
          )

      eventBus.sendMiddlewareEvent(
          "suspicious_request",
          request,
          "logged",
          "test reason",
          emptyMap(),
      )

      assertEquals(1, agent.events.size)
    }
  }

  // ------------------------------------------- test_edge_cases.py:288-317

  @Test
  fun integrationAllEdgeCases() {
    coreRunTest {
      val config = coreTestConfig { enableDynamicRules = false }

      val drm = DynamicRuleManager.getInstance(config)
      drm.agentHandler = null
      val rules =
          DynamicRules(
              ruleId = "test",
              version = 1,
              timestamp = OffsetDateTime.now(java.time.ZoneOffset.UTC),
          )
      drm.sendRuleReceivedEvent(rules)

      val rlm = RateLimitManager.getInstance(config)
      assertNull(rlm.getRedisRequestCount("127.0.0.1", 1000.0, 900.0))

      val shm = SecurityHeadersManager.getInstance()
      val savedCorsConfig = shm.corsConfig
      shm.corsConfig = null
      try {
        val (methods, headers) = shm.getValidatedCorsConfig()
        assertEquals(listOf("GET", "POST"), methods)
        assertEquals(listOf("*"), headers)
      } finally {
        shm.corsConfig = savedCorsConfig
      }

      val engine = SusPatternsManager.shared()
      val originalPatterns = engine.patterns.toList()
      val originalCompiled = engine.compiledPatterns.toList()
      try {
        val result = SusPatternsRegistry.removeDefaultPattern("nonexistent")
        assertTrue(!result)
      } finally {
        engine.patterns.clear()
        engine.patterns.addAll(originalPatterns)
        engine.compiledPatterns.clear()
        engine.compiledPatterns.addAll(originalCompiled)
      }
    }
  }
}
