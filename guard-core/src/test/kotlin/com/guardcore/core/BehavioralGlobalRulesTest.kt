package com.guardcore.core

import com.guardcore.core.behavioral.BehavioralContext
import com.guardcore.core.behavioral.BehavioralProcessor
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.handlers.BehaviorRule
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.isIpBanned
import com.guardcore.handlers.resetIpBanGlobalState
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_behavioral_global_rules.py: the global return-pattern rules run on
 * the response path without route correlation, the detection-correlation threshold halving, and the
 * tracker-resolution halves.
 */
class BehavioralGlobalRulesTest {
  /**
   * The python helper's conventions: guard_decorator "default" means a decorator carrying the
   * tracker (the processor resolves it through decorator.behaviorTracker), None means no decorator
   * (the context-carried tracker is used); middleware None means the correlation source is absent.
   */
  private fun buildProcessor(
      suspiciousCounts: Map<String, Map<String, Int>>? = null,
      withDecorator: Boolean = true,
      middlewareTracker: BehaviorTracker? = null,
      withMiddleware: Boolean = true,
  ): Pair<BehavioralProcessor, RecordingBus> {
    val config = coreTestConfig()
    val bus = RecordingBus()
    val tracker = middlewareTracker ?: BehaviorTracker(config)
    val decorator = if (withDecorator) BaseSecurityDecorator(config) else null
    val middleware = if (withMiddleware) TestMiddleware(config) else null
    if (middleware != null && suspiciousCounts != null) {
      for ((ip, cats) in suspiciousCounts) {
        middleware.suspiciousRequestCounts[ip] = cats.toMutableMap()
      }
    }
    val context =
        BehavioralContext(
            config = config,
            logger = Logger.getLogger("test_behavioral_global"),
            eventBus = bus,
            guardDecorator = decorator,
            behaviorTracker = if (decorator == null) tracker else null,
            middleware = middleware,
        )
    return Pair(BehavioralProcessor(context), bus)
  }

  private fun makeRequest(): TestRequest {
    val request = TestRequest(method = "GET", urlPath = "/x")
    request.state.setAttr("guard_endpoint_id", null)
    request.state.setAttr("guard_decorator", null)
    return request
  }

  private fun notFound(): TestResponse = TestResponse(404, "not found".encodeToByteArray())

  private fun returnRule(
      threshold: Int,
      correlate: Boolean = false,
  ): BehaviorRule =
      BehaviorRule(
          ruleType = "return_pattern",
          threshold = threshold,
          pattern = "status:404",
          action = "log",
          correlateWithDetection = correlate,
      )

  @Test
  fun globalReturnRulesProcessWithoutCorrelation() {
    coreRunTest {
      val (processor, bus) = buildProcessor()
      val rule = returnRule(2)
      val request = makeRequest()
      repeat(3) { processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule)) }
      assertTrue(
          bus.events.any { it["violation_type"] == "return_pattern" },
          "expected a return_pattern violation event: ${bus.events}",
      )
    }
  }

  @Test
  fun correlationHalvesThresholdWhenIpHasDetections() {
    coreRunTest {
      val (processor, bus) =
          buildProcessor(suspiciousCounts = mapOf("1.2.3.4" to mapOf("xss" to 1)))
      val rule = returnRule(10, correlate = true)
      val request = makeRequest()
      repeat(5) { processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule)) }
      assertEquals(0, bus.events.size)
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(1, bus.events.size)
      val event = bus.events.last()
      assertEquals("return_pattern", event["violation_type"])
      assertEquals(true, event["correlation"])
      assertEquals(listOf("xss"), event["correlated_categories"])
      assertEquals(5, event["threshold"])
    }
  }

  @Test
  fun correlationDoesNotFireWhenIpClean() {
    coreRunTest {
      val (processor, bus) = buildProcessor(suspiciousCounts = emptyMap())
      val rule = returnRule(10, correlate = true)
      val request = makeRequest()
      repeat(10) {
        processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      }
      assertEquals(0, bus.events.size)
    }
  }

  @Test
  fun correlationHalvesThresholdFloorAtOne() {
    coreRunTest {
      val (processor, bus) =
          buildProcessor(suspiciousCounts = mapOf("1.2.3.4" to mapOf("sqli" to 1)))
      val rule = returnRule(1, correlate = true)
      val request = makeRequest()
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(0, bus.events.size)
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(1, bus.events.size)
    }
  }

  @Test
  fun nonReturnPatternRulesAreIgnored() {
    coreRunTest {
      val (processor, bus) = buildProcessor()
      val rule = BehaviorRule(ruleType = "usage", threshold = 1)
      val request = makeRequest()
      val response = TestResponse(200, "ok".encodeToByteArray())
      repeat(5) { processor.processGlobalReturnRules(request, response, "1.2.3.4", listOf(rule)) }
      assertEquals(0, bus.events.size)
    }
  }

  @Test
  fun globalReturnRulesUseMiddlewareTrackerWithoutDecorator() {
    coreRunTest {
      val (processor, bus) =
          buildProcessor(
              withDecorator = false,
              middlewareTracker = BehaviorTracker(coreTestConfig()),
          )
      val rule = returnRule(1)
      val request = makeRequest()
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(0, bus.events.size)
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(1, bus.events.size)
    }
  }

  @Test
  fun globalReturnRulesShortCircuitWhenNoTracker() {
    coreRunTest {
      // No decorator and no context tracker: the processor resolves nothing and returns.
      val config = coreTestConfig()
      val bus = RecordingBus()
      val context =
          BehavioralContext(
              config = config,
              logger = Logger.getLogger("test_behavioral_global"),
              eventBus = bus,
              guardDecorator = null,
              behaviorTracker = null,
              middleware = TestMiddleware(config),
          )
      val processor = BehavioralProcessor(context)
      val rule = returnRule(1)
      val request = makeRequest()
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(0, bus.events.size)
    }
  }

  @Test
  fun globalReturnRulesHandleMissingMiddleware() {
    coreRunTest {
      val (processor, bus) = buildProcessor(withMiddleware = false)
      val rule = returnRule(1, correlate = true)
      val request = makeRequest()
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(0, bus.events.size)
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(1, bus.events.size)
      val event = bus.events.last()
      assertEquals(false, event["correlation"])
      assertEquals(emptyList<String>(), event["correlated_categories"])
    }
  }

  @Test
  fun globalReturnRulesZeroCountIgnoredForCorrelation() {
    coreRunTest {
      val (processor, bus) =
          buildProcessor(suspiciousCounts = mapOf("1.2.3.4" to mapOf("xss" to 0)))
      val rule = returnRule(4, correlate = true)
      val request = makeRequest()
      repeat(4) { processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule)) }
      assertEquals(0, bus.events.size)
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      assertEquals(1, bus.events.size)
      assertEquals(false, bus.events.last()["correlation"])
    }
  }

  @Test
  fun globalReturnRulesApplyActionInvoked() {
    coreRunTest {
      resetIpBanGlobalState()
      IpBanManager.getInstance().banIpOverride = null
      val config = coreTestConfig()
      val bus = RecordingBus()
      val tracker = BehaviorTracker(config)
      val context =
          BehavioralContext(
              config = config,
              logger = Logger.getLogger("t"),
              eventBus = bus,
              guardDecorator = null,
              behaviorTracker = tracker,
              middleware = TestMiddleware(config),
          )
      val processor = BehavioralProcessor(context)
      val rule =
          BehaviorRule(
              ruleType = "return_pattern",
              threshold = 1,
              pattern = "status:404",
              action = "ban",
          )
      val request = makeRequest()
      // The python test mocks track_return_pattern to True on the first call; against the live
      // tracker the threshold-1 rule trips on the second matching response (size > threshold).
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      processor.processGlobalReturnRules(request, notFound(), "1.2.3.4", listOf(rule))
      // apply_action ran: the ban action banned the client ip through the live ban manager.
      assertTrue(
          IpBanManager.getInstance().isIpBanned("1.2.3.4"),
          "the ban action should have banned the client ip",
      )
    }
  }
}
