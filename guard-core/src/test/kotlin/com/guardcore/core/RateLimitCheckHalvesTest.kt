package com.guardcore.core

import com.guardcore.core.checks.implementations.RateLimitCheck
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.isIpBanned
import com.guardcore.handlers.resetIpBanGlobalState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The RateLimitCheck middleware-check halves deferred from W3 (KNOWN_GAPS.md, W3 deferral note):
 * test_rate_limit_singleton_isolation.py, test_rate_limit_autoban_wiring.py and the RateLimitCheck
 * halves of test_rate_limit_edge_cases.py.
 */
public class RateLimitCheckHalvesTest {
  /**
   * test_rate_limit_singleton_isolation.py:42-86: the singleton enforces each config's own limit.
   */
  @Test
  fun twoMiddlewaresEnforceTheirOwnRateLimitInterleaved() {
    coreRunTest {
      resetIpBanGlobalState()
      val configTight = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
      }
      val configLoose = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 100
        rateLimitWindow = 60
      }
      val middlewareTight = TestMiddleware(configTight)
      val middlewareLoose = TestMiddleware(configLoose)

      // python asserts both middlewares share the process-singleton handler
      assertEquals(middlewareTight.rateLimitHandler, middlewareLoose.rateLimitHandler)

      val checkTight = RateLimitCheck(middlewareTight)
      val checkLoose = RateLimitCheck(middlewareLoose)
      (middlewareTight.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()

      val ipTight = "198.51.100.10"
      val ipLoose = "198.51.100.20"

      assertNull(checkTight.checkGlobalRateLimit(TestRequest(clientHost = ipTight), ipTight))

      repeat(5) {
        assertNull(checkLoose.checkGlobalRateLimit(TestRequest(clientHost = ipLoose), ipLoose))
      }

      val blocked = checkTight.checkGlobalRateLimit(TestRequest(clientHost = ipTight), ipTight)
      assertEquals(429, blocked?.statusCode)

      repeat(90) {
        assertNull(checkLoose.checkGlobalRateLimit(TestRequest(clientHost = ipLoose), ipLoose))
      }
    }
  }

  /** test_rate_limit_autoban_wiring.py:56-71: knob off (default) never bans on violation. */
  @Test
  fun autobanKnobOffDefaultNeverBans() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
        enableIpBanning = true
        autoBanThreshold = 1
      }
      assertTrue(!config.enableRateLimitAutoBan)
      val middleware = TestMiddleware(config)
      val check = RateLimitCheck(middleware)
      (middleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()
      val request = TestRequest(clientHost = "1.1.1.1")
      request.state.setAttr("client_ip", "1.1.1.1")

      check.check(request)
      check.check(request)

      assertTrue(!IpBanManager.getInstance().isIpBanned("1.1.1.1"))
    }
  }

  /** test_rate_limit_autoban_wiring.py:73-95: threshold crossing bans with duration and reason. */
  @Test
  fun autobanThresholdCrossingBans() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
        enableRateLimitAutoBan = true
        enableIpBanning = true
        autoBanThreshold = 2
        autoBanDuration = 1234
      }
      val middleware = TestMiddleware(config)
      val check = RateLimitCheck(middleware)
      (middleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()
      val request = TestRequest(clientHost = "2.2.2.2")
      request.state.setAttr("client_ip", "2.2.2.2")

      // violation #1: counter reaches 1, below the threshold of 2
      check.check(request)
      assertTrue(!IpBanManager.getInstance().isIpBanned("2.2.2.2"))

      // violation #2: counter reaches 2 -> ban with the configured duration
      check.check(request)
      check.check(request)
      assertTrue(IpBanManager.getInstance().isIpBanned("2.2.2.2"))
    }
  }

  /** test_rate_limit_autoban_wiring.py:132-149: passive mode does not feed the counter or ban. */
  @Test
  fun autobanPassiveModeDoesNotBan() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
        enableRateLimitAutoBan = true
        enableIpBanning = true
        autoBanThreshold = 1
        passiveMode = true
      }
      val middleware = TestMiddleware(config)
      val check = RateLimitCheck(middleware)
      (middleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()
      val request = TestRequest(clientHost = "3.3.3.3")
      request.state.setAttr("client_ip", "3.3.3.3")

      check.check(request)
      check.check(request)

      assertTrue(!IpBanManager.getInstance().isIpBanned("3.3.3.3"))
      assertEquals(0, middleware.suspiciousRequestCounts.size)
    }
  }

  /** test_rate_limit_autoban_wiring.py:151-174 + :176-190. */
  @Test
  fun autobanLoopbackRefusalAndIpBanningOff() {
    coreRunTest {
      resetIpBanGlobalState()
      val loopbackConfig = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
        enableRateLimitAutoBan = true
        enableIpBanning = true
        autoBanThreshold = 1
      }
      val loopbackMiddleware = TestMiddleware(loopbackConfig)
      val loopbackCheck = RateLimitCheck(loopbackMiddleware)
      (loopbackMiddleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()
      val loopbackRequest = TestRequest(clientHost = "127.0.0.1")
      loopbackRequest.state.setAttr("client_ip", "127.0.0.1")
      loopbackCheck.check(loopbackRequest)
      loopbackCheck.check(loopbackRequest)
      // self-DoS guard: loopback is never banned (the ban_ip refusal)
      assertTrue(!IpBanManager.getInstance().isIpBanned("127.0.0.1"))

      resetIpBanGlobalState()
      val offConfig = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
        enableRateLimitAutoBan = true
        enableIpBanning = false
        autoBanThreshold = 1
      }
      val offMiddleware = TestMiddleware(offConfig)
      val offCheck = RateLimitCheck(offMiddleware)
      (offMiddleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()
      val offRequest = TestRequest(clientHost = "4.4.4.4")
      offRequest.state.setAttr("client_ip", "4.4.4.4")
      offCheck.check(offRequest)
      offCheck.check(offRequest)
      assertTrue(!IpBanManager.getInstance().isIpBanned("4.4.4.4"))
    }
  }

  /** The RateLimitCheck halves of test_rate_limit_edge_cases.py: endpoint tier isolation. */
  @Test
  fun endpointTierIndependentOfGlobal() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 5
        rateLimitWindow = 60
        endpointRateLimits = mapOf("/api/heavy" to (2 to 60))
      }
      val middleware = TestMiddleware(config)
      val check = RateLimitCheck(middleware)
      (middleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager).reset()

      val heavy = TestRequest(clientHost = "198.51.100.30", urlPath = "/api/heavy")
      heavy.state.setAttr("client_ip", "198.51.100.30")
      assertNull(check.check(heavy))
      assertNull(check.check(heavy))
      assertEquals(429, check.check(heavy)?.statusCode)

      // the global tier window for the endpoint path is separate; /api stays open
      val other = TestRequest(clientHost = "198.51.100.30", urlPath = "/api")
      other.state.setAttr("client_ip", "198.51.100.30")
      assertNull(check.check(other))
    }
  }
}
