package com.guardcore.core

import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.resetIpBanGlobalState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_ip_security_banned_ip_events.py: a banned-ip block emits the
 * ip_blocked event with the banned filter metadata, and passive mode downgrades the action to
 * logged_only.
 */
class IpSecurityBannedIpEventsTest {
  private val bannedIp = "1.2.3.4"

  private fun config(passive: Boolean): com.guardcore.config.SecurityConfig = coreTestConfig {
    passiveMode = passive
    enableIpBanning = true
  }

  private suspend fun bannedRequestEvent(
      passive: Boolean,
  ): Map<String, Any?> {
    resetIpBanGlobalState()
    IpBanManager.getInstance().banIpOverride = null
    val middleware = TestMiddleware(config(passive))
    val check = IpSecurityCheck(middleware)
    val request = TestRequest(clientHost = bannedIp, urlPath = "/api")
    request.state.setAttr("client_ip", bannedIp)
    request.state.setAttr("route_config", null)
    IpBanManager.getInstance().bannedIps[bannedIp] = System.currentTimeMillis() / 1000.0 + 3600
    val result = check.check(request)
    if (!passive) {
      assertTrue(result != null, "a banned ip must be blocked in active mode")
    }
    assertTrue(middleware.bus.events.isNotEmpty(), "expected the ip_blocked event")
    return middleware.bus.events.last()
  }

  @Test
  fun bannedIpBlockEmitsIpBlockedEvent() {
    coreRunTest {
      val event = bannedRequestEvent(passive = false)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("banned", event["filter_type"])
      assertEquals(bannedIp, event["ip_address"])
      assertEquals("request_blocked", event["action_taken"])
    }
  }

  @Test
  fun bannedIpInPassiveModeEmitsLoggedOnlyEvent() {
    coreRunTest {
      val event = bannedRequestEvent(passive = true)
      assertEquals("logged_only", event["action_taken"])
      assertEquals("banned", event["filter_type"])
    }
  }
}
