package com.guardcore.util

import com.guardcore.config.ConfigSeams
import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** G-1/G-4/G-5 seam registration tests (ports of the python validators' behavior). */
class DetectionEngineWiringTest {
  init {
    DetectionEngineWiring.register()
  }

  @Test
  fun blockedUserAgentsGateRejectsUnsafePattern() {
    val error =
        try {
          ConfigSeams.blockedUserAgentsPatternGate!!.invoke(listOf("(.*)+"))
          null
        } catch (e: Exception) {
          e
        }
    assertTrue(error != null, "unsafe pattern must be rejected at construction")
    assertTrue(
        (error!!.message ?: "").contains("blocked_user_agents pattern rejected"),
        error.message,
    )
  }

  @Test
  fun blockedUserAgentsGateAcceptsSafePattern() {
    ConfigSeams.blockedUserAgentsPatternGate!!.invoke(listOf("badbot", "crawler\\d+"))
  }

  @Test
  fun userAgentMatcherBlocksMatchingUa() {
    val matcher = com.guardcore.util.AccessControl.userAgentBlockedPatternMatcher!!
    val blocked =
        kotlinx.coroutines.runBlocking {
          com.guardcore.util.AccessControl.isUserAgentAllowed(
              "sqlmap/1.0",
              builderWith(listOf("sqlmap")),
          )
        }
    assertEquals(false, blocked)
  }

  @Test
  fun userAgentMatcherAllowsCleanUa() {
    val allowed =
        kotlinx.coroutines.runBlocking {
          com.guardcore.util.AccessControl.isUserAgentAllowed(
              "Mozilla/5.0",
              builderWith(listOf("sqlmap")),
          )
        }
    assertEquals(true, allowed)
  }

  private fun builderWith(blocked: List<String>): SecurityConfig =
      SecurityConfigBuilder().apply { this.blockedUserAgents = blocked }.build()
}
