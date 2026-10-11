package com.guardcore.core

import com.guardcore.config.CustomRequestCheck
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.checks.implementations.CloudIpRefreshCheck
import com.guardcore.core.checks.implementations.UserAgentCheck
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * Port of the python pipeline surface tests: tests/test_core/test_pipeline.py (order,
 * add/insert/remove/get_check_names/len), test_pipeline_factory.py (fixed order),
 * test_enforced_on_excluded_paths_attribute.py + the exclusion-scope contract
 * (test_exclusion_scope_contract.py), and the fail-open/fail-secure split of
 * test_pipeline_fail_secure.py.
 */
public class PipelineTest {
  /** The fixed DEFAULT_CHECK_CLASSES order (factory.py:30). */
  @Test
  fun defaultCheckClassesOrderIsFixed() {
    val expected =
        listOf(
            "route_config",
            "emergency_mode",
            "https_enforcement",
            "request_logging",
            "request_size_content",
            "required_headers",
            "authentication",
            "referrer",
            "custom_validators",
            "time_window",
            "cloud_ip_refresh",
            "ip_security",
            "cloud_provider",
            "user_agent",
            "rate_limit",
            "suspicious_activity",
            "custom_request",
        )
    val config = coreTestConfig {
      logRequestLevel = com.guardcore.config.LogLevel.WARNING
      emergencyMode = false
      enableDynamicRules = true
      enableAgent = true
      agentApiKey = "test-agent-key"
      blockCloudProviders = setOf("AWS")
      customRequestCheck = CustomRequestCheck { null }
    }
    val middleware = TestMiddleware(config)
    val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
    assertEquals(expected, pipeline.getCheckNames())
    // factory.py:50-54: watched container fields, first-seen order, de-duplicated.
    assertEquals(
        listOf("block_cloud_providers", "blocked_user_agents", "endpoint_rate_limits"),
        ChecksFactory.WATCHED_CONTAINER_FIELDS,
    )
  }

  /** test_pipeline.py:155-219: add/insert/remove/get_check_names/len. */
  @Test
  fun addInsertRemoveChecks() {
    val middleware = TestMiddleware(coreTestConfig())
    val pipeline = SecurityCheckPipeline(emptyList())
    assertEquals(0, pipeline.size)

    val config = middleware.config
    val check = CloudIpRefreshCheck(middleware)
    pipeline.addCheck(check)
    assertEquals(1, pipeline.size)
    assertEquals(listOf("cloud_ip_refresh"), pipeline.getCheckNames())

    val ua = UserAgentCheck(middleware)
    pipeline.insertCheck(0, ua)
    assertEquals(listOf("user_agent", "cloud_ip_refresh"), pipeline.getCheckNames())

    assertTrue(pipeline.removeCheck("cloud_ip_refresh"))
    assertFalse(pipeline.removeCheck("nonexistent"))
    assertEquals(listOf("user_agent"), pipeline.getCheckNames())
    assertEquals(config.revision, config.revision)
  }

  /** test_pipeline.py:87-111: first blocking check wins; later checks do not run. */
  @Test
  fun firstBlockingCheckWins() {
    var secondRan = false
    val middleware = TestMiddleware(coreTestConfig())
    val blocker =
        object : SecurityCheck(middleware) {
          override val checkName: String = "blocker"

          override suspend fun check(request: GuardRequest): GuardResponse {
            return TestResponse(403, "blocked".encodeToByteArray())
          }
        }
    val second =
        object : SecurityCheck(middleware) {
          override val checkName: String = "second"

          override suspend fun check(request: GuardRequest): GuardResponse? {
            secondRan = true
            return null
          }
        }
    val pipeline = SecurityCheckPipeline(listOf(blocker, second))
    val response = runBlocking { pipeline.execute(TestRequest()) }
    assertEquals(403, response?.statusCode)
    assertEquals("blocked", response?.body?.decodeToString())
    assertFalse(secondRan)
  }

  /** test_pipeline_fail_secure.py: fail-open by default, 500 in fail-secure mode. */
  @Test
  fun checkExceptionFailOpenThenFailSecure() {
    val openConfig = coreTestConfig { failSecure = false }
    val middleware = TestMiddleware(openConfig)
    val throwing =
        object : SecurityCheck(middleware) {
          override val checkName: String = "thrower"

          override suspend fun check(request: GuardRequest): GuardResponse? {
            throw IllegalStateException("boom")
          }
        }
    val failOpen = SecurityCheckPipeline(listOf(throwing), config = openConfig)
    val failSecureConfig = coreTestConfig { failSecure = true }
    val secureMiddleware = TestMiddleware(failSecureConfig)
    val secureThrower =
        object : SecurityCheck(secureMiddleware) {
          override val checkName: String = "thrower"

          override suspend fun check(request: GuardRequest): GuardResponse? {
            throw IllegalStateException("boom")
          }
        }
    val failSecure = SecurityCheckPipeline(listOf(secureThrower), config = failSecureConfig)

    runBlocking {
      assertNull(failOpen.execute(TestRequest()))
      val response = failSecure.execute(TestRequest())
      assertEquals(500, response?.statusCode)
    }
  }

  /** test_enforced_on_excluded_paths_attribute.py + exclusion-scope contract. */
  @Test
  fun exclusionScopedRunsOnlyEnforcedChecks() {
    val middleware = TestMiddleware(coreTestConfig())
    val notEnforced =
        object : SecurityCheck(middleware) {
          override val checkName: String = "regular"

          var ran = false

          override suspend fun check(request: GuardRequest): GuardResponse? {
            ran = true
            return null
          }
        }
    val enforced =
        object : SecurityCheck(middleware) {
          override val checkName: String = "scoped"
          override val enforcedOnExcludedPaths: Boolean = true

          var ran = false

          override suspend fun check(request: GuardRequest): GuardResponse? {
            ran = true
            return null
          }
        }
    val pipeline = SecurityCheckPipeline(listOf(notEnforced, enforced))
    val request = TestRequest()
    request.state.setAttr("guard_exclusion_scoped", true)
    runBlocking { pipeline.execute(request) }
    assertFalse(notEnforced.ran)
    assertTrue(enforced.ran)
  }

  /** test_pipeline.py:87-100 pass-through when no check blocks. */
  @Test
  fun executeAllPassReturnsNull() {
    val middleware = TestMiddleware(coreTestConfig())
    val pipeline = SecurityCheckPipeline(emptyList())
    val response = runBlocking { pipeline.execute(TestRequest()) }
    assertNull(response)
  }
}
