package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.handlers.CloudManager
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The G-13 pipeline rebuild-policy halves: the port of
 * tests/test_core/test_pipeline_concurrent_rebuild.py and
 * tests/test_core/test_pipeline_rebuild_failure_policy.py and the config-revision halves of
 * tests/test_core/test_pipeline_config_revision.py, through the public pipeline surface.
 */
public class PipelineRebuildPolicyTest {
  private class StubCheck(
      middleware: GuardMiddlewareProtocol,
      private val name: String,
  ) : SecurityCheck(middleware) {
    override val checkName: String = name

    override suspend fun check(request: GuardRequest): GuardResponse? = null
  }

  private fun neutralConfig(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enablePenetrationDetection = false
            enableRateLimiting = false
          }
          .apply(mutate)
          .build()

  /**
   * The python test's `middleware.guard_decorator = MagicMock()` shape: a decorator presenting an
   * EMPTY route-config collection, so `route_config_applies([], pred)` is False and the
   * route-only checks start eliminated (config_revision harness, test_pipeline_config_revision.py).
   */
  private class EmptyRoutesMiddleware(private val inner: GuardMiddlewareProtocol) :
      GuardMiddlewareProtocol by inner {
    private val decorator =
        object : com.guardcore.decorators.RouteConfigProvider {
          override fun getRouteConfigs(): Map<String, com.guardcore.decorators.RouteConfig> =
              emptyMap()

          override fun getRevisionValue(): Int = 0
        }

    override val guardDecorator: Any? = decorator
  }

  // ---------------------------------- test_pipeline_rebuild_failure_policy.py

  @Test
  fun executeBlocksWhenFailSecureAndRebuildRaises() = runBlocking {
    val config = neutralConfig { failSecure = true }
    val middleware = TestMiddleware(config)
    val check = StubCheck(middleware, "route_config")

    val pipeline =
        SecurityCheckPipeline(
            listOf(check),
            config = config,
            rebuildChecks = { throw IllegalStateException("boom") },
        )
    config.customLogFile = "trigger-staleness.log"

    val result = pipeline.execute(TestRequest(urlPath = "/x", method = "GET"))

    assertNotNull(result)
    assertEquals(500, result.statusCode)
  }

  @Test
  fun executeContinuesOnLastKnownGoodChecksWhenNotFailSecure() = runBlocking {
    val config = neutralConfig { failSecure = false }
    val middleware = TestMiddleware(config)
    val check = StubCheck(middleware, "route_config")

    val pipeline =
        SecurityCheckPipeline(
            listOf(check),
            config = config,
            rebuildChecks = { throw IllegalStateException("boom") },
        )
    config.customLogFile = "trigger-staleness.log"

    val result = pipeline.execute(TestRequest(urlPath = "/x", method = "GET"))

    assertEquals(null, result)
    assertEquals(listOf(check), pipeline.checks)
  }

  @Test
  fun transientRebuildFailureRecoversOnALaterRequest() = runBlocking {
    val config = neutralConfig { failSecure = false }
    val middleware = TestMiddleware(config)
    val oldCheck = StubCheck(middleware, "route_config")
    val newCheck = StubCheck(middleware, "cloud_provider")

    val attempts = intArrayOf(0)
    val pipeline =
        SecurityCheckPipeline(
            listOf(oldCheck),
            config = config,
            rebuildChecks = {
              attempts[0] += 1
              if (attempts[0] == 1) throw IllegalStateException("boom")
              listOf(oldCheck, newCheck)
            },
        )
    config.customLogFile = "trigger-staleness.log"

    pipeline.execute(TestRequest(urlPath = "/x", method = "GET"))
    assertEquals(listOf("route_config"), pipeline.getCheckNames())

    pipeline.execute(TestRequest(urlPath = "/x", method = "GET"))
    assertEquals(listOf("route_config", "cloud_provider"), pipeline.getCheckNames())
  }

  @Test
  fun executeReraisesWhenFailSecureAndNoKnownGoodChecksExist() = runBlocking {
    val config = neutralConfig { failSecure = true }

    val pipeline =
        SecurityCheckPipeline(
            emptyList(),
            config = config,
            rebuildChecks = { throw IllegalStateException("boom") },
        )
    config.customLogFile = "trigger-staleness.log"

    assertFailsWith<IllegalStateException> {
      pipeline.execute(TestRequest(urlPath = "/x", method = "GET"))
    }
    Unit
  }

  // ---------------------------------- test_pipeline_concurrent_rebuild.py

  @Test
  fun concurrentRebuildSelfHealsALostCheck() {
    val config = neutralConfig()
    val middleware = TestMiddleware(config)
    val baselineCheck = StubCheck(middleware, "route_config")
    val cloudCheck = StubCheck(middleware, "cloud_provider")

    val buildStarted = CountDownLatch(1)
    val releaseSlowBuild = CountDownLatch(1)
    val callCount = intArrayOf(0)

    val pipeline =
        SecurityCheckPipeline(
            listOf(baselineCheck),
            config = config,
            rebuildChecks = {
              synchronized(callCount) {
                callCount[0] += 1
              }
              val isFirstCall = callCount[0] == 1
              if (isFirstCall) {
                buildStarted.countDown()
                releaseSlowBuild.await(5, TimeUnit.SECONDS)
                listOf(baselineCheck)
              } else {
                listOf(baselineCheck, cloudCheck)
              }
            },
            watchedContainerFields = listOf("block_cloud_providers"),
        )

    config.customLogFile = "trigger-first-staleness.log"

    // The slow rebuild starts and blocks inside the builder.
    val slowThread = Thread { runBlocking { pipeline.execute(TestRequest()) } }
    slowThread.start()
    assertTrue(buildStarted.await(5, TimeUnit.SECONDS))

    // A config mutation makes the pipeline stale while the slow build is in flight; the fast
    // request's rebuild runs to completion first.
    config.blockCloudProviders = setOf("AWS")
    val fastThread = Thread { runBlocking { pipeline.execute(TestRequest()) } }
    fastThread.start()
    fastThread.join(TimeUnit.SECONDS.toMillis(5))

    releaseSlowBuild.countDown()
    slowThread.join(TimeUnit.SECONDS.toMillis(5))

    // The reference property: the race must not leave the pipeline missing a check while
    // believing it is current. One more rebuild converges either way (pipeline.py:65-81).
    val missingAfterRace = "cloud_provider" !in pipeline.getCheckNames()
    if (missingAfterRace) {
      runBlocking { pipeline.execute(TestRequest()) }
    }
    assertTrue("cloud_provider" in pipeline.getCheckNames())
  }

  // ---------------------------------- test_pipeline_config_revision.py halves

  @Test
  fun mutatingConfigMakesEliminatedUserAgentCheckBlock() = runBlocking {
    val config = neutralConfig()
    val middleware = EmptyRoutesMiddleware(TestMiddleware(config))
    val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
    assertTrue("user_agent" !in pipeline.getCheckNames())

    config.blockedUserAgents = listOf("badbot")

    val request =
        TestRequest(
            clientHost = "198.51.100.101",
            headers = mapOf("User-Agent" to "badbot-scanner"),
        )
    val result = pipeline.execute(request)

    assertTrue("user_agent" in pipeline.getCheckNames())
    assertNotNull(result)
    assertEquals(403, result.statusCode)
  }

  @Test
  fun mutatingConfigMakesEliminatedCustomRequestCheckBlock() = runBlocking {
    val config = neutralConfig()
    val middleware = TestMiddleware(config)
    val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
    assertTrue("custom_request" !in pipeline.getCheckNames())

    config.customRequestCheck =
        com.guardcore.config.CustomRequestCheck { request ->
          object : GuardResponse {
            override val headers: MutableMap<String, String> = linkedMapOf()
            override val statusCode: Int = 451
            override val body: ByteArray = "blocked-by-custom-request-check".encodeToByteArray()
          }
        }

    val request = TestRequest(clientHost = "198.51.100.102")
    val result = pipeline.execute(request)

    assertTrue("custom_request" in pipeline.getCheckNames())
    assertNotNull(result)
    assertEquals(451, result.statusCode)
  }

  @Test
  fun mutatingConfigMakesEliminatedCloudProviderCheckBlock() = runBlocking {
    val config = neutralConfig()
    val middleware = EmptyRoutesMiddleware(TestMiddleware(config))
    val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
    assertTrue("cloud_provider" !in pipeline.getCheckNames())

    val cloud = CloudManager.getInstance()
    val savedRanges = cloud.ipRanges.toMap()
    cloud.ipRanges["AWS"] = (savedRanges["AWS"] ?: emptySet()) +
        com.guardcore.util.py.IpNetwork.parse("3.0.0.0/8")
    config.blockCloudProviders = setOf("AWS")

    try {
      val request = TestRequest(clientHost = "3.0.0.9")
      val result = pipeline.execute(request)

      assertTrue("cloud_provider" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(403, result.statusCode)
    } finally {
      cloud.ipRanges.clear()
      cloud.ipRanges.putAll(savedRanges)
    }
  }
}
