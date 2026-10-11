package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.checks.ChecksFactory
import com.guardcore.core.checks.SecurityCheckPipeline
import com.guardcore.core.routing.RouteConfigResolver
import com.guardcore.core.routing.RoutingContext
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.RateLimitManager
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.util.py.IpNetwork
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_pipeline_route_config_revision.py: in-place route-config mutations
 * route through the pipeline's revision watch, so an eliminated check comes back on the next
 * execute and a no-predicate mutation rebuilds exactly once without changing the composition.
 *
 * The python middleware is a MagicMock carrying a real RouteConfigResolver and the decorator; the
 * JVM composes the same shape over [TestMiddleware] with a delegating wrapper (the W4a
 * EmptyRoutesMiddleware idiom). The rebuild spy is the constructor seam the W4a rebuild-policy
 * tests established: the pipeline is built exactly like [ChecksFactory.buildDefaultPipeline] with
 * a counting rebuildChecks lambda.
 */
public class PipelineRouteConfigRevisionTest {
  /** python `_neutral_config`: penetration detection + rate limiting off. */
  private fun neutralConfig(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enablePenetrationDetection = false
            enableRateLimiting = false
          }
          .apply(mutate)
          .build()

  private class DecoratorMiddleware(
      private val inner: TestMiddleware,
      decorator: BaseSecurityDecorator?,
  ) : GuardMiddlewareProtocol by inner {
    override val guardDecorator: Any? = decorator
  }

  /** python `MagicMock(get_country=MagicMock(return_value=None))`: a geo handler with no data. */
  private class NullGeoHandler : com.guardcore.protocols.GeoIPHandler {
    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun buildMiddleware(
      config: SecurityConfig,
      decorator: BaseSecurityDecorator?,
  ): DecoratorMiddleware {
    val inner =
        TestMiddleware(
            config,
            resolver =
                RouteConfigResolver(
                    RoutingContext(config = config, logger = Logger.getLogger("test.revision"), guardDecorator = decorator),
                ),
        )
    return DecoratorMiddleware(inner, decorator)
  }

  /** build_default_pipeline with a counting _build_checks wrap (python's rebuild_spy). */
  private fun buildCountingPipeline(
      middleware: GuardMiddlewareProtocol,
      config: SecurityConfig,
  ): Pair<SecurityCheckPipeline, IntArray> {
    val rebuilds = intArrayOf(0)
    val pipeline =
        SecurityCheckPipeline(
            ChecksFactory.buildChecks(middleware),
            mutedCheckLogs = config.mutedCheckLogs,
            config = config,
            rebuildChecks = {
              rebuilds[0] += 1
              ChecksFactory.buildChecks(middleware)
            },
            watchedContainerFields = ChecksFactory.WATCHED_CONTAINER_FIELDS,
            routeConfigRevision = { ChecksFactory.routeConfigRevision(middleware) },
        )
    return pipeline to rebuilds
  }

  private fun requestWithRoute(
      clientHost: String,
      routeId: String?,
      headers: Map<String, String> = emptyMap(),
  ): TestRequest {
    val request = TestRequest(clientHost = clientHost, headers = headers)
    if (routeId != null) {
      request.state.setAttr("guard_route_id", routeId)
    }
    return request
  }

  /** python `_blocking_validator`: a validator that blocks with a 418. */
  private fun blockingValidator(): suspend (com.guardcore.protocols.GuardRequest) -> Any? =
      { TestResponse(418, "blocked-by-custom-validator".encodeToByteArray()) }

  // ------------------------------- test_pipeline_route_config_revision.py:66-86

  @Test
  fun assigningAuthRequiredOnExistingRouteRunsEliminatedCheck() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val routeId = "routeA"
      val middleware = buildMiddleware(config, decorator)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("authentication" !in pipeline.getCheckNames())

      rc.authRequired = "bearer"
      rc.touch()

      val result = pipeline.execute(requestWithRoute("198.51.100.201", routeId))

      assertTrue("authentication" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(401, result.statusCode)
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:89-109

  @Test
  fun registeringNewRouteWithHeadersRunsEliminatedHeadersCheck() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val middleware = buildMiddleware(config, decorator)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("required_headers" !in pipeline.getCheckNames())

      val newRc = decorator.ensureRouteConfig("routeB")
      newRc.requiredHeaders["X-Api-Key"] = "required"

      val result =
          pipeline.execute(requestWithRoute("198.51.100.202", "routeB"))

      assertTrue("required_headers" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(400, result.statusCode)
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:112-130

  @Test
  fun appendingCustomValidatorInPlaceRunsEliminatedCheck() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("custom_validators" !in pipeline.getCheckNames())

      rc.customValidators.add(blockingValidator())

      val result = pipeline.execute(requestWithRoute("198.51.100.203", "routeA"))

      assertTrue("custom_validators" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(418, result.statusCode)
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:133-151

  @Test
  fun settingRequiredHeaderItemInPlaceRunsEliminatedCheck() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("required_headers" !in pipeline.getCheckNames())

      rc.requiredHeaders["X-Api-Key"] = "required"

      val result = pipeline.execute(requestWithRoute("198.51.100.205", "routeA"))

      assertTrue("required_headers" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(400, result.statusCode)
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:154-174

  @Test
  fun appendingBlockedUserAgentInPlaceRunsEliminatedCheck() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("user_agent" !in pipeline.getCheckNames())

      rc.blockedUserAgents.add("badbot")

      val result =
          pipeline.execute(
              requestWithRoute(
                  "198.51.100.208",
                  "routeA",
                  headers = mapOf("User-Agent" to "badbot-scanner"),
              ),
          )

      assertTrue("user_agent" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(403, result.statusCode)
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:177-196
  // python patches cloud_handler.is_cloud_ip; the JVM drives the real CloudManager ranges
  // (the established real path).

  @Test
  fun addingBlockCloudProviderInPlaceRunsEliminatedCheck() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("cloud_provider" !in pipeline.getCheckNames())

      rc.blockCloudProviders.add("AWS")

      val cloud = CloudManager.getInstance()
      val savedRanges = cloud.ipRanges.toMap()
      cloud.ipRanges["AWS"] = (savedRanges["AWS"] ?: emptySet()) + IpNetwork.parse("3.0.0.0/8")
      try {
        val result = pipeline.execute(requestWithRoute("3.0.0.9", "routeA"))

        assertTrue("cloud_provider" in pipeline.getCheckNames())
        assertNotNull(result)
        assertEquals(403, result.statusCode)
      } finally {
        cloud.ipRanges.clear()
        cloud.ipRanges.putAll(savedRanges)
      }
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:199-222

  @Test
  fun updatingGeoRateLimitInPlaceRunsEliminatedCheck() {
    coreRunTest {
      val config = neutralConfig { geoIpHandler = NullGeoHandler() }
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)
      val rateLimitHandler = middleware.rateLimitHandler as RateLimitManager
      rateLimitHandler.reset()

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("rate_limit" !in pipeline.getCheckNames())

      // python assigns {} then writes ["*"] in place; the assignment wraps the map in a
      // revision-tracked container, so the in-place write bumps the revision.
      rc.geoRateLimits = mutableMapOf()
      @Suppress("UNCHECKED_CAST")
      val trackedGeo = rc.geoRateLimits as MutableMap<String, kotlin.Pair<Int, Int>>
      trackedGeo["*"] = kotlin.Pair(0, 60)
      // python's MagicMock rate_limit_handler short-circuits to a 429; the JVM drives the real
      // manager, which honors this knob at execute time (the initial composition above is
      // asserted before the flip, so the check still starts eliminated).
      config.enableRateLimiting = true

      val result = pipeline.execute(requestWithRoute("198.51.100.209", "routeA"))

      assertTrue("rate_limit" in pipeline.getCheckNames())
      assertNotNull(result)
      assertEquals(429, result.statusCode)
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:225-247

  @Test
  fun mutatingFieldNoPredicateReadsDoesNotChangeComposition() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      val rc = decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)

      val (pipeline, rebuilds) = buildCountingPipeline(middleware, config)
      val before = pipeline.getCheckNames()

      rc.rateLimitWindow = 120
      rc.touch()

      val request = requestWithRoute("198.51.100.204", "routeA")
      repeat(5) { pipeline.execute(request) }

      assertEquals(before, pipeline.getCheckNames())
      // The revision bumped, so exactly one rebuild ran; the composition is unchanged.
      assertEquals(1, rebuilds[0])
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:250-268

  @Test
  fun executeDoesNotRebuildWhenRouteConfigsAreUnchanged() {
    coreRunTest {
      val config = neutralConfig()
      val decorator = BaseSecurityDecorator(config)
      decorator.ensureRouteConfig("routeA")
      val middleware = buildMiddleware(config, decorator)

      val (pipeline, rebuilds) = buildCountingPipeline(middleware, config)

      val request = requestWithRoute("198.51.100.206", "routeA")
      repeat(5) { pipeline.execute(request) }

      assertEquals(0, rebuilds[0])
    }
  }

  // ------------------------------- test_pipeline_route_config_revision.py:271-283

  @Test
  fun pipelineWithoutGuardDecoratorNeverRebuildsOnRouteChanges() {
    coreRunTest {
      val config = neutralConfig()
      val middleware = buildMiddleware(config, decorator = null)

      val pipeline = ChecksFactory.buildDefaultPipeline(middleware)
      assertTrue("authentication" in pipeline.getCheckNames())

      val result = pipeline.execute(requestWithRoute("198.51.100.207", null))

      assertNull(result)
    }
  }
}
