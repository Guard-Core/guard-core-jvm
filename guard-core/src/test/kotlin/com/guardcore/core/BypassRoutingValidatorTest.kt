package com.guardcore.core

import com.guardcore.core.bypass.BypassContext
import com.guardcore.core.bypass.BypassHandler
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.responses.ResponseContext
import com.guardcore.core.routing.RouteConfigResolver
import com.guardcore.core.routing.RoutingContext
import com.guardcore.core.validation.RequestValidator
import com.guardcore.core.validation.ValidationContext
import com.guardcore.decorators.BaseSecurityDecorator
import com.guardcore.decorators.RouteConfig
import com.guardcore.decorators.RouteConfigRevision
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_bypass_handler.py, test_routing_resolver.py and test_validator.py
 * (the exclusion/passive surface the wave gate names).
 */
public class BypassRoutingValidatorTest {
  /** test_routing_resolver.py:43-120. */
  @Test
  fun routingResolver() {
    val config = coreTestConfig()
    val decorator = BaseSecurityDecorator(config)
    val revision = RouteConfigRevision()
    val route = RouteConfig(revision)
    route.bypassedChecks.add("rate_limit")
    decorator.routeConfigMap["m.tests.mod.fn"] = route
    val context = RoutingContext(config, LoggerFor("routing"), guardDecorator = decorator)
    val resolver = RouteConfigResolver(context)

    val request = TestRequest(urlPath = "/api")
    assertNull(resolver.getRouteConfig(request))

    request.state.setAttr("guard_route_id", "m.tests.mod.fn")
    assertEquals(route, resolver.getRouteConfig(request))

    request.state.setAttr("guard_route_id", null)
    assertNull(resolver.getRouteConfig(request))

    val noDecoratorContext = RoutingContext(config, LoggerFor("routing"), guardDecorator = null)
    val bareResolver = RouteConfigResolver(noDecoratorContext)
    request.state.setAttr("guard_route_id", "m.tests.mod.fn")
    assertNull(bareResolver.getRouteConfig(request))

    // should_bypass_check
    assertFalse(resolver.shouldBypassCheck("ip", null))
    assertTrue(resolver.shouldBypassCheck("rate_limit", route))
    assertFalse(resolver.shouldBypassCheck("ip", route))
    val allRoute = RouteConfig()
    allRoute.bypassedChecks.add("all")
    assertTrue(resolver.shouldBypassCheck("ip", allRoute))

    // get_cloud_providers_to_check
    assertNull(resolver.getCloudProvidersToCheck(null))
    assertNull(resolver.getCloudProvidersToCheck(route))
    route.blockCloudProviders.add("aws")
    assertEquals(listOf("aws"), resolver.getCloudProvidersToCheck(route))
  }

  /** RouteConfig revision bumps on attribute writes (route_config.py:280-291). */
  @Test
  fun routeConfigRevisionBumps() {
    val revision = RouteConfigRevision()
    val route = RouteConfig(revision)
    assertEquals(0, revision.value)
    route.requireHttps = true
    route.touch()
    assertEquals(1, revision.value)
    route.touch()
    assertEquals(2, revision.value)
  }

  /** test_bypass_handler.py:219-256: excluded path marks the request and skips the warning. */
  @Test
  fun bypassPassthroughExcludedPath() {
    val config = coreTestConfig {
      excludePaths = listOf("/health", "/metrics")
      failSecure = true
    }
    val middleware = TestMiddleware(config)
    val bus = middleware.bus
    val validator =
        RequestValidator(
            ValidationContext(config, middleware.logger, bus),
        )
    val handler =
        BypassHandler(
            BypassContext(
                config = config,
                logger = middleware.logger,
                eventBus = bus,
                routeResolver = RouteConfigResolver(RoutingContext(config, middleware.logger)),
                responseFactory =
                    ErrorResponseFactory(
                        ResponseContext(
                            config,
                            middleware.logger,
                            MetricsCollector(null, config),
                            responseFactory = middleware.responseFactory,
                        ),
                    ),
                validator = validator,
            ),
        )

    val excluded = TestRequest(urlPath = "/health")
    val result = kotlinx.coroutines.runBlocking { handler.handlePassthrough(excluded) { null } }
    assertNull(result)
    assertEquals(true, excluded.state.getAttr("guard_exclusion_scoped"))

    val normal = TestRequest(urlPath = "/api/data")
    val normalResult = kotlinx.coroutines.runBlocking { handler.handlePassthrough(normal) { null } }
    assertNull(normalResult)
    assertEquals(null, normal.state.getAttr("guard_exclusion_scoped"))
  }

  /** test_bypass_handler.py:109-150: no client address -> fail-secure 403, fail-open unknown. */
  @Test
  fun bypassPassthroughNoClient() {
    val secureConfig = coreTestConfig { failSecure = true }
    val secureMiddleware = TestMiddleware(secureConfig)
    val secureHandler = bypassHandlerFor(secureConfig, secureMiddleware)

    val noClient = TestRequest(clientHost = null)
    val response =
        kotlinx.coroutines.runBlocking { secureHandler.handlePassthrough(noClient) { null } }
    assertEquals(403, response?.statusCode)
    assertEquals(
        com.guardcore.util.IpExtraction.UNKNOWN_CLIENT_IDENTITY,
        noClient.state.getAttr("client_ip"),
    )

    val openConfig = coreTestConfig { failSecure = false }
    val openMiddleware = TestMiddleware(openConfig)
    val openHandler = bypassHandlerFor(openConfig, openMiddleware)
    val openRequest = TestRequest(clientHost = null)
    val openResult =
        kotlinx.coroutines.runBlocking { openHandler.handlePassthrough(openRequest) { null } }
    assertNull(openResult)
    assertEquals(
        com.guardcore.util.IpExtraction.UNKNOWN_CLIENT_IDENTITY,
        openRequest.state.getAttr("client_ip"),
    )
  }

  /** test_bypass_handler.py: security_bypass passthrough + passive-mode skip. */
  @Test
  fun bypassSecurityBypass() {
    val config = coreTestConfig()
    val middleware = TestMiddleware(config)
    val handler = bypassHandlerFor(config, middleware)

    val plainRoute = RouteConfig()
    val plainRequest = TestRequest()
    val plainResult =
        kotlinx.coroutines.runBlocking {
          handler.handleSecurityBypass(plainRequest, { null }, plainRoute)
        }
    assertNull(plainResult)
    assertTrue(middleware.bus.events.isEmpty())

    val bypassRoute = RouteConfig()
    bypassRoute.bypassedChecks.add("all")
    val bypassedRequest = TestRequest()
    val bypassResult =
        kotlinx.coroutines.runBlocking {
          handler.handleSecurityBypass(
              bypassedRequest,
              { TestResponse(200, "ok".encodeToByteArray()) },
              bypassRoute,
          )
        }
    assertEquals(200, bypassResult?.statusCode)
    assertEquals(1, middleware.bus.events.size)

    val passiveConfig = coreTestConfig { passiveMode = true }
    val passiveMiddleware = TestMiddleware(passiveConfig)
    val passiveHandler = bypassHandlerFor(passiveConfig, passiveMiddleware)
    val passiveRequest = TestRequest()
    var called = false
    val passiveResult =
        kotlinx.coroutines.runBlocking {
          passiveHandler.handleSecurityBypass(
              passiveRequest,
              {
                called = true
                TestResponse(200)
              },
              bypassRoute,
          )
        }
    assertNull(passiveResult)
    assertFalse(called)
  }

  private fun bypassHandlerFor(
      config: com.guardcore.config.SecurityConfig,
      middleware: TestMiddleware,
  ): BypassHandler =
      BypassHandler(
          BypassContext(
              config = config,
              logger = middleware.logger,
              eventBus = middleware.bus,
              routeResolver = RouteConfigResolver(RoutingContext(config, middleware.logger)),
              responseFactory =
                  ErrorResponseFactory(
                      ResponseContext(
                          config,
                          middleware.logger,
                          MetricsCollector(null, config),
                          responseFactory = middleware.responseFactory,
                      ),
                  ),
              validator =
                  RequestValidator(
                      ValidationContext(config, middleware.logger, middleware.bus),
                  ),
          ),
      )

  /** test_validator.py surface: is_path_excluded emits the exclusion event once per path. */
  @Test
  fun validatorPathExcludedEventOnce() {
    val config = coreTestConfig { excludePaths = listOf("/public") }
    val middleware = TestMiddleware(config)
    val validator = RequestValidator(ValidationContext(config, middleware.logger, middleware.bus))

    val request = TestRequest(urlPath = "/public/docs")
    val first = kotlinx.coroutines.runBlocking { validator.isPathExcluded(request) }
    val second = kotlinx.coroutines.runBlocking { validator.isPathExcluded(request) }
    assertTrue(first)
    assertTrue(second)
    assertEquals(1, middleware.bus.events.size)
    assertEquals("path_excluded", middleware.bus.events[0]["event_type"])
    assertEquals("security_checks_bypassed", middleware.bus.events[0]["action_taken"])

    val notExcluded = TestRequest(urlPath = "/api")
    val third = kotlinx.coroutines.runBlocking { validator.isPathExcluded(notExcluded) }
    assertFalse(third)
    assertEquals(1, middleware.bus.events.size)
  }

  /** test_validator.py: trusted-proxy X-Forwarded-Proto https detection. */
  @Test
  fun validatorRequestHttps() {
    val config = coreTestConfig {
      trustXForwardedProto = true
      trustedProxies = listOf("10.0.0.0/8")
    }
    val middleware = TestMiddleware(config)
    val validator = RequestValidator(ValidationContext(config, middleware.logger, middleware.bus))

    val plain = TestRequest(urlScheme = "http")
    assertFalse(validator.isRequestHttps(plain))

    val proxied =
        TestRequest(
            clientHost = "10.0.0.1",
            urlScheme = "http",
            headers = mapOf("X-Forwarded-Proto" to "https"),
        )
    assertTrue(validator.isRequestHttps(proxied))
  }

  private fun LoggerFor(name: String): java.util.logging.Logger =
      java.util.logging.Logger.getLogger("test.$name")
}
