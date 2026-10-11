package com.guardcore.core

import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.responses.ErrorResponseFactory
import com.guardcore.core.responses.ResponseContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_response_factory.py - including the response-factory halves the W3
 * wave deferred from the rate-limit and security-headers per-config tests (KNOWN_GAPS.md, W3
 * deferral note).
 */
public class ResponseFactoryTest {
  private fun factoryFor(
      config: com.guardcore.config.SecurityConfig,
  ): Pair<TestMiddleware, ErrorResponseFactory> {
    val middleware = TestMiddleware(config)
    val factory =
        ErrorResponseFactory(
            ResponseContext(
                config = config,
                logger = middleware.logger,
                metricsCollector = MetricsCollector(null, config),
                agentHandler = null,
                responseFactory = middleware.responseFactory,
            ),
        )
    return middleware to factory
  }

  /** test_response_factory.py:46-56. */
  @Test
  fun createErrorResponseDefaultAndCustom() {
    coreRunTest {
      val (_, factory) = factoryFor(coreTestConfig())
      val response = factory.createErrorResponse(403, "Forbidden")
      assertEquals(403, response.statusCode)
      assertEquals("Forbidden", response.body?.decodeToString())

      val customConfig = coreTestConfig {
        customErrorResponses = mapOf(403 to "Custom Forbidden")
      }
      val (_, customFactory) = factoryFor(customConfig)
      val custom = customFactory.createErrorResponse(403, "Forbidden")
      assertEquals("Custom Forbidden", custom.body?.decodeToString())
    }
  }

  /** test_response_factory.py:58-64. */
  @Test
  fun createHttpsRedirect() {
    coreRunTest {
      val (_, factory) = factoryFor(coreTestConfig())
      val response = factory.createHttpsRedirect(TestRequest(urlPath = "/api/x"))
      assertEquals(301, response.statusCode)
      assertEquals("https://example.com/api/x", response.headers["Location"])
    }
  }

  /**
   * The security-headers response-factory half deferred from W3 (test_security_headers per-config
   * tests): enabled/disabled config drives the headers on the error response.
   */
  @Test
  fun applySecurityHeadersEnabledAndDisabled() {
    coreRunTest {
      val (enabledMiddleware, enabledFactory) = factoryFor(coreTestConfig())
      val enabled = enabledFactory.createErrorResponse(403, "Forbidden")
      assertEquals("nosniff", enabled.headers["X-Content-Type-Options"])
      assertEquals("SAMEORIGIN", enabled.headers["X-Frame-Options"])
      assertTrue(enabled.headers.containsKey("Strict-Transport-Security"))
      // headers only land through the factory; the bare middleware stub does not add them
      assertTrue(enabledMiddleware.bus.events.isEmpty())

      val disabledConfig = coreTestConfig {
        securityHeaders = mapOf("enabled" to false)
      }
      val (_, disabledFactory) = factoryFor(disabledConfig)
      val disabled = disabledFactory.createErrorResponse(403, "Forbidden")
      assertEquals(0, disabled.headers.size)
    }
  }

  /** test_response_factory.py:87-104: CORS headers echo and disabled state. */
  @Test
  fun applyCorsHeaders() {
    coreRunTest {
      val corsConfig = coreTestConfig {
        enableCors = true
        corsAllowOrigins = listOf("https://app.example.com")
      }
      val (_, factory) = factoryFor(corsConfig)
      val base = TestResponse(200)
      val withCors = factory.applyCorsHeaders(base, "https://app.example.com")
      assertEquals("https://app.example.com", withCors.headers["Access-Control-Allow-Origin"])
      assertTrue(withCors.headers.containsKey("Access-Control-Allow-Methods"))
      assertTrue(withCors.headers.containsKey("Access-Control-Max-Age"))
    }
  }

  /** test_response_factory.py:105-145: modifier pass-through, custom, and raise handling. */
  @Test
  fun applyModifier() {
    coreRunTest {
      val (_, noModifier) = factoryFor(coreTestConfig())
      val plain = TestResponse(403)
      assertEquals(plain, noModifier.applyModifier(plain))

      val config = coreTestConfig {
        customResponseModifier =
            com.guardcore.config.CustomResponseModifier { response ->
              response.headers["X-Modified"] = "1"
              response
            }
      }
      val (_, withModifier) = factoryFor(config)
      val modified = withModifier.applyModifier(TestResponse(403))
      assertEquals("1", modified.headers["X-Modified"])

      val raisingConfig = coreTestConfig {
        customResponseModifier =
            com.guardcore.config.CustomResponseModifier { _ ->
              throw IllegalStateException("nope")
            }
      }
      val (_, raising) = factoryFor(raisingConfig)
      val unmodified = raising.applyModifier(TestResponse(403))
      assertEquals(403, unmodified.statusCode)
    }
  }

  /**
   * The rate-limit response-factory half deferred from W3: the 429 body carries the custom error
   * message and the Retry-After header lands via the rate limiter's error path.
   */
  @Test
  fun rateLimitResponseFactoryHalf() {
    coreRunTest {
      val config = coreTestConfig {
        enableRateLimiting = true
        rateLimit = 1
        rateLimitWindow = 60
        customErrorResponses = mapOf(429 to "Custom Too Many Requests")
      }
      val middleware = TestMiddleware(config)
      val factory =
          ErrorResponseFactory(
              ResponseContext(
                  config,
                  middleware.logger,
                  MetricsCollector(null, config),
                  responseFactory = middleware.responseFactory,
              ),
          )
      val limiter = middleware.rateLimitHandler as com.guardcore.handlers.RateLimitManager
      limiter.reset()
      val request = TestRequest(clientHost = "198.51.100.10")
      val first =
          limiter.checkRateLimit(
              request,
              "198.51.100.10",
              { statusCode, defaultMessage ->
                factory.createErrorResponse(statusCode, defaultMessage)
              },
              rateLimit = 1,
              rateLimitWindow = 60,
              config = config,
          )
      assertEquals(null, first)
      val second =
          limiter.checkRateLimit(
              request,
              "198.51.100.10",
              { statusCode, defaultMessage ->
                factory.createErrorResponse(statusCode, defaultMessage)
              },
              rateLimit = 1,
              rateLimitWindow = 60,
              config = config,
          )
      assertEquals(429, second?.statusCode)
      assertEquals("Custom Too Many Requests", second?.body?.decodeToString())
      assertEquals("60", second?.headers?.get("Retry-After"))
    }
  }
}
