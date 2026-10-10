package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Ports of tests/test_cors_handler.py (20 tests). */
class CorsHandlerTest {
  private fun corsConfig(): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableCors = true
            corsAllowOrigins = listOf("https://app.example.com")
            corsAllowMethods = listOf("GET", "POST")
            corsAllowHeaders = listOf("X-Custom")
            corsAllowCredentials = true
            corsMaxAge = 600
            corsExposeHeaders = listOf("X-Trace")
          }
          .build()

  @Test
  fun isPreflightTrueForOptionsWithAcrm() {
    val headers =
        mapOf(
            "origin" to "https://app.example.com",
            "access-control-request-method" to "POST",
        )
    assertEquals(true, isPreflight("OPTIONS", headers))
  }

  @Test
  fun isPreflightLowercaseOptionsWorks() {
    val headers =
        mapOf(
            "origin" to "https://app.example.com",
            "access-control-request-method" to "POST",
        )
    assertEquals(true, isPreflight("options", headers))
  }

  @Test
  fun isPreflightFalseForOptionsWithoutAcrm() {
    assertEquals(false, isPreflight("OPTIONS", mapOf("origin" to "x")))
  }

  @Test
  fun isPreflightFalseForGet() {
    assertEquals(false, isPreflight("GET", mapOf("origin" to "x")))
  }

  @Test
  fun isPreflightHandlesMixedCaseHeaders() {
    val headers =
        mapOf(
            "Origin" to "https://app.example.com",
            "Access-Control-Request-Method" to "POST",
        )
    assertEquals(true, isPreflight("OPTIONS", headers))
  }

  @Test
  fun preflightResponseAllowedOrigin() {
    val handler = CorsHandler(corsConfig())
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://app.example.com",
                    "access-control-request-method" to "POST",
                    "access-control-request-headers" to "X-Custom",
                ),
        )
    assertEquals(200, response.statusCode)
    assertEquals("https://app.example.com", response.headers["Access-Control-Allow-Origin"])
    assertEquals("true", response.headers["Access-Control-Allow-Credentials"])
    assertTrue(response.headers.getValue("Access-Control-Allow-Methods").contains("POST"))
    assertEquals("600", response.headers["Access-Control-Max-Age"])
    assertEquals("Origin", response.headers["Vary"])
  }

  @Test
  fun preflightResponseDisallowedOrigin() {
    val handler = CorsHandler(corsConfig())
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://evil.example.com",
                    "access-control-request-method" to "POST",
                ),
        )
    assertEquals(400, response.statusCode)
    assertTrue(response.body.lowercase().contains("origin"))
  }

  @Test
  fun preflightResponseDisallowedMethod() {
    val handler = CorsHandler(corsConfig())
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://app.example.com",
                    "access-control-request-method" to "DELETE",
                ),
        )
    assertEquals(400, response.statusCode)
    assertTrue(response.body.lowercase().contains("method"))
  }

  @Test
  fun preflightResponseDisallowedHeaders() {
    val handler = CorsHandler(corsConfig())
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://app.example.com",
                    "access-control-request-method" to "POST",
                    "access-control-request-headers" to "X-Not-Allowed",
                ),
        )
    assertEquals(400, response.statusCode)
    assertTrue(response.body.lowercase().contains("headers"))
  }

  @Test
  fun responseHeadersForSimpleRequest() {
    val handler = CorsHandler(corsConfig())
    val headers =
        handler.buildResponseHeaders(requestHeaders = mapOf("origin" to "https://app.example.com"))
    assertEquals("https://app.example.com", headers["Access-Control-Allow-Origin"])
    assertEquals("true", headers["Access-Control-Allow-Credentials"])
    assertEquals("X-Trace", headers["Access-Control-Expose-Headers"])
    assertEquals("Origin", headers["Vary"])
  }

  @Test
  fun responseHeadersForDisallowedOrigin() {
    val handler = CorsHandler(corsConfig())
    val headers =
        handler.buildResponseHeaders(requestHeaders = mapOf("origin" to "https://evil.example.com"))
    assertEquals(emptyMap<String, String>().keys, headers.keys)
  }

  @Test
  fun responseHeadersWithNoOriginReturnsEmpty() {
    val handler = CorsHandler(corsConfig())
    val headers = handler.buildResponseHeaders(requestHeaders = emptyMap())
    assertEquals(emptyMap<String, String>().keys, headers.keys)
  }

  @Test
  fun wildcardOriginWithCredentialsRaisesAtInit() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableCors = true
              corsAllowOrigins = listOf("*")
              corsAllowCredentials = true
            }
            .build()
    assertFailsWithMessage<IllegalArgumentException>("wildcard origin '*' is incompatible") {
      CorsHandler(config)
    }
  }

  @Test
  fun wildcardOriginWithoutCredentials() {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableCors = true
              corsAllowOrigins = listOf("*")
              corsAllowCredentials = false
            }
            .build()
    val handler = CorsHandler(config)
    val headers =
        handler.buildResponseHeaders(requestHeaders = mapOf("origin" to "https://any.example.com"))
    assertEquals("*", headers["Access-Control-Allow-Origin"])
  }

  @Test
  fun allowAllHeadersMirrorsRequested() {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableCors = true
              corsAllowOrigins = listOf("https://app.example.com")
              corsAllowHeaders = listOf("*")
            }
            .build()
    val handler = CorsHandler(config)
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://app.example.com",
                    "access-control-request-method" to "POST",
                    "access-control-request-headers" to "X-Anything, Y-Other",
                ),
        )
    assertEquals(200, response.statusCode)
    assertEquals("X-Anything, Y-Other", response.headers["Access-Control-Allow-Headers"])
  }

  @Test
  fun disabledCorsHandlerSkipsLogic() {
    val config = SecurityConfigBuilder().apply { enableCors = false }.build()
    val handler = CorsHandler(config)
    val headers =
        handler.buildResponseHeaders(requestHeaders = mapOf("origin" to "https://example.com"))
    assertEquals(emptyMap<String, String>().keys, headers.keys)
  }

  @Test
  fun isOriginAllowedFalseWhenDisabled() {
    val config = SecurityConfigBuilder().apply { enableCors = false }.build()
    val handler = CorsHandler(config)
    assertEquals(false, handler.isOriginAllowed("https://example.com"))
  }

  @Test
  fun isOriginAllowedTrueForWildcard() {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableCors = true
              corsAllowOrigins = listOf("*")
            }
            .build()
    val handler = CorsHandler(config)
    assertEquals(true, handler.isOriginAllowed("https://any.example.com"))
  }

  @Test
  fun preflightAllowAllHeadersEmptyRequestedHeadersRaw() {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableCors = true
              corsAllowOrigins = listOf("https://app.example.com")
              corsAllowHeaders = listOf("*")
            }
            .build()
    val handler = CorsHandler(config)
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://app.example.com",
                    "access-control-request-method" to "POST",
                ),
        )
    assertEquals(200, response.statusCode)
    assertFalse(response.headers.containsKey("Access-Control-Allow-Headers"))
  }

  @Test
  fun preflightNoCredentialsFlag() {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableCors = true
              corsAllowOrigins = listOf("https://app.example.com")
              corsAllowCredentials = false
            }
            .build()
    val handler = CorsHandler(config)
    val response =
        handler.buildPreflightResponse(
            requestHeaders =
                mapOf(
                    "origin" to "https://app.example.com",
                    "access-control-request-method" to "GET",
                ),
        )
    assertEquals(200, response.statusCode)
    assertFalse(response.headers.containsKey("Access-Control-Allow-Credentials"))
  }
}
