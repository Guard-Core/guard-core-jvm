package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll

/** Shared config helpers for the security-headers ports. */
public fun headersConfig(vararg pairs: Pair<String, Any?>): SecurityConfig {
  val merged = linkedMapOf<String, Any?>("enabled" to true)
  for (pair in pairs) {
    merged[pair.first] = pair.second
  }
  return SecurityConfigBuilder()
      .apply {
        enableRedis = false
        redisUrl = null
        securityHeaders = merged
      }
      .build()
}

private suspend fun freshHeadersManager(): SecurityHeadersManager {
  SecurityHeadersManager.resetInstance()
  val m = SecurityHeadersManager.getInstance()
  m.reset()
  SecurityHeadersManager.resetInstance()
  val fresh = SecurityHeadersManager.getInstance()
  return fresh
}

/** Ports of tests/test_security_headers/test_security_validation.py (18 tests). */
class SecurityHeadersValidationTest {
  @Test
  fun headerValueWithNewlineRejected() = runTest {
    val manager = freshHeadersManager()
    assertFailsWithMessage<IllegalArgumentException>("Invalid header value contains newline") {
      manager.configure(frameOptions = "DENY\r\nX-Evil: true")
    }
    assertFailsWithMessage<IllegalArgumentException>("Invalid header value contains newline") {
      manager.configure(referrerPolicy = "no-referrer\nX-Evil: true")
    }
  }

  @Test
  fun headerNameWithNewlineRejected() = runTest {
    val manager = freshHeadersManager()
    assertFailsWithMessage<IllegalArgumentException>("Invalid header name") {
      manager.configure(customHeaders = mapOf("X-Bad\nName" to "value"))
    }
  }

  @Test
  fun headerNameTokenCharactersAccepted() = runTest {
    val manager = freshHeadersManager()
    manager.configure(
        customHeaders = mapOf("X-Custom-Header123" to "value", "X!#\$%&'*+.^_`|~-Y" to "value"),
    )
    val headers = manager.getHeaders()
    assertEquals("value", headers["X-Custom-Header123"])
    assertEquals("value", headers["X!#\$%&'*+.^_`|~-Y"])
  }

  @Test
  fun headerValueTooLongRejected() = runTest {
    val manager = freshHeadersManager()
    assertFailsWithMessage<IllegalArgumentException>("Header value too long") {
      manager.configure(customHeaders = mapOf("X-Long" to "a".repeat(8193)))
    }
  }

  @Test
  fun controlCharactersSanitized() = runTest {
    val manager = freshHeadersManager()
    manager.configure(customHeaders = mapOf("X-Custom" to "normal\u0000text"))
    val headers = manager.getHeaders()
    assertEquals("normaltext", headers["X-Custom"])

    // python asserts the tab survives: "normal\ttext".
    manager.configure(customHeaders = mapOf("X-Custom" to "normal\ttext"))
    assertEquals("normal\ttext", manager.getHeaders()["X-Custom"])
  }

  @Test
  fun standardHeadersValidated() = runTest {
    val manager = freshHeadersManager()
    assertFailsWithMessage<IllegalArgumentException>("Invalid header value contains newline") {
      manager.configure(frameOptions = "DENY\r\nX-Evil: true")
    }
    assertFailsWithMessage<IllegalArgumentException>("Invalid header value contains newline") {
      manager.configure(referrerPolicy = "no-referrer\nX-Evil: true")
    }
  }

  @Test
  fun singletonInitializationOnce() = runTest {
    val m1 = SecurityHeadersManager.getInstance()
    val m2 = SecurityHeadersManager.getInstance()
    val m3 = SecurityHeadersManager.getInstance()
    assertTrue(m1 === m2 && m2 === m3)
  }

  @Test
  fun singletonConcurrentCreationYieldsOneInstance() = runTest {
    val results =
        kotlinx.coroutines.coroutineScope {
          (1..10).map { async { SecurityHeadersManager.getInstance() } }.awaitAll()
        }
    assertTrue(results.all { it === results[0] })
  }

  @Test
  fun cacheKeyUsesHashing() = runTest {
    val manager = freshHeadersManager()
    val keys =
        listOf("/api/users", "/API/USERS", "/api/users/", "api/users").map { p ->
          manager.generateCacheKey(p)
        }
    for (key in keys) {
      assertTrue(key.startsWith("path_"))
      assertEquals(21, key.length)
      assertTrue(key.substring(5).all { it in "0123456789abcdef" })
    }
    assertEquals(keys[0], keys[1])
    assertEquals(keys[1], keys[2])
    assertEquals(keys[2], keys[3])
  }

  @Test
  fun cacheKeyCollisionResistance() = runTest {
    val manager = freshHeadersManager()
    val keys = (1..20).map { i -> manager.generateCacheKey("/path/$i") }
    assertEquals(keys.size, keys.toSet().size)
  }

  @Test
  fun cacheKeyDefaultPath() = runTest {
    val manager = freshHeadersManager()
    assertEquals("default", manager.generateCacheKey(null))
    assertEquals("default", manager.generateCacheKey(""))
  }

  @Test
  fun hstsPreloadRequiresLongMaxAge() = runTest {
    val manager = freshHeadersManager()
    captureLogs("guard_core.handlers.security_headers", java.util.logging.Level.WARNING) { capture
      ->
      manager.configure(hstsMaxAge = 1000, hstsPreload = true)
      assertTrue(manager.hstsConfig != null)
      assertEquals(false, manager.hstsConfig!!["preload"])
      assertTrue(
          capture.records.any { it.message.contains("HSTS preload requires max_age >= 31536000") },
      )
    }
  }

  @Test
  fun hstsPreloadRequiresIncludeSubdomains() = runTest {
    val manager = freshHeadersManager()
    captureLogs("guard_core.handlers.security_headers", java.util.logging.Level.WARNING) { capture
      ->
      manager.configure(hstsMaxAge = 31536000, hstsIncludeSubdomains = false, hstsPreload = true)
      assertTrue(manager.hstsConfig != null)
      assertEquals(true, manager.hstsConfig!!["include_subdomains"])
      assertTrue(
          capture.records.any { it.message.contains("HSTS preload requires includeSubDomains") },
      )
    }
  }

  @Test
  fun hstsValidPreloadConfiguration() = runTest {
    val manager = freshHeadersManager()
    captureLogs("guard_core.handlers.security_headers", java.util.logging.Level.WARNING) { capture
      ->
      manager.configure(hstsMaxAge = 31536000, hstsIncludeSubdomains = true, hstsPreload = true)
      assertTrue(manager.hstsConfig != null)
      assertEquals(true, manager.hstsConfig!!["preload"])
      assertEquals(true, manager.hstsConfig!!["include_subdomains"])
      assertEquals(31536000, manager.hstsConfig!!["max_age"])
      assertFalse(capture.records.any { it.message.contains("HSTS preload requires") })
    }
  }

  @Test
  fun reconfigureWithoutHstsClearsTheStaleHeader() = runTest {
    val manager = freshHeadersManager()
    manager.configure(hstsMaxAge = 31536000)
    assertTrue(manager.getHeaders().containsKey("Strict-Transport-Security"))

    manager.configure()
    assertNull(manager.hstsConfig)
    assertFalse(manager.getHeaders().containsKey("Strict-Transport-Security"))
  }

  @Test
  fun reconfigureWithNoOverridesClearsEveryPriorGroup() = runTest {
    val manager = freshHeadersManager()
    manager.configure(
        csp = mapOf("default-src" to listOf("'self'")),
        hstsMaxAge = 31536000,
        corsOrigins = listOf("https://app.example.com"),
        corsAllowCredentials = true,
        customHeaders = mapOf("X-Custom" to "enabled"),
    )

    manager.configure()

    assertNull(manager.cspConfig)
    assertNull(manager.hstsConfig)
    assertNull(manager.corsConfig)
    assertEquals(emptyMap<String, String>(), manager.customHeaders)
    assertFalse(manager.getHeaders().containsKey("Content-Security-Policy"))
    assertFalse(manager.getHeaders().containsKey("Strict-Transport-Security"))
  }
}

/**
 * Ports of tests/test_security_headers/test_per_config_isolation.py (5 tests; the response factory
 * half is W4).
 */
class SecurityHeadersPerConfigIsolationTest {
  @Test
  fun getHeadersWithExplicitConfigsStayIsolated() = runTest {
    val cspA = mapOf("default-src" to listOf("'self'"))
    val cspB =
        linkedMapOf<String, List<String>>(
            "default-src" to listOf("'none'"),
            "script-src" to listOf("'none'"),
        )
    val configA = headersConfig("csp" to cspA)
    val configB = headersConfig("csp" to cspB)

    val manager = freshHeadersManager()
    manager.configure(enabled = true, csp = cspA)
    val headersA = manager.getHeaders("/a", config = configA)

    manager.configure(enabled = true, csp = cspB)
    val headersB = manager.getHeaders("/b", config = configB)

    val headersAAgain = manager.getHeaders("/a", config = configA)

    assertEquals("default-src 'self'", headersA["Content-Security-Policy"])
    assertEquals("default-src 'none'; script-src 'none'", headersB["Content-Security-Policy"])
    assertEquals("default-src 'self'", headersAAgain["Content-Security-Policy"])
  }

  @Test
  fun getHeadersWithConfigDisabledReturnsEmpty() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              securityHeaders = linkedMapOf("enabled" to false)
            }
            .build()
    val manager = freshHeadersManager()
    val headers = manager.getHeaders("/off", config = config)
    assertEquals(emptyMap<String, String>(), headers)
  }

  @Test
  fun getHeadersWithoutConfigUsesMostRecentlyConfiguredState() = runTest {
    val manager = freshHeadersManager()
    manager.configure(enabled = true, csp = mapOf("default-src" to listOf("'self'")))
    manager.configure(enabled = true, csp = mapOf("default-src" to listOf("'none'")))

    val headers = manager.getHeaders("/legacy")
    assertEquals("default-src 'none'", headers["Content-Security-Policy"])
  }

  @Test
  fun getCorsHeadersWithExplicitConfigsStayIsolated() = runTest {
    val configA =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              securityHeaders = linkedMapOf("enabled" to true)
              enableCors = true
              corsAllowOrigins = listOf("https://a.example.com")
            }
            .build()
    val configB =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              securityHeaders = linkedMapOf("enabled" to true)
              enableCors = true
              corsAllowOrigins = listOf("https://b.example.com")
            }
            .build()

    val manager = freshHeadersManager()
    val corsA = manager.getCorsHeaders("https://a.example.com", config = configA)
    val corsB = manager.getCorsHeaders("https://b.example.com", config = configB)
    val corsARejectsB = manager.getCorsHeaders("https://b.example.com", config = configA)

    assertEquals("https://a.example.com", corsA["Access-Control-Allow-Origin"])
    assertEquals("https://b.example.com", corsB["Access-Control-Allow-Origin"])
    assertEquals(emptyMap<String, String>(), corsARejectsB)
  }

  @Test
  fun perConfigCacheKeysAreDistinct() = runTest {
    val configA = headersConfig()
    val configB = headersConfig()
    val manager = freshHeadersManager()
    assertFalse(manager.generateCacheKey("/p", configA) == manager.generateCacheKey("/p", configB))
    assertTrue(manager.generateCacheKey("/p", configA) == manager.generateCacheKey("/p", configA))
  }
}

/**
 * Ports of tests/test_security_headers/test_edge_cases.py (core set) and test_csp_validation.py.
 */
class SecurityHeadersEdgeCasesTest {
  @Test
  fun resetGlobalStateClearsState() = runTest {
    val manager = freshHeadersManager()
    manager.configure(customHeaders = mapOf("X-Keep" to "1"))
    resetSecurityHeadersGlobalState()
    val newManager = SecurityHeadersManager.getInstance()
    assertEquals(true, newManager.enabled)
    assertEquals(0, newManager.customHeaders.size)
  }

  @Test
  fun completeSecureConfiguration() = runTest {
    val manager = freshHeadersManager()
    manager.configure(
        csp =
            linkedMapOf(
                "default-src" to listOf("'self'"),
                "script-src" to listOf("'self'", "https://cdn.example.com"),
            ),
        hstsMaxAge = 63072000,
        hstsPreload = true,
        customHeaders =
            linkedMapOf(
                "X-Custom-Security" to "enabled",
                "X-Request-ID" to "123456",
            ),
        corsOrigins = listOf("https://app.example.com"),
        corsAllowCredentials = true,
    )

    val headers = manager.getHeaders()
    assertTrue(headers.containsKey("Content-Security-Policy"))
    assertTrue(headers.getValue("Content-Security-Policy").contains("default-src 'self'"))
    assertTrue(headers.containsKey("Strict-Transport-Security"))
    val hsts = headers.getValue("Strict-Transport-Security")
    assertTrue(hsts.contains("max-age=63072000"))
    assertTrue(hsts.contains("includeSubDomains"))
    assertTrue(hsts.contains("preload"))
    assertEquals("enabled", headers["X-Custom-Security"])
    assertEquals("123456", headers["X-Request-ID"])

    val corsHeaders = manager.getCorsHeaders("https://app.example.com")
    assertEquals("https://app.example.com", corsHeaders["Access-Control-Allow-Origin"])
    assertEquals("true", corsHeaders["Access-Control-Allow-Credentials"])
  }

  @Test
  fun buildHstsVariants() = runTest {
    val manager = freshHeadersManager()
    assertEquals(
        "max-age=31536000",
        manager.buildHsts(
            linkedMapOf("max_age" to 31536000, "include_subdomains" to false, "preload" to false),
        ),
    )
    assertEquals(
        "max-age=31536000; includeSubDomains",
        manager.buildHsts(
            linkedMapOf("max_age" to 31536000, "include_subdomains" to true, "preload" to false),
        ),
    )
    assertEquals(
        "max-age=31536000; includeSubDomains; preload",
        manager.buildHsts(
            linkedMapOf("max_age" to 31536000, "include_subdomains" to true, "preload" to true),
        ),
    )
  }

  @Test
  fun wildcardOriginWithCredentialsBlocksCors() = runTest {
    val manager = freshHeadersManager()
    manager.configure(corsOrigins = listOf("*"), corsAllowCredentials = false)
    // Wildcard without credentials serves the wildcard headers.
    val served = manager.getCorsHeaders("https://anything.example.com")
    assertEquals("*", served["Access-Control-Allow-Origin"])

    // A credentials-true cors_config blocks CORS entirely.
    manager.corsConfig =
        linkedMapOf<String, Any?>(
            "origins" to listOf("*"),
            "allow_credentials" to true,
        )
    val blocking = manager.getCorsHeaders("https://anything.example.com")
    assertEquals(emptyMap<String, String>(), blocking)
  }

  @Test
  fun cspReportValidationRequiresFields() = runTest {
    val manager = freshHeadersManager()
    val incomplete = linkedMapOf<String, Any?>("document-uri" to "x")
    assertEquals(false, manager.validateCspReport(linkedMapOf("csp-report" to incomplete)))

    val complete =
        linkedMapOf<String, Any?>(
            "document-uri" to "https://e.example.com/",
            "violated-directive" to "script-src",
            "blocked-uri" to "https://evil.example.com/x.js",
        )
    assertEquals(true, manager.validateCspReport(linkedMapOf("csp-report" to complete)))
  }

  @Test
  fun headersAppliedEventEmittedWithAgent() = runTest {
    val manager = freshHeadersManager()
    val agent = RecordingAgent()
    manager.agentHandler = agent
    manager.getHeaders("/some/path")
    assertEquals(1, agent.events.size)
    assertEquals("security_headers_applied", agent.events[0]["event_type"])
    @Suppress("UNCHECKED_CAST") val metadata = agent.events[0]["metadata"] as Map<String, Any?>
    assertEquals("/some/path", metadata["path"])
    assertEquals(false, metadata["has_csp"])
  }

  @Test
  fun headersAppliedEventNotEmittedWithoutPath() = runTest {
    val manager = freshHeadersManager()
    val agent = RecordingAgent()
    manager.agentHandler = agent
    manager.getHeaders()
    assertEquals(0, agent.events.size)
  }
}

/** Ports of tests/test_security_headers/test_redis_integration.py (the live-Redis core set). */
class SecurityHeadersRedisIntegrationTest {
  @Test
  fun initializeRedisCachesConfiguration() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val manager = freshHeadersManager()
      manager.configure(
          csp = mapOf("default-src" to listOf("'self'")),
          hstsMaxAge = 31536000,
          customHeaders = mapOf("X-Custom" to "value"),
      )
      manager.initializeHeadersRedis(redis)

      assertTrue(
          redis
              .operations()!!
              .get("${config.redisPrefix}security_headers:csp_config")!!
              .contains("default-src"),
      )
      assertTrue(
          redis
              .operations()!!
              .get("${config.redisPrefix}security_headers:hsts_config")!!
              .contains("31536000"),
      )
      assertTrue(
          redis
              .operations()!!
              .get("${config.redisPrefix}security_headers:custom_headers")!!
              .contains("X-Custom"),
      )
    } finally {
      redis.close()
    }
  }

  @Test
  fun loadCachedConfigRestoresFromRedis() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val manager = freshHeadersManager()
      manager.configure(
          csp = mapOf("default-src" to listOf("'self'")),
          hstsMaxAge = 63072000,
          customHeaders = mapOf("X-Restored" to "yes"),
      )
      manager.initializeHeadersRedis(redis)

      // A fresh manager restores the persisted configuration from Redis.
      val manager2 = freshHeadersManager()
      manager2.initializeHeadersRedis(redis)
      assertEquals(mapOf("default-src" to listOf("'self'")), manager2.cspConfig)
      assertEquals(63072000L, manager2.hstsConfig!!["max_age"])
      assertEquals("yes", manager2.customHeaders["X-Restored"])
    } finally {
      redis.close()
    }
  }

  @Test
  fun resetClearsRedisSecurityHeaderKeys() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val manager = freshHeadersManager()
      manager.configure(customHeaders = mapOf("X-Custom" to "value"))
      manager.initializeHeadersRedis(redis)

      val keys = redis.keys("security_headers:*")
      assertTrue(keys!!.isNotEmpty())

      manager.reset()
      val after = redis.keys("security_headers:*")
      assertTrue(after.isNullOrEmpty())
      assertNull(manager.redisHandler)
    } finally {
      redis.close()
    }
  }

  @Test
  fun headerTtlIsOneDay() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val manager = freshHeadersManager()
      manager.configure(hstsMaxAge = 63072000)
      manager.initializeHeadersRedis(redis)

      val ttl = redis.operations()!!.pTtl("${config.redisPrefix}security_headers:hsts_config")
      assertTrue(ttl > (86400L * 1000 - 60_000), "TTL should be ~1 day, got $ttl")
    } finally {
      redis.close()
    }
  }
}
