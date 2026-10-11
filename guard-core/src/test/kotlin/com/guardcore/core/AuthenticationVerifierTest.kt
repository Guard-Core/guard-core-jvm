package com.guardcore.core

import com.guardcore.config.AuthVerifier
import com.guardcore.core.checks.implementations.AuthenticationCheck
import com.guardcore.decorators.RouteAuthVerifier
import com.guardcore.decorators.RouteConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_authentication_verifier.py: bearer/api-key/presence-only route
 * authentication, route-vs-global verifier resolution, fail-closed halves and the passive-mode
 * halves. The async-verifier-await half is N/A by construction: the JVM verifier SAMs are
 * synchronous (the facade bridges async sources before the check runs).
 */
class AuthenticationVerifierTest {
  private fun route(
      authRequired: String? = null,
      authVerifier: RouteAuthVerifier? = null,
      apiKeyRequired: Boolean = false,
      apiKeyHeader: String? = null,
      apiKeyVerifier: RouteAuthVerifier? = null,
      presenceScheme: String? = null,
  ): RouteConfig {
    val rc = RouteConfig()
    rc.authRequired = authRequired
    rc.authVerifier = authVerifier
    rc.apiKeyRequired = apiKeyRequired
    rc.apiKeyHeader = apiKeyHeader
    rc.apiKeyVerifier = apiKeyVerifier
    rc.authorizationHeaderRequired = presenceScheme
    return rc
  }

  private fun request(
      headers: Map<String, String>,
      rc: RouteConfig,
  ): TestRequest {
    val req = TestRequest(headers = headers)
    req.state.setAttr("route_config", rc)
    return req
  }

  private fun verifierReturning(principal: Any?): RouteAuthVerifier = RouteAuthVerifier { _, _ ->
    principal
  }

  @Test
  fun arbitraryBearerRejectedWithoutVerifier() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val result =
          check.check(request(mapOf("authorization" to "Bearer attacker-value"), route("bearer")))
      assertTrue(result != null, "a bearer request without a verifier must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun verifierDenialRejected() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val result =
          check.check(
              request(
                  mapOf("authorization" to "Bearer creds"),
                  route("bearer", verifierReturning(null)),
              ),
          )
      assertTrue(result != null, "a verifier denial must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun verifierRaisesExceptionFailClosed() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val failing = RouteAuthVerifier { _, _ -> throw RuntimeException("jwt decode failed") }
      val result =
          check.check(request(mapOf("authorization" to "Bearer token"), route("bearer", failing)))
      assertTrue(result != null, "a throwing verifier must fail closed")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun verifierSuccessAllowsAndStashesPrincipal() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val principal = linkedMapOf("user" to "alice")
      val req =
          request(
              mapOf("authorization" to "Bearer good-token"),
              route("bearer", verifierReturning(principal)),
          )
      assertNull(check.check(req))
      assertEquals(principal, req.state.getAttr("auth_principal"))
    }
  }

  @Test
  fun wrongSchemeRejected() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val result =
          check.check(
              request(
                  mapOf("authorization" to "Basic creds"),
                  route("bearer", verifierReturning(linkedMapOf("user" to "x"))),
              ),
          )
      assertTrue(result != null, "a wrong scheme must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun missingAuthorizationRejected() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val result =
          check.check(
              request(
                  emptyMap(),
                  route("bearer", verifierReturning(linkedMapOf("user" to "x"))),
              ),
          )
      assertTrue(result != null, "a missing authorization header must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun globalVerifierUsedWhenRouteHasNone() {
    coreRunTest {
      val principal = linkedMapOf("user" to "bob")
      // The global verifier rides the config seam (python: SecurityConfig(auth_verifier=...)).
      val config = coreTestConfig { authVerifier = AuthVerifier { _, _ -> principal } }
      val check = AuthenticationCheck(TestMiddleware(config))
      val req = request(mapOf("authorization" to "Bearer token"), route("bearer"))
      assertNull(check.check(req))
      assertEquals(principal, req.state.getAttr("auth_principal"))
    }
  }

  @Test
  fun routeVerifierOverridesGlobal() {
    coreRunTest {
      val routePrincipal = linkedMapOf("user" to "route")
      val globalPrincipal = linkedMapOf("user" to "global")
      val config = coreTestConfig { authVerifier = AuthVerifier { _, _ -> globalPrincipal } }
      val check = AuthenticationCheck(TestMiddleware(config))
      val req =
          request(
              mapOf("authorization" to "Bearer token"),
              route("bearer", verifierReturning(routePrincipal)),
          )
      assertNull(check.check(req))
      assertEquals(routePrincipal, req.state.getAttr("auth_principal"))
    }
  }

  @Test
  fun apiKeyWithoutVerifierFailClosed() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val rc = route(apiKeyRequired = true, apiKeyHeader = "X-API-Key")
      rc.requiredHeaders["X-API-Key"] = "required"
      val result = check.check(request(mapOf("X-API-Key" to "any-value"), rc))
      assertTrue(result != null, "an api key without a verifier must fail closed")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun apiKeyMissingRejected() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val rc =
          route(
              apiKeyRequired = true,
              apiKeyHeader = "X-API-Key",
              apiKeyVerifier = verifierReturning(linkedMapOf("user" to "x")),
          )
      val result = check.check(request(emptyMap(), rc))
      assertTrue(result != null, "a missing api key must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun apiKeyVerifierDenial() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val rc =
          route(
              apiKeyRequired = true,
              apiKeyHeader = "X-API-Key",
              apiKeyVerifier = verifierReturning(null),
          )
      val result = check.check(request(mapOf("X-API-Key" to "bad"), rc))
      assertTrue(result != null, "an api-key verifier denial must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun apiKeyVerifierSuccess() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val principal = linkedMapOf("user" to "dave")
      val rc =
          route(
              apiKeyRequired = true,
              apiKeyHeader = "X-API-Key",
              apiKeyVerifier = verifierReturning(principal),
          )
      val req = request(mapOf("X-API-Key" to "good"), rc)
      assertNull(check.check(req))
      assertEquals(principal, req.state.getAttr("auth_principal"))
    }
  }

  @Test
  fun presenceOnlyAllowsAnyBearerNoPrincipal() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val req =
          request(mapOf("authorization" to "Bearer anything"), route(presenceScheme = "bearer"))
      assertNull(check.check(req))
      assertNull(req.state.getAttr("auth_principal"))
    }
  }

  @Test
  fun presenceOnlyMissingHeaderRejected() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val result = check.check(request(emptyMap(), route(presenceScheme = "bearer")))
      assertTrue(result != null, "presence-only with a missing header must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun presenceOnlyWrongSchemeRejected() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig()))
      val result =
          check.check(
              request(mapOf("authorization" to "Basic creds"), route(presenceScheme = "bearer")),
          )
      assertTrue(result != null, "presence-only with a wrong scheme must be rejected")
      assertEquals(401, result!!.statusCode)
    }
  }

  @Test
  fun passiveModeFailClosedDoesNotBlock() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig { passiveMode = true }))
      val result =
          check.check(request(mapOf("authorization" to "Bearer attacker-value"), route("bearer")))
      assertNull(result, "passive mode must not block a fail-closed case")
    }
  }

  @Test
  fun passiveModeDenialDoesNotBlock() {
    coreRunTest {
      val check = AuthenticationCheck(TestMiddleware(coreTestConfig { passiveMode = true }))
      val result =
          check.check(
              request(
                  mapOf("authorization" to "Bearer creds"),
                  route("bearer", verifierReturning(null)),
              ),
          )
      assertNull(result, "passive mode must not block a verifier denial")
    }
  }
}
