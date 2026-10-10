package com.guardcore.util

import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RequestState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** Shared fake GuardRequest mirroring tests/conftest.py MockGuardRequest. */
class FakeRequest(
    override val urlPath: String = "/",
    override val clientHost: String? = null,
    override val headers: Map<String, String> = emptyMap(),
    override val method: String = "GET",
    private val stateBag: MutableMap<String, Any?> = mutableMapOf(),
) : GuardRequest {
  override val urlScheme: String = "http"
  override val urlFull: String = "http://testserver$urlPath"
  override val queryParams: Map<String, String> = emptyMap()

  override fun urlReplaceScheme(scheme: String): String = urlFull.replaceFirst("http", scheme)

  override suspend fun body(): ByteArray = ByteArray(0)

  override val state: RequestState =
      object : RequestState {
        override fun getAttr(name: String): Any? = stateBag[name]

        override fun setAttr(name: String, value: Any?) {
          stateBag[name] = value
        }
      }

  override val scope: Map<String, Any?> = emptyMap()
}

/** Ports of tests/test_public_redaction_helpers.py and the redaction gates. */
class RedactionTest {
  private val secret = "PLANTED-SECRET-VALUE"

  @Test
  fun testPairSecretInReasonTextRedactedWithDefaults() {
    val redacted =
        RequestLogging.redactBlobForDisplay("blocked: token=$secret at login", null, null)
    assertEquals("blocked: token=[REDACTED]", redacted)
  }

  @Test
  fun testJsonContextSecretRedactedWithDefaults() {
    val context = "{\"password\": \"$secret\", \"user\": \"alice\"}"
    val redacted = RequestLogging.redactBlobForDisplay(context, null, null)
    assertTrue(secret !in redacted)
    assertTrue("alice" in redacted)
  }

  @Test
  fun testExtraHeaderNameExtendsDefaultSet() {
    val text = "x-auth-token=$secret"
    assertTrue(secret in RequestLogging.redactBlobForDisplay(text, null, null))
    assertTrue(
        secret !in RequestLogging.redactBlobForDisplay(text, null, null, setOf("x-auth-token")),
    )
  }

  @Test
  fun testUserAgentWithoutSecretUnchanged() {
    val userAgent = "Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0"
    assertEquals(userAgent, RequestLogging.redactBlobForDisplay(userAgent, null, null))
  }

  @Test
  fun testEndpointQuerySecretRedactedWithDefaults() {
    val redacted =
        RequestLogging.redactUrlForDisplay("/login?access_token=$secret&next=/home", null)
    assertTrue(secret !in redacted)
    assertTrue("next=/home" in redacted)
  }

  @Test
  fun testEndpointUserinfoPasswordRedacted() {
    val redacted = RequestLogging.redactUrlForDisplay("https://svc:$secret@api.internal/v1", null)
    assertTrue(secret !in redacted)
    assertTrue("svc:[REDACTED]@api.internal/v1" in redacted)
  }

  @Test
  fun testEndpointWithoutSecretUnchanged() {
    assertEquals("/health", RequestLogging.redactUrlForDisplay("/health", null))
  }

  @Test
  fun testXmlElementsRedacted() {
    val redacted =
        RequestLogging.redactXmlElements(
            "<password>$secret</password><ok>fine</ok>",
            setOf("password"),
        )
    assertEquals("<password>[REDACTED]</password><ok>fine</ok>", redacted)
  }

  @Test
  fun testSensitivePathSegmentRedaction() {
    // Path pairs: /api/token=$secret/x
    val redacted = RequestLogging.redactUrlForDisplay("/api/token=$secret/x", null)
    assertTrue(secret !in redacted)
    assertTrue(redacted.startsWith("/api/token="))
  }

  @Test
  fun testHeaderRedactionByDefaultSet() {
    val headers =
        RequestLogging.redactSensitiveHeaders(
            linkedMapOf("Authorization" to "Bearer abc", "X-Custom" to "value"),
            null,
        )
    assertEquals("[REDACTED]", headers["Authorization"])
    assertEquals("value", headers["X-Custom"])
  }

  @Test
  fun testPercentEncodedJsonInQueryRedacted() {
    val json = "%7B%22api_key%22%3A%22$secret%22%7D"
    val redacted = RequestLogging.redactUrlForDisplay("/x?data=$json", null)
    assertTrue(secret !in redacted, redacted)
  }

  @Test
  fun testUrlControlEscape() {
    // _escape_url_unsafe_controls turns \t \r \n into percent escapes.
    val redacted = RequestLogging.redactUrlForDisplay("/a\tb", null)
    assertTrue("\t" !in redacted)
  }
}

/** Ports of tests/test_utils/test_proxy_handling.py (core cases). */
class IpExtractionTest {
  @Test
  fun testExtractClientIpCanonicalizesViaConnectingHost() {
    runBlocking {
      for ((raw, canonical) in
          mapOf(
              "2001:db8::1" to "2001:db8::1",
              "2001:0db8::1" to "2001:db8::1",
              "2001:DB8::1" to "2001:db8::1",
              "2001:db8:0:0:0:0:0:1" to "2001:db8::1",
              "::ffff:1.2.3.4" to "1.2.3.4",
              "1.2.3.4" to "1.2.3.4",
          )) {
        val config = com.guardcore.config.SecurityConfigBuilder().build()
        val resolved = IpExtraction.extractClientIp(FakeRequest(clientHost = raw), config)
        assertEquals(canonical, resolved, "raw=$raw")
      }
    }
  }

  @Test
  fun testExtractClientIpViaForwardedHeaderWithTrustedProxy() {
    runBlocking {
      for ((raw, canonical) in
          mapOf(
              "2001:db8::1" to "2001:db8::1",
              "::ffff:1.2.3.4" to "1.2.3.4",
              "1.2.3.4" to "1.2.3.4",
          )) {
        val config =
            com.guardcore.config
                .SecurityConfigBuilder()
                .apply {
                  trustedProxies = listOf("127.0.0.1")
                  trustedProxyDepth = 1
                }
                .build()
        val resolved =
            IpExtraction.extractClientIp(
                FakeRequest(headers = mapOf("X-Forwarded-For" to raw), clientHost = "127.0.0.1"),
                config,
            )
        assertEquals(canonical, resolved, "raw=$raw")
      }
    }
  }

  @Test
  fun testNoTrustedProxiesIgnoresForwardedFor() {
    runBlocking {
      val config = com.guardcore.config.SecurityConfigBuilder().build()
      val resolved =
          IpExtraction.extractClientIp(
              FakeRequest(
                  headers = mapOf("X-Forwarded-For" to "9.9.9.9"),
                  clientHost = "1.2.3.4",
              ),
              config,
          )
      assertEquals("1.2.3.4", resolved)
    }
  }

  @Test
  fun testUntrustedProxyFallsBackToConnectingIp() {
    runBlocking {
      val config =
          com.guardcore.config
              .SecurityConfigBuilder()
              .apply {
                trustedProxies = listOf("10.0.0.1")
                trustedProxyDepth = 1
              }
              .build()
      val resolved =
          IpExtraction.extractClientIp(
              FakeRequest(
                  headers = mapOf("X-Forwarded-For" to "9.9.9.9"),
                  clientHost = "1.2.3.4",
              ),
              config,
          )
      assertEquals("1.2.3.4", resolved)
    }
  }

  @Test
  fun testDepthSelectsFromEndOfChain() {
    runBlocking {
      val config =
          com.guardcore.config
              .SecurityConfigBuilder()
              .apply {
                trustedProxies = listOf("127.0.0.1")
                trustedProxyDepth = 2
              }
              .build()
      val resolved =
          IpExtraction.extractClientIp(
              FakeRequest(
                  headers = mapOf("X-Forwarded-For" to "5.5.5.5, 127.0.0.1"),
                  clientHost = "127.0.0.1",
              ),
              config,
          )
      assertEquals("5.5.5.5", resolved)
    }
  }

  @Test
  fun testUnknownClientWithoutHost() {
    runBlocking {
      val config = com.guardcore.config.SecurityConfigBuilder().build()
      val resolved = IpExtraction.extractClientIp(FakeRequest(), config)
      assertEquals(IpExtraction.UNKNOWN_CLIENT_IDENTITY, resolved)
    }
  }

  @Test
  fun testDisplayForwardedChainRedactsNonAddresses() {
    assertEquals(
        "1.2.3.4,[REDACTED]",
        IpExtraction.displayForwardedChain("1.2.3.4, not-an-ip"),
    )
  }
}
