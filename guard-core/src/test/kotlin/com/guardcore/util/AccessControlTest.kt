package com.guardcore.util

import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.RedisHandlerProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** Config-facing geo handler fake used through the W3 seam. */
class FakeGeoForConfig(private val country: String?) : GeoIPHandler {
  override val isInitialized: Boolean = true

  override suspend fun initialize() {}

  override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

  override suspend fun initializeAgent(
      agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
  ) {}

  override fun getCountry(ip: String): String? = country

  override suspend fun refresh() {}

  override fun close() {}
}

/** Ports of tests/test_utils/test_request_checks.py (access control core). */
class AccessControlTest {
  init {
    // Register the W3 geo-handler seam so country-rule configs construct,
    // mirroring the always-installed maxminddb extra on Python.
    com.guardcore.config.ConfigSeams.geoIpHandlerFactory = { _, _, _ -> FakeGeoForConfig("ZZ") }
  }

  private fun config(
      whitelist: List<String>? = null,
      blacklist: List<String> = emptyList(),
      whitelistCountries: Set<String> = emptySet(),
      blockedCountries: Set<String> = emptySet(),
  ): com.guardcore.config.SecurityConfig =
      com.guardcore.config
          .SecurityConfigBuilder()
          .apply {
            this.whitelist = whitelist
            this.blacklist = blacklist
            this.whitelistCountries = whitelistCountries
            this.blockedCountries = blockedCountries
            if (whitelistCountries.isNotEmpty() || blockedCountries.isNotEmpty()) {
              ipinfoToken = "test-token"
            }
          }
          .build()

  private class FakeGeo(private val country: String?) : GeoIPHandler {
    override val isInitialized: Boolean = true

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override fun getCountry(ip: String): String? = country

    override suspend fun refresh() {}

    override fun close() {}
  }

  @Test
  fun testWhitelistBlocksUnlistedIp() {
    runBlocking {
      val result = AccessControl.checkIpAccess("8.8.8.8", config(whitelist = listOf("10.0.0.0/8")))
      assertFalse(result.allowed)
      assertEquals(
          "IP 8.8.8.8 not in global allowlist/blocklist",
          result.reason,
      )
    }
  }

  @Test
  fun testWhitelistAllowsListedIpAndSkipsCountries() {
    runBlocking {
      val result =
          AccessControl.checkIpAccess(
              "10.1.2.3",
              config(whitelist = listOf("10.0.0.0/8"), blockedCountries = setOf("CN")),
              geoIpHandler = FakeGeo("CN"),
          )
      assertTrue(result.allowed)
    }
  }

  @Test
  fun testBlacklistBlocksListedIp() {
    runBlocking {
      val result =
          AccessControl.checkIpAccess("192.168.1.1", config(blacklist = listOf("192.168.1.0/24")))
      assertFalse(result.allowed)
    }
  }

  @Test
  fun testBlacklistAllowsOtherIps() {
    runBlocking {
      val result =
          AccessControl.checkIpAccess("192.168.2.1", config(blacklist = listOf("192.168.1.0/24")))
      assertTrue(result.allowed)
    }
  }

  @Test
  fun testCountryBlocking() {
    runBlocking {
      val result =
          AccessControl.checkIpAccess(
              "8.8.8.8",
              config(blockedCountries = setOf("US")),
              geoIpHandler = FakeGeo("US"),
          )
      assertFalse(result.allowed)
      assertEquals("IP from blocked country: US", result.reason)
    }
  }

  @Test
  fun testCountryAllowlistBlocksUnresolved() {
    runBlocking {
      // A non-empty whitelist_countries blocks an unresolved country.
      val result =
          AccessControl.checkIpAccess(
              "8.8.8.8",
              config(whitelistCountries = setOf("DE")),
              geoIpHandler = FakeGeo(null),
          )
      assertFalse(result.allowed)
    }
  }

  @Test
  fun testLoopbackExemptFromCountryRules() {
    runBlocking {
      val result =
          AccessControl.checkIpAccess(
              "127.0.0.1",
              config(blockedCountries = setOf("CN")),
              geoIpHandler = FakeGeo("CN"),
          )
      assertTrue(result.allowed)
    }
  }

  @Test
  fun testUnknownIdentityBlockedOnlyByWhitelists() {
    runBlocking {
      val blocked =
          AccessControl.checkIpAccess(
              IpExtraction.UNKNOWN_CLIENT_IDENTITY,
              config(whitelist = listOf("10.0.0.0/8")),
          )
      assertFalse(blocked.allowed)
      val allowed = AccessControl.checkIpAccess(IpExtraction.UNKNOWN_CLIENT_IDENTITY, config())
      assertTrue(allowed.allowed)
    }
  }

  @Test
  fun testInvalidIpBlocked() {
    runBlocking {
      val result = AccessControl.checkIpAccess("not-an-ip", config())
      assertFalse(result.allowed)
    }
  }

  @Test
  fun testUserAgentAllowedWithoutEngineSeam() {
    runBlocking {
      // With the W2 matcher unregistered, no UA is blocked by patterns.
      assertTrue(AccessControl.isUserAgentAllowed("evil-bot", config()))
    }
  }
}

class MiscUtilTest {
  @Test
  fun testLruPopOrCreateEvictsOldest() {
    // lru_store.py:7-16: pop-or-create; the caller stores the new value.
    val store = linkedMapOf("a" to 1, "b" to 2)
    assertEquals(1, LruStore.lruPopOrCreate(store, "a", 2) { -1 })
    assertEquals(setOf("b"), store.keys)
    // At capacity: the oldest entry ("b") is evicted before creating.
    store["c"] = 3
    assertEquals(9, LruStore.lruPopOrCreate(store, "d", 2) { 9 })
    assertEquals(setOf("c"), store.keys)
  }

  @Test
  fun testIdentityHash() {
    // tests/test_utils/test_identity_hash.py: sha256 of the utf-8 value.
    val expected =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest("hello".toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    assertEquals(expected, IdentityHash.hashIdentitySegment("hello"))
  }

  @Test
  fun testNormalizeUrlPath() {
    // path_matching.py semantics.
    assertEquals("/a/b", PathMatching.normalizeUrlPath("/a/b"))
    assertEquals("/b", PathMatching.normalizeUrlPath("/a/../b"))
    assertEquals("/a/b", PathMatching.normalizeUrlPath("/a/./b//"))
    assertEquals("/b", PathMatching.normalizeUrlPath("/a%2F..%2Fb")) // decodes then collapses
    assertEquals(null, PathMatching.normalizeUrlPath("/%ff")) // valid run, invalid utf-8
    assertEquals("/x", PathMatching.normalizeUrlPath("/%78"))
    assertEquals("/", PathMatching.normalizeUrlPath("/"))
  }

  @Test
  fun testScanBudgetDepthCap() {
    assertEquals(32, DetectionScanContext.jsonDepthCapValue())
    DetectionScanContext.withScanBudget(512, 8, 65536, 16) {
      assertEquals(8, DetectionScanContext.jsonDepthCapValue())
    }
    assertEquals(32, DetectionScanContext.jsonDepthCapValue())
  }

  @Test
  fun testParseContentLength() {
    assertEquals(42, BodyReader.parseContentLength("42"))
    assertEquals(null, BodyReader.parseContentLength("-1"))
    assertEquals(null, BodyReader.parseContentLength("0"))
    assertEquals(null, BodyReader.parseContentLength("12x"))
    assertEquals(null, BodyReader.parseContentLength(""))
  }
}
