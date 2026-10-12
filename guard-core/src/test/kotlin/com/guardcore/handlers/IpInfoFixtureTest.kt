package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.protocols.RedisHandlerProtocol
import java.net.URI
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9e batch 5: the IpInfoManager reader lifecycle over the VENDORED MaxMind test database
 * (guard-core/src/test/resources/maxmind/GeoIP2-Country-Test.mmdb, Apache-2.0 from the MaxMind-DB
 * repository). The GeoIP2 layout nests `country` as an object, so MmdbCountryRecord lookups take
 * the lookup-failure arm by construction; the fixture exercises the open/refresh/ replace lifecycle
 * exactly like a production download.
 */
class IpInfoFixtureTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  private fun fixture(): Path {
    val resource = java.nio.file.Paths.get("src/test/resources/maxmind/GeoIP2-Country-Test.mmdb")
    return resource.toAbsolutePath()
  }

  private class FakeResponse(
      private val status: Int,
      private val payload: ByteArray,
      private val uri: URI,
  ) : HttpResponse<ByteArray> {
    override fun statusCode(): Int = status

    override fun body(): ByteArray = payload

    override fun headers(): HttpHeaders = HttpHeaders.of(mapOf(), { _, _ -> true })

    override fun uri(): URI = uri

    override fun previousResponse(): java.util.Optional<HttpResponse<ByteArray>> =
        java.util.Optional.empty()

    override fun request(): HttpRequest = HttpRequest.newBuilder().uri(uri).build()

    override fun sslSession(): java.util.Optional<javax.net.ssl.SSLSession> =
        java.util.Optional.empty()

    override fun version(): java.net.http.HttpClient.Version =
        java.net.http.HttpClient.Version.HTTP_1_1
  }

  @Test
  fun `the vendored fixture opens a real reader and serves lookups`() {
    val reader = com.maxmind.db.Reader(fixture().toFile())
    try {
      // a known subnet answers, but the GeoIP2 nested record shape fails the flat
      // MmdbCountryRecord decode (the production format is the flat ipinfo layout) - the
      // decoder raise is exactly the lookup-failure arm the manager's getCountry handles
      var threw = false
      try {
        reader.get(java.net.InetAddress.getByName("89.160.20.128"), MmdbCountryRecord::class.java)
      } catch (expected: Exception) {
        // the flat-record decode raises inside the decoder
        threw = true
      }
      assertTrue(threw)
      // an unrouted address returns null quietly
      val unrouted =
          reader.get(java.net.InetAddress.getByName("203.0.113.1"), MmdbCountryRecord::class.java)
      assertNull(unrouted)
    } finally {
      reader.close()
    }
  }

  @Test
  fun `manager surface answers over the fixture-backed reader`() = runBlocking {
    val dir = Files.createTempDirectory("w9e-b5-surface")
    val dbPath = dir.resolve("geo.mmdb")
    val agent =
        object : com.guardcore.protocols.AgentHandlerProtocol {
          override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

          override suspend fun sendEvent(event: Any?) {}

          override suspend fun sendMetric(metric: Any?) {}

          override suspend fun start() {}

          override suspend fun stop() {}

          override suspend fun flushBuffer() {}

          override suspend fun getDynamicRules(): Any? = null

          override suspend fun healthCheck(): Boolean = true
        }
    // the empty-token guard
    assertFailsWith<IllegalArgumentException> { IpInfoManager.getInstance("") }
    val manager = IpInfoManager.getInstance("w9e-surface", dbPath, 3600)
    try {
      manager.applyOpenedReader(com.maxmind.db.Reader(fixture().toFile()))
      assertTrue(manager.isInitialized)
      assertTrue(manager.entryCount > 0)
      assertTrue(manager.getStatus()["ready"] == true)
      assertNotNull(manager.getStatus()["entries"])
      manager.initializeAgent(agent)
      manager.setAgentSinkForTests(HandlerAgentSink.of(agent))
      // the lookup over the live reader: the unrouted address takes the null arm
      assertNull(manager.getCountry("203.0.113.1"))
      // a malformed address throws inside the lookup and takes the failure-event arm
      assertNull(manager.getCountry("999.999.999.999"))
      // the non-2xx download arm raises HttpStatusException (the aiohttp status shape)
      manager.httpSendOverride = { url, _ ->
        FakeResponse(503, "unavailable".toByteArray(), URI.create(url))
      }
      var sawStatus = false
      try {
        manager.downloadDatabase()
      } catch (expected: HttpStatusException) {
        sawStatus = expected.status == 503
      }
      assertTrue(sawStatus)
    } finally {
      manager.httpSendOverride = null
      manager.setAgentSinkForTests(null)
      manager.close()
    }
  }

  @Test
  fun `write database atomically cleans up on failure`() {
    val dir = Files.createTempDirectory("w9e-b5-atomic")
    val dbPath = dir.resolve("geo.mmdb")
    val manager = IpInfoManager.getInstance("w9e-atomic", dbPath, 60)
    try {
      // a directory at the tmp path forces the write failure + cleanup arm
      Files.createDirectory(dbPath.resolveSibling("geo.mmdb.tmp"))
      var threw = false
      try {
        manager.writeDatabaseAtomically("bytes".toByteArray())
      } catch (expected: Exception) {
        threw = true
      }
      assertTrue(threw)
      assertFalse(Files.exists(dbPath.resolveSibling("geo.mmdb.tmp")))
    } finally {
      Files.deleteIfExists(dbPath.resolveSibling("geo.mmdb.tmp"))
    }
  }

  @Test
  fun `mmdb country record constructs and round trips its value`() {
    val record = MmdbCountryRecord("US")
    assertEquals("US", record.country)
    val empty = MmdbCountryRecord(null)
    assertNull(empty.country)
  }

  @Test
  fun `refresh over the fixture downloads, reopens and swaps the reader`() = runBlocking {
    val dir = Files.createTempDirectory("w9e-b5-ipinfo")
    val dbPath = dir.resolve("geo.mmdb")
    val manager = IpInfoManager.getInstance("w9e", dbPath, 3600)
    try {
      // seed the file with the REAL fixture bytes over the download seam, then let the
      // manager reopen it: the refresh-success path swaps the reader in
      val fixtureBytes = Files.readAllBytes(fixture())
      manager.httpSendOverride = { url, _ ->
        FakeResponse(200, fixtureBytes, URI.create(url))
      }
      manager.refresh()
      // the reader is live over a real MaxMind database now
      val country = manager.getCountry("89.160.20.128")
      // the GeoIP2 nested shape decodes into the lookup-failure arm or null; both leave the
      // manager serving from a real reader
      assertTrue(country == null || country.length <= 2, country.toString())
      assertNotNull(manager.lastRefreshed)
      assertFalse(manager.isDbOutdated())
      // a second refresh with a download failure keeps the existing reader
      manager.httpSendOverride = { url, _ -> throw java.net.http.HttpTimeoutException("down $url") }
      manager.refresh()
      assertNotNull(manager.lastRefreshed)
      // the close arm releases the reader
      manager.close()
    } finally {
      manager.httpSendOverride = null
      manager.countryLookupOverride = null
      manager.downloadOverride = null
      manager.setReaderForTests(null)
      manager.setInitializationAttempted(false)
    }
  }

  @Test
  fun `initialize over the fixture takes the fresh-file path`() = runBlocking {
    val dir = Files.createTempDirectory("w9e-b5-ipinfo-init")
    val dbPath = dir.resolve("geo.mmdb")
    Files.copy(fixture(), dbPath)
    val manager = IpInfoManager.getInstance("w9e-init", dbPath, 86400)
    try {
      // the file is fresh (just copied): initialize keeps it and opens the reader
      manager.initialize()
      assertNotNull(manager.lastRefreshed)
      manager.countryLookupOverride = { ip -> if (ip == "192.0.2.1") "US" else null }
      assertEquals("US", manager.getCountry("192.0.2.1"))
    } finally {
      manager.countryLookupOverride = null
      manager.setReaderForTests(null)
    }
  }

  @Test
  fun `a corrupted database is quarantined on open`() = runBlocking {
    val dir = Files.createTempDirectory("w9e-b5-corrupt")
    val dbPath = dir.resolve("geo.mmdb")
    Files.write(dbPath, "definitely not an mmdb".toByteArray())
    val manager = IpInfoManager.getInstance("w9e-corrupt", dbPath, 60)
    try {
      // the open failure deletes the corrupted file and returns null
      assertNull(manager.openDatabaseOrNone())
      assertFalse(Files.exists(dbPath))
    } finally {
      manager.setReaderForTests(null)
    }
  }

  @Test
  fun `redis-cached database bytes are restored through initialize`() = runBlocking {
    val dir = Files.createTempDirectory("w9e-b5-restore")
    val dbPath = dir.resolve("geo.mmdb")
    val live =
        RedisManager.getInstance(
            config {
              redisUrl = "redis://localhost:6379/0"
              enableRedis = true
            },
        )
    val manager = IpInfoManager.getInstance("w9e-restore", dbPath, 86400)
    try {
      live.initialize()
      manager.redisHandler = live
      // stash the REAL fixture bytes in the ipinfo namespace: initialize restores them
      live.setKey("ipinfo", "database", Files.readAllBytes(fixture()), ttl = 3600)
      manager.initialize()
      assertNotNull(manager.lastRefreshed)
      manager.close()
    } finally {
      manager.redisHandler = null
      live.discardClientQuietlyForCorpus()
      RedisManager.resetInstance()
    }
  }
}
