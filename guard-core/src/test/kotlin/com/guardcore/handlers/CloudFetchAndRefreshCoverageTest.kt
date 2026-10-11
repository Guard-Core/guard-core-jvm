package com.guardcore.handlers

import com.guardcore.util.py.IpNetwork
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * Ports of tests/test_cloud_ips: the fetcher parse arms over mocked transports (the aiohttp
 * session-mock analog is the httpGetOverride seam), _fetch_provider_ranges dispatch, and the
 * non-blocking refresh family (test_nonblocking_refresh.py).
 */
class CloudFetchersTest {
  private fun withHttp(handler: suspend (String) -> Pair<Int, String>, block: suspend () -> Unit) {
    val previous = CloudFetchers.httpGetOverride
    CloudFetchers.httpGetOverride = handler
    try {
      runBlocking { block() }
    } finally {
      CloudFetchers.httpGetOverride = previous
    }
  }

  private val awsUrl = "https://ip-ranges.amazonaws.com/ip-ranges.json"

  /** test_cloud_ips.py:77 AWS payload parse with the AMAZON service filter + regions. */
  @Test
  fun testFetchAwsIpRangesParsesAmazonPrefixes() {
    withHttp(
        { url ->
          assertEquals(awsUrl, url)
          200 to
              """{"prefixes": [
        {"ip_prefix": "52.94.76.0/22", "region": "us-east-1", "service": "AMAZON"},
        {"ip_prefix": "52.119.128.0/17", "region": "eu-west-1", "service": "CLOUDFRONT"},
        {"ip_prefix": "13.248.128.0/17", "region": "us-west-2", "service": "AMAZON"}
      ]}"""
        },
    ) {
      val (networks, regions) = CloudFetchers.fetchAwsIpRanges()
      assertEquals(2, networks.size)
      assertEquals("us-west-2", regions["13.248.128.0/17"])
    }
  }

  /** Malformed entries are skipped, not fatal (the continue arms). */
  @Test
  fun testFetchAwsIpRangesSkipsIncompleteEntries() {
    withHttp(
        { _ ->
          200 to
              """{"prefixes": [
        {"region": "us-east-1", "service": "AMAZON"},
        {"ip_prefix": "1.2.3.0/24", "service": "AMAZON"}
      ]}"""
        },
    ) {
      val (networks, _) = CloudFetchers.fetchAwsIpRanges()
      assertEquals(1, networks.size)
    }
  }

  /** The catch arm: transport failure yields the empty pair (cloud_handler failure-path). */
  @Test
  fun testFetchAwsIpRangesFailureYieldsEmpty() {
    withHttp({ _ -> throw java.net.ConnectException("down") }) {
      val (networks, regions) = CloudFetchers.fetchAwsIpRanges()
      assertTrue(networks.isEmpty())
      assertTrue(regions.isEmpty())
    }
  }

  @Test
  fun testFetchAwsIpRangesHttpErrorYieldsEmpty() {
    withHttp({ _ -> 500 to "oops" }) {
      val (networks, _) = CloudFetchers.fetchAwsIpRanges()
      assertTrue(networks.isEmpty())
    }
  }

  /** test_cloud_ips.py GCP: ipv4Prefix and ipv6Prefix with scopes. */
  @Test
  fun testFetchGcpIpRangesParsesBothFamilies() {
    withHttp(
        { _ ->
          200 to
              """{"prefixes": [
        {"ipv4Prefix": "34.0.0.0/8", "scope": "us-east1"},
        {"ipv6Prefix": "2600:1900::/28", "scope": "europe-west1"},
        {"scope": "no-prefix"}
      ]}"""
        },
    ) {
      val (networks, regions) = CloudFetchers.fetchGcpIpRanges()
      assertEquals(2, networks.size)
      assertEquals("us-east1", regions["34.0.0.0/8"])
      assertEquals("europe-west1", regions["2600:1900::/28"])
    }
  }

  @Test
  fun testFetchGcpIpRangesFailureYieldsEmpty() {
    withHttp({ _ -> 403 to "denied" }) {
      val (networks, _) = CloudFetchers.fetchGcpIpRanges()
      assertTrue(networks.isEmpty())
    }
  }

  /** _fetch_csv_prefix_networks: comments, blanks and unparsable lines skipped. */
  @Test
  fun testFetchDigitalOceanIpRangesParsesCsv() {
    withHttp(
        { _ ->
          200 to "# header comment\n\n10.0.0.0/8,us-east1\nnot-a-prefix,xx\n192.168.1.0/24,eu1\n"
        },
    ) {
      val networks = CloudFetchers.fetchDigitalOceanIpRanges()
      assertEquals(2, networks.size)
    }
  }

  @Test
  fun testFetchLinodeIpRangesParsesCsv() {
    withHttp({ _ -> 200 to "# comments\n45.79.0.0/16,us-east\n" }) {
      val networks = CloudFetchers.fetchLinodeIpRanges()
      assertEquals(1, networks.size)
    }
  }

  @Test
  fun testFetchDigitalOceanFailureYieldsEmpty() {
    withHttp({ _ -> 500 to "x" }) {
      assertTrue(CloudFetchers.fetchDigitalOceanIpRanges().isEmpty())
    }
  }

  /** Vultr: subnets json with unparsable entries skipped. */
  @Test
  fun testFetchVultrIpRangesParsesSubnets() {
    withHttp(
        { _ ->
          200 to """{"subnets": [{"ip_prefix": "45.63.0.0/16"}, {"ip_prefix": "bogus"}, {}]}"""
        },
    ) {
      val networks = CloudFetchers.fetchVultrIpRanges()
      assertEquals(1, networks.size)
    }
  }

  @Test
  fun testFetchVultrFailureYieldsEmpty() {
    withHttp({ _ -> throw java.io.IOException("nope") }) {
      assertTrue(CloudFetchers.fetchVultrIpRanges().isEmpty())
    }
  }

  /** _fetch_provider_ranges: pair-normalizing for AWS/GCP, set-normalizing for the CSV ones. */
  @Test
  fun testFetchProviderRangesDispatchAndNormalization() {
    withHttp(
        { _ ->
          200 to
              """{"prefixes": [{"ip_prefix": "1.2.3.0/24", "region": "r1", "service": "AMAZON"}]}"""
        },
    ) {
      val (awsRanges, awsRegions) = fetchProviderRanges("AWS")
      assertEquals(1, awsRanges.size)
      assertEquals("r1", awsRegions["1.2.3.0/24"])
      val (doRanges, doRegions) = fetchProviderRanges("DigitalOcean")
      assertEquals(0, doRanges.size)
      assertTrue(doRegions.isEmpty())
    }
  }

  @Test
  fun testFetchProviderRangesUnknownProviderThrows() {
    runBlocking {
      val error =
          try {
            fetchProviderRanges("Rackspace")
            null
          } catch (e: IllegalArgumentException) {
            e
          }
      assertTrue(error != null)
      assertTrue(error!!.message!!.contains("unknown cloud provider"), error.message)
    }
  }
}

class CloudAzureFetchTest {
  private fun withHttp(handler: suspend (String) -> Pair<Int, String>, block: suspend () -> Unit) {
    val previous = CloudAzureFetch.httpGetOverride
    CloudAzureFetch.httpGetOverride = handler
    try {
      runBlocking { block() }
    } finally {
      CloudAzureFetch.httpGetOverride = previous
    }
  }

  private val serviceTagsJson =
      """{"changeNumber": 1, "cloud": "Public", "values": [
    {"name": "AzureCloud", "id": "AzureCloud", "properties": {
      "changeNumber": 1, "region": "", "platform": "Azure",
      "systemService": "", "addressPrefixes": ["20.0.0.0/8", "2603:1000::/28"]
    }}
  ]}"""

  private val pageHtml =
      "<html>Click <a href='https://download.microsoft.com/download/7/1/6/" +
          "ServiceTags_Public_20260101.json'>here</a></html>"

  /** The discovery chain: page scrape -> trusted URL extraction -> newest ServiceTags JSON. */
  @Test
  fun testFetchAzureIpRangesDiscoveryChain() {
    withHttp(
        { url ->
          if (url.startsWith("https://www.microsoft.com/")) 200 to pageHtml
          else 200 to serviceTagsJson
        },
    ) {
      val networks = CloudAzureFetch.fetchAzureIpRanges()
      assertEquals(2, networks.size)
    }
  }

  /** Redirect refusal: a 3xx download answer aborts the chain. */
  @Test
  fun testDownloadAzureServiceTagsRejectsRedirect() {
    withHttp({ _ -> 302 to "" }) {
      val error =
          try {
            CloudAzureFetch.downloadAzureServiceTags("https://download.microsoft.com/x.json")
            null
          } catch (e: IllegalArgumentException) {
            e
          }
      assertTrue(error != null)
      assertTrue(error!!.message!!.contains("refusing to follow redirects"), error.message)
    }
  }

  /** HTTP error status aborts the chain. */
  @Test
  fun testDownloadAzureServiceTagsHttpError() {
    withHttp({ _ -> 404 to "gone" }) {
      val error =
          try {
            CloudAzureFetch.downloadAzureServiceTags("https://download.microsoft.com/x.json")
            null
          } catch (e: IllegalStateException) {
            e
          }
      assertTrue(error != null)
      assertTrue(error!!.message!!.contains("HTTP 404"), error.message)
    }
  }

  /** Transport errors retry up to the attempt cap, then propagate. */
  @Test
  fun testDownloadAzureServiceTagsRetriesThenPropagates() {
    var calls = 0
    withHttp(
        { _ ->
          calls++
          throw java.net.ConnectException("down")
        },
    ) {
      val error =
          try {
            CloudAzureFetch.downloadAzureServiceTags("https://download.microsoft.com/x.json")
            null
          } catch (e: java.net.ConnectException) {
            e
          }
      assertTrue(error != null)
      assertEquals(CloudAzureFetch.AZURE_DOWNLOAD_MAX_ATTEMPTS, calls)
    }
  }

  @Test
  fun testIsTrustedAzureDownloadUrl() {
    assertTrue(
        CloudAzureFetch.isTrustedAzureDownloadUrl(
            "https://download.microsoft.com/x/ServiceTags.json",
        ),
    )
    assertEquals(
        false,
        CloudAzureFetch.isTrustedAzureDownloadUrl("http://download.microsoft.com/x"),
    )
    assertEquals(false, CloudAzureFetch.isTrustedAzureDownloadUrl("https://evil.example/x.json"))
    assertEquals(false, CloudAzureFetch.isTrustedAzureDownloadUrl("::::"))
  }

  @Test
  fun testParseServiceTagsDate() {
    assertEquals(
        java.time.LocalDate.of(2026, 1, 1),
        CloudAzureFetch.parseServiceTagsDate(
            "https://download.microsoft.com/ServiceTags_Public_20260101.json",
        ),
    )
    assertEquals(
        null,
        CloudAzureFetch.parseServiceTagsDate("https://download.microsoft.com/x.json"),
    )
    assertEquals(
        null,
        CloudAzureFetch.parseServiceTagsDate(
            "https://download.microsoft.com/ServiceTags_Public_99999999.json",
        ),
    )
  }

  /** fetchAzureIpRanges failure arm: empty set. */
  @Test
  fun testFetchAzureIpRangesFailureYieldsEmpty() {
    withHttp({ _ -> throw java.net.ConnectException("down") }) {
      assertTrue(CloudAzureFetch.fetchAzureIpRanges().isEmpty())
    }
  }

  @Test
  fun testFetchAzureIpRangesPageErrorYieldsEmpty() {
    withHttp({ _ -> 503 to "unavailable" }) {
      assertTrue(CloudAzureFetch.fetchAzureIpRanges().isEmpty())
    }
  }

  @Test
  fun testFetchAzureIpRangesNoDownloadUrlYieldsEmpty() {
    withHttp(
        { url ->
          if (url.startsWith("https://www.microsoft.com/")) 200 to "<html>no links</html>"
          else 200 to serviceTagsJson
        },
    ) {
      assertTrue(CloudAzureFetch.fetchAzureIpRanges().isEmpty())
    }
  }
}

/** test_nonblocking_refresh.py: refresh scheduling semantics over the fetch seam. */
class CloudManagerRefreshTest {
  init {
    CloudManager.resetInstance()
  }

  private fun awsRanges(): Set<IpNetwork> = setOf(IpNetwork.parse("52.94.76.0/22"))

  private class ThrowingAgentHandler : com.guardcore.protocols.AgentHandlerProtocol {
    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun sendEvent(event: Any?) = throw IllegalStateException("nope")

    override suspend fun sendMetric(metric: Any?) {}

    override suspend fun start() {}

    override suspend fun stop() {}

    override suspend fun flushBuffer() {}

    override suspend fun getDynamicRules(): Any? = null

    override suspend fun healthCheck(): Boolean = true
  }

  /** The recording agent sink of the handler tests. */
  private class RecordingSink : HandlerAgentSink {
    val events: MutableList<Map<String, Any?>> = mutableListOf()

    override suspend fun sendEvent(event: Map<String, Any?>) {
      events.add(event)
    }
  }

  /** test_nonblocking_refresh.py: single-flight scheduling returns true once, then false. */
  @Test
  fun testScheduleRefreshSingleFlight() {
    val previous = fetchProviderRangesOverride
    fetchProviderRangesOverride = { provider ->
      if (provider == "AWS") awsRanges() to mapOf("52.94.76.0/22" to "us-east-1")
      else linkedSetOf<IpNetwork>() to linkedMapOf()
    }
    try {
      runBlocking {
        val manager = CloudManager.getInstance()
        // Hold the in-flight task open so the second scheduling attempt races nothing.
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val first = manager.scheduleRefresh(refresh = { gate.await() })
        val second = manager.scheduleRefresh(refresh = { gate.await() })
        assertTrue(first)
        assertEquals(false, second)
        gate.complete(Unit)
        // Let the launched task settle before resetting the singleton.
        kotlinx.coroutines.delay(200)
      }
    } finally {
      fetchProviderRangesOverride = previous
      CloudManager.resetInstance()
    }
  }

  /** test_nonblocking_refresh.py:142 - a throwing fetcher never escapes the sync refresh. */
  @Test
  fun testRefreshSwallowsFetcherFailure() {
    val previous = fetchProviderRangesOverride
    fetchProviderRangesOverride = { _ -> throw java.io.IOException("boom") }
    try {
      runBlocking {
        val manager = CloudManager.getInstance()
        manager.refreshProviders(listOf("AWS"))
        assertTrue(manager.ipRanges["AWS"]!!.isEmpty())
      }
    } finally {
      fetchProviderRangesOverride = previous
      CloudManager.resetInstance()
    }
  }

  @Test
  fun testRefreshProvidersPopulatesRangesAndRegions() {
    val previous = fetchProviderRangesOverride
    fetchProviderRangesOverride = { provider ->
      if (provider == "AWS") awsRanges() to mapOf("52.94.76.0/22" to "us-east-1")
      else linkedSetOf<IpNetwork>() to linkedMapOf()
    }
    try {
      runBlocking {
        val manager = CloudManager.getInstance()
        manager.refreshProviders(listOf("AWS"))
        assertTrue(manager.ipRanges["AWS"]!!.isNotEmpty())
        manager.refreshProviders(listOf("AWS")) // second pass: no change logged, ranges stable
        assertTrue(manager.ipRanges["AWS"]!!.isNotEmpty())
      }
    } finally {
      fetchProviderRangesOverride = previous
      CloudManager.resetInstance()
    }
  }

  @Test
  fun testSendCloudEventWithAgent() {
    runBlocking {
      val manager = CloudManager.getInstance()
      val agent = RecordingSink()
      manager.agentHandler = agent
      manager.sendCloudEvent("cloud_detected", "1.2.3.4", "blocked", "aws ip")
      assertEquals(1, agent.events.size)
      assertEquals("cloud", agent.events[0]["handler_name"])
      // A throwing sink is swallowed (sendCloudEvent catch arm).
      manager.agentHandler = HandlerAgentSink.of(ThrowingAgentHandler())
      manager.sendCloudEvent("cloud_detected", "1.2.3.4", "blocked", "aws ip")
      manager.agentHandler = null
      CloudManager.resetInstance()
    }
  }
}
