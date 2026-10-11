package com.guardcore.handlers

import com.guardcore.util.py.IpNetwork
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.logging.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Port of `guard_core/handlers/_cloud_provider_fetchers.py`: AWS/GCP/DigitalOcean/Linode/Vultr
 * range fetches over `java.net.http` (the sanctioned JDK client standing in for aiohttp).
 */
public object CloudFetchers {
  private val logger: Logger = Logger.getLogger("guard_core.handlers.cloud")
  private val json = Json { isLenient = true }
  private val client: HttpClient =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

  /**
   * Test seam mirroring the python tests' aiohttp session mocks (test_cloud_ips.py): when set,
   * every GET resolves through it as (status, body); production never sets it.
   */
  @Volatile internal var httpGetOverride: (suspend (url: String) -> Pair<Int, String>)? = null

  private suspend fun httpGet(
      url: String,
      timeoutSeconds: Long = 10,
  ): HttpResponse<String> {
    httpGetOverride?.let {
      val (status, body) = it(url)
      return FakeHttpResponse(status, body, URI.create(url))
    }
    return withContext(Dispatchers.IO) {
      val request =
          HttpRequest.newBuilder()
              .uri(URI.create(url))
              .timeout(Duration.ofSeconds(timeoutSeconds))
              .GET()
              .build()
      client.send(request, HttpResponse.BodyHandlers.ofString())
    }
  }

  /** The status/body pair the override seam folds into the HttpClient response shape. */
  private class FakeHttpResponse(
      private val status: Int,
      private val content: String,
      private val uri: URI,
  ) : HttpResponse<String> {
    override fun statusCode(): Int = status

    override fun body(): String = content

    override fun uri(): URI = uri

    override fun headers(): java.net.http.HttpHeaders =
        java.net.http.HttpHeaders.of(mapOf(), { _, _ -> true })

    override fun previousResponse(): java.util.Optional<HttpResponse<String>> =
        java.util.Optional.empty()

    override fun request(): HttpRequest = HttpRequest.newBuilder().uri(uri).build()

    override fun sslSession(): java.util.Optional<javax.net.ssl.SSLSession> =
        java.util.Optional.empty()

    override fun version(): HttpClient.Version = HttpClient.Version.HTTP_1_1

    override fun toString(): String = "FakeHttpResponse[$status]"
  }

  private fun raiseForStatus(response: HttpResponse<String>) {
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      throw IllegalStateException("HTTP ${response.statusCode()} for ${response.uri()}")
    }
  }

  /** Port of `fetch_aws_ip_ranges` (_cloud_provider_fetchers.py:9). */
  public suspend fun fetchAwsIpRanges(): Pair<Set<IpNetwork>, Map<String, String>> {
    return try {
      val response = httpGet("https://ip-ranges.amazonaws.com/ip-ranges.json")
      raiseForStatus(response)
      val data = json.parseToJsonElement(response.body()).jsonObject
      val networks = linkedSetOf<IpNetwork>()
      val regions = linkedMapOf<String, String>()
      val prefixes: List<kotlinx.serialization.json.JsonElement> =
          data["prefixes"]?.jsonArray ?: emptyList()
      for (ipRange in prefixes) {
        val entry = ipRange.jsonObject
        val service = entry["service"]?.jsonPrimitive?.content ?: continue
        if (service != "AMAZON") {
          continue
        }
        val prefix = entry["ip_prefix"]?.jsonPrimitive?.content ?: continue
        val network = IpNetwork.parse(prefix)
        networks.add(network)
        val region = entry["region"]?.jsonPrimitive?.content
        if (!region.isNullOrEmpty()) {
          regions[network.text] = region
        }
      }
      networks to regions
    } catch (e: Exception) {
      logger.severe("Failed to fetch AWS IP ranges: $e")
      linkedSetOf<IpNetwork>() to linkedMapOf<String, String>()
    }
  }

  /** Port of `fetch_gcp_ip_ranges` (_cloud_provider_fetchers.py:36). */
  public suspend fun fetchGcpIpRanges(): Pair<Set<IpNetwork>, Map<String, String>> {
    return try {
      val response = httpGet("https://www.gstatic.com/ipranges/cloud.json")
      raiseForStatus(response)
      val data = json.parseToJsonElement(response.body()).jsonObject
      val networks = linkedSetOf<IpNetwork>()
      val regions = linkedMapOf<String, String>()
      val prefixes: List<kotlinx.serialization.json.JsonElement> =
          data["prefixes"]?.jsonArray ?: emptyList()
      for (ipRange in prefixes) {
        val entry = ipRange.jsonObject
        val prefix =
            entry["ipv4Prefix"]?.jsonPrimitive?.content
                ?: entry["ipv6Prefix"]?.jsonPrimitive?.content
        if (prefix == null) {
          continue
        }
        val network = IpNetwork.parse(prefix)
        networks.add(network)
        val scope = entry["scope"]?.jsonPrimitive?.content
        if (!scope.isNullOrEmpty()) {
          regions[network.text] = scope
        }
      }
      networks to regions
    } catch (e: Exception) {
      logger.severe("Failed to fetch GCP IP ranges: $e")
      linkedSetOf<IpNetwork>() to linkedMapOf<String, String>()
    }
  }

  /** Port of `_fetch_csv_prefix_networks` (_cloud_provider_fetchers.py:64). */
  private suspend fun fetchCsvPrefixNetworks(url: String): Set<IpNetwork> {
    val response = httpGet(url)
    raiseForStatus(response)
    val body = response.body()

    val networks = linkedSetOf<IpNetwork>()
    for (rawLine in body.lineSequence()) {
      val line = rawLine.trim()
      if (line.isEmpty() || line.startsWith("#")) {
        continue
      }
      val prefix = line.substringBefore(",").trim()
      if (prefix.isEmpty()) {
        continue
      }
      try {
        networks.add(IpNetwork.parse(prefix))
      } catch (e: Exception) {
        continue
      }
    }
    return networks
  }

  /** Port of `fetch_digitalocean_ip_ranges` (_cloud_provider_fetchers.py:90). */
  public suspend fun fetchDigitalOceanIpRanges(): Set<IpNetwork> {
    return try {
      fetchCsvPrefixNetworks("https://www.digitalocean.com/geo/google.csv")
    } catch (e: Exception) {
      logger.severe("Failed to fetch DigitalOcean IP ranges: $e")
      linkedSetOf()
    }
  }

  /** Port of `fetch_linode_ip_ranges` (_cloud_provider_fetchers.py:102). */
  public suspend fun fetchLinodeIpRanges(): Set<IpNetwork> {
    return try {
      fetchCsvPrefixNetworks("https://geoip.linode.com/")
    } catch (e: Exception) {
      logger.severe("Failed to fetch Linode IP ranges: $e")
      linkedSetOf()
    }
  }

  /** Port of `fetch_vultr_ip_ranges` (_cloud_provider_fetchers.py:112). */
  public suspend fun fetchVultrIpRanges(): Set<IpNetwork> {
    return try {
      val response = httpGet("https://geofeed.constant.com/?json")
      raiseForStatus(response)
      val data = json.parseToJsonElement(response.body()).jsonObject

      val networks = linkedSetOf<IpNetwork>()
      val subnets: List<kotlinx.serialization.json.JsonElement> =
          data["subnets"]?.jsonArray ?: emptyList()
      for (entryElement in subnets) {
        val entry = entryElement.jsonObject
        val prefix = entry["ip_prefix"]?.jsonPrimitive?.content
        if (prefix == null) {
          continue
        }
        try {
          networks.add(IpNetwork.parse(prefix))
        } catch (e: Exception) {
          continue
        }
      }
      networks
    } catch (e: Exception) {
      logger.severe("Failed to fetch Vultr IP ranges: $e")
      linkedSetOf()
    }
  }
}
