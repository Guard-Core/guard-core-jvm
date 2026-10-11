package com.guardcore.handlers

import com.guardcore.util.py.IpNetwork
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.logging.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Port of `guard_core/handlers/_cloud_azure_fetch.py`: the Microsoft ServiceTags discovery chain
 * (download page scrape -> trusted-URL extraction -> newest-date selection -> ServiceTags JSON).
 */
public object CloudAzureFetch {
  private val logger: Logger = Logger.getLogger("guard_core.handlers.cloud")
  private val json = Json { isLenient = true }

  public const val AZURE_DOWNLOAD_MAX_ATTEMPTS: Int = 3
  public const val AZURE_DOWNLOAD_RETRY_DELAY_SECONDS: Double = 2.0
  public const val AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS: Double = 20.0
  public const val AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS: Double = 10.0
  public const val AZURE_PAGE_FETCH_TIMEOUT_SECONDS: Double = 10.0

  public const val AZURE_TRUSTED_DOWNLOAD_HOST: String = "download.microsoft.com"

  /** Python's fixed download-page URL (_cloud_azure_fetch.py). */
  public const val PAGE_URL: String =
      "https://www.microsoft.com/en-us/download/details.aspx?id=56519"

  /** Python `_AZURE_SERVICE_TAGS_URL_PATTERN` (_cloud_azure_fetch.py:22). */
  public const val AZURE_SERVICE_TAGS_URL_PATTERN: String =
      "https://download\\.microsoft\\.com/[^\"'\\s<>]+ServiceTags[^\"'\\s<>]*\\.json(?:\\?[^\"'\\s<>]*)?"

  /** Python `_AZURE_SERVICE_TAGS_DATE_PATTERN` (_cloud_azure_fetch.py:26). */
  private val AZURE_SERVICE_TAGS_DATE_PATTERN = Regex("ServiceTags_Public_(\\d{8})")

  public const val AZURE_SERVICE_TAGS_STALE_WARNING_DAYS: Long = 90
  private const val AZURE_CLOUD_SERVICE_TAG_NAME = "AzureCloud"

  private val client: HttpClient =
      HttpClient.newBuilder()
          .followRedirects(HttpClient.Redirect.NEVER)
          .connectTimeout(Duration.ofSeconds(10))
          .build()

  /**
   * Test seam mirroring the python tests' aiohttp session mocks (test_cloud_ips.py, the Azure
   * redirect real-sockets family): when set, every GET resolves through it as (status, body);
   * production never sets it.
   */
  @Volatile
  internal var httpGetOverride: (suspend (url: String) -> Pair<Int, String>)? = null

  private suspend fun httpGet(url: String, timeoutNanos: Long): HttpResponse<String> {
    httpGetOverride?.let {
      val (status, body) = it(url)
      return FakeHttpResponse(status, body, URI.create(url))
    }
    return withContext(Dispatchers.IO) {
      val request =
          HttpRequest.newBuilder()
              .uri(URI.create(url))
              .timeout(Duration.ofNanos(timeoutNanos))
              .GET()
              .build()
      client.send(request, HttpResponse.BodyHandlers.ofString())
    }
  }

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
  }

  private fun monotonic(): Double = System.nanoTime() / 1_000_000_000.0

  /** Port of `_download_azure_service_tags` (_cloud_azure_fetch.py:31). */
  public suspend fun downloadAzureServiceTags(
      downloadUrl: String,
      deadline: Double = monotonic() + AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS,
  ): kotlinx.serialization.json.JsonObject {
    var attempt = 0
    while (true) {
      val remaining = deadline - monotonic()
      if (remaining <= 0) {
        throw IllegalStateException("Azure IP ranges download exceeded max elapsed time")
      }
      attempt += 1
      val attemptTimeout = minOf(AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS, remaining)
      val response =
          try {
            httpGet(downloadUrl, (attemptTimeout * 1e9).toLong())
          } catch (e: Exception) {
            val remainingAfter = deadline - monotonic()
            if (attempt >= AZURE_DOWNLOAD_MAX_ATTEMPTS || remainingAfter <= 0) {
              throw e
            }
            kotlinx.coroutines.delay(
                (minOf(AZURE_DOWNLOAD_RETRY_DELAY_SECONDS, remainingAfter) * 1000).toLong(),
            )
            continue
          }
      if (response.statusCode() in 300..399) {
        throw IllegalArgumentException(
            "Azure IP ranges download redirected (status ${response.statusCode()}); " +
                "refusing to follow redirects",
        )
      }
      if (response.statusCode() < 200 || response.statusCode() >= 300) {
        throw IllegalStateException("HTTP ${response.statusCode()} for $downloadUrl")
      }
      return json.parseToJsonElement(response.body()).jsonObject
    }
  }

  /** Port of `_is_trusted_azure_download_url` (_cloud_azure_fetch.py:65). */
  public fun isTrustedAzureDownloadUrl(url: String): Boolean {
    val uri =
        try {
          URI(url)
        } catch (e: Exception) {
          return false
        }
    return uri.scheme == "https" && uri.host == AZURE_TRUSTED_DOWNLOAD_HOST
  }

  /** Port of `_parse_service_tags_date` (_cloud_azure_fetch.py:70). */
  public fun parseServiceTagsDate(url: String): LocalDate? {
    val dateMatch = AZURE_SERVICE_TAGS_DATE_PATTERN.find(url) ?: return null
    val parsedDate =
        try {
          LocalDate.parse(dateMatch.groupValues[1], DateTimeFormatter.ofPattern("yyyyMMdd"))
        } catch (e: Exception) {
          return null
        }
    if (parsedDate.isAfter(LocalDate.now(ZoneOffset.UTC))) {
      return null
    }
    return parsedDate
  }

  /** Port of `_service_tags_sort_key` (_cloud_azure_fetch.py:83): (has_date, date, url). */
  public fun serviceTagsSortKey(url: String): Triple<Boolean, LocalDate, String> {
    val parsedDate = parseServiceTagsDate(url)
    return Triple(
        parsedDate != null,
        parsedDate ?: LocalDate.MIN,
        url,
    )
  }

  /** Port of `_warn_if_service_tags_url_is_stale` (_cloud_azure_fetch.py:88). */
  public fun warnIfServiceTagsUrlIsStale(url: String) {
    val parsedDate = parseServiceTagsDate(url)
    if (parsedDate == null) {
      logger.warning(
          "Selected Azure ServiceTags URL has no parseable date, cannot confirm " +
              "it is current: $url",
      )
      return
    }
    val ageDays = LocalDate.now(ZoneOffset.UTC).toEpochDay() - parsedDate.toEpochDay()
    if (ageDays > AZURE_SERVICE_TAGS_STALE_WARNING_DAYS) {
      logger.warning(
          "Selected Azure ServiceTags URL is $ageDays days old, possibly stale: $url",
      )
    }
  }

  /** Port of `_extract_failover_link_url` (_cloud_azure_fetch.py:106). */
  public fun extractFailoverLinkUrl(decodedHtml: String): String? {
    val anchorMatch =
        Regex("<a\\b[^>]*\\bid=[\"']failoverLink[\"'][^>]*>").find(decodedHtml) ?: return null
    val hrefMatch = Regex("href=[\"']([^\"']+)[\"']").find(anchorMatch.value) ?: return null
    val url = hrefMatch.groupValues[1]
    return if (isTrustedAzureDownloadUrl(url)) url else null
  }

  /** Port of `_extract_newest_service_tags_url` (_cloud_azure_fetch.py:119). */
  public fun extractNewestServiceTagsUrl(decodedHtml: String): String? {
    val candidates =
        Regex(AZURE_SERVICE_TAGS_URL_PATTERN)
            .findAll(decodedHtml)
            .map { it.value }
            .filter { isTrustedAzureDownloadUrl(it) }
            .toList()
    if (candidates.isEmpty()) {
      return null
    }
    val winner =
        candidates.maxWith(
            compareBy(
                { serviceTagsSortKey(it).first },
                { serviceTagsSortKey(it).second },
                { serviceTagsSortKey(it).third },
            ),
        )
    warnIfServiceTagsUrlIsStale(winner)
    return winner
  }

  /** Port of `_extract_generic_json_url` (_cloud_azure_fetch.py:132). */
  public fun extractGenericJsonUrl(decodedHtml: String): String? {
    val match =
        Regex(
                "href=[\"'](https://download\\.microsoft\\.com/[^\"']+\\.json(?:\\?[^\"']*)?)[\"']",
            )
            .find(decodedHtml) ?: return null
    val url = match.groupValues[1]
    return if (isTrustedAzureDownloadUrl(url)) url else null
  }

  /** Port of `_extract_azure_download_url` (_cloud_azure_fetch.py:143). */
  public fun extractAzureDownloadUrl(decodedHtml: String): String? =
      extractFailoverLinkUrl(decodedHtml)
          ?: extractNewestServiceTagsUrl(decodedHtml)
          ?: extractGenericJsonUrl(decodedHtml)

  /** Python `html.unescape` equivalent (HTML5 named + numeric entities). */
  public fun htmlUnescape(text: String): String {
    var result = text
    // Numeric entities first, then the common named set; Python's html.unescape
    // covers the full HTML5 table, the ServiceTags page uses this subset.
    result =
        Regex("&#x([0-9a-fA-F]+);?").replace(result) { m ->
          m.groupValues[1].toInt(16).toChar().toString()
        }
    result =
        Regex("&#(\\d+);?").replace(result) { m -> m.groupValues[1].toInt().toChar().toString() }
    val named =
        mapOf(
            "&amp;" to "&",
            "&lt;" to "<",
            "&gt;" to ">",
            "&quot;" to "\"",
            "&apos;" to "'",
            "&#39;" to "'",
            "&nbsp;" to "\u00a0",
        )
    for ((entity, replacement) in named) {
      result = result.replace(entity, replacement)
    }
    return result
  }

  /** Port of `_select_azure_cloud_prefixes` (_cloud_azure_fetch.py:151). */
  public fun selectAzureCloudPrefixes(data: kotlinx.serialization.json.JsonObject): List<String> {
    val values: List<kotlinx.serialization.json.JsonElement> =
        data["values"]?.jsonArray ?: emptyList()
    for (entryElement in values) {
      val entry = entryElement.jsonObject
      val name = entry["name"]?.jsonPrimitive?.content
      if (name == AZURE_CLOUD_SERVICE_TAG_NAME) {
        val properties = entry["properties"]?.jsonObject
        val prefixes = properties?.get("addressPrefixes")?.jsonArray
        return prefixes?.map { it.jsonPrimitive.content } ?: emptyList()
      }
    }
    logger.severe("Azure ServiceTags document has no '$AZURE_CLOUD_SERVICE_TAG_NAME' tag")
    return emptyList()
  }

  /** Port of `fetch_azure_ip_ranges` (_cloud_azure_fetch.py:161). */
  public suspend fun fetchAzureIpRanges(): Set<IpNetwork> {
    return try {
      val deadline = monotonic() + AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS
      val pageTimeout = minOf(AZURE_PAGE_FETCH_TIMEOUT_SECONDS, deadline - monotonic())
      if (pageTimeout <= 0) {
        throw IllegalStateException("Azure IP ranges download exceeded max elapsed time")
      }

      val pageResponse = httpGet(PAGE_URL, (pageTimeout * 1e9).toLong())
      if (pageResponse.statusCode() < 200 || pageResponse.statusCode() >= 300) {
        throw IllegalStateException("HTTP ${pageResponse.statusCode()} for the download page")
      }
      val pageText = pageResponse.body()

      val decodedHtml = htmlUnescape(pageText)
      val downloadUrl =
          extractAzureDownloadUrl(decodedHtml)
              ?: throw IllegalArgumentException("Could not find Azure IP ranges download URL")

      val data = downloadAzureServiceTags(downloadUrl, deadline)

      selectAzureCloudPrefixes(data)
          .mapNotNull { prefix ->
            try {
              IpNetwork.parse(prefix)
            } catch (e: Exception) {
              null
            }
          }
          .toSet()
    } catch (e: Exception) {
      logger.severe("Failed to fetch Azure IP ranges: $e")
      linkedSetOf()
    }
  }
}
