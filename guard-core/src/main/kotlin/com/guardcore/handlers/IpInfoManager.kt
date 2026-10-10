package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.RedisHandlerProtocol
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Duration
import java.time.Instant
import java.util.logging.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** GeoIP record projection: the `country` key of the mmdb record (ipinfo_handler.py:256). */
public class MmdbCountryRecord {
  public var country: String? = null
    private set

  @com.maxmind.db.MaxMindDbConstructor
  public constructor(
      @com.maxmind.db.MaxMindDbParameter(name = "country", useDefault = true, defaultValue = "")
      country: String?,
  ) {
    this.country = country
  }
}

/** Python `_IPINFO_HANDLER_NAME` (ipinfo_handler.py:20). */
public const val IPINFO_HANDLER_NAME: String = "ipinfo"

/** The aiohttp `status`-carrying exception shape of the reference download path. */
public class HttpStatusException(
    public val status: Int,
    message: String,
) : RuntimeException(message)

/** Port of `_describe_download_error` (ipinfo_handler.py:23). */
public fun describeDownloadError(exc: Throwable): String =
    when (exc) {
      is HttpStatusException -> "${exc.javaClass.simpleName} (HTTP ${exc.status})"
      else -> exc.javaClass.simpleName
    }

/**
 * Port of `guard_core/handlers/ipinfo_handler.py` (IPInfoManager): the GeoIP country resolver over
 * the MaxMind JVM db reader with ipinfo download + Redis caching. Implements the [GeoIPHandler]
 * protocol (G-2 registration: the config geo factory constructs this manager).
 */
public class IpInfoManager
private constructor(
    public var token: String,
    public var dbPath: Path,
    public var maxAge: Int,
) : GeoIPHandler {
  public companion object {
    /** Python `_download_retries` (ipinfo_handler.py:35). */
    public const val DOWNLOAD_RETRIES: Int = 3

    private val client: HttpClient =
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

    @Volatile private var instance: IpInfoManager? = null

    /**
     * Python `IPInfoManager(token, db_path, max_age)` singleton dispatch (ipinfo_handler.py:46).
     */
    public fun getInstance(
        token: String,
        dbPath: Path? = null,
        maxAge: Int = 86400,
    ): IpInfoManager {
      if (token.isEmpty()) {
        throw IllegalArgumentException("IPInfo token is required!")
      }
      val existing = instance
      if (existing != null) {
        existing.token = token
        if (dbPath != null) {
          existing.dbPath = dbPath
        }
        existing.maxAge = maxAge
        return existing
      }
      synchronized(this) {
        val again = instance
        if (again != null) {
          again.token = token
          if (dbPath != null) {
            again.dbPath = dbPath
          }
          again.maxAge = maxAge
          return again
        }
        val created =
            IpInfoManager(
                token,
                dbPath ?: Path.of("data/ipinfo/country_asn.mmdb"),
                maxAge,
            )
        instance = created
        return created
      }
    }

    /** Test seam mirroring `IPInfoManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }

    /** Test seam mirroring `_download_retries` assignment. */
    @Volatile public var downloadRetries: Int = DOWNLOAD_RETRIES
  }

  public val logger: Logger = Logger.getLogger("guard_core.handlers.ipinfo")

  public var reader: com.maxmind.db.Reader? = null
    private set

  @Volatile public var redisHandler: RedisHandlerProtocol? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  @Volatile
  public var lastRefreshed: Instant? = null
    private set

  @Volatile
  public var initializationAttempted: Boolean = false
    private set

  private val scope = CoroutineScope(Dispatchers.Default)

  /** Python `is_initialized` (ipinfo_handler.py:74). */
  override val isInitialized: Boolean
    get() = reader != null

  /** Python `entry_count` (ipinfo_handler.py:78). */
  public val entryCount: Long
    get() = reader?.metadata?.nodeCount() ?: 0L

  /** Port of `get_status` (ipinfo_handler.py:83). */
  public fun getStatus(): Map<String, Any?> =
      linkedMapOf(
          "ready" to isInitialized,
          "last_refreshed" to lastRefreshed,
          "entries" to entryCount,
      )

  /** Port of `initialize_agent` (ipinfo_handler.py:90). */
  override suspend fun initializeAgent(agentHandler: AgentHandlerProtocol) {
    this.agentHandler = HandlerAgentSink.of(agentHandler)
  }

  /** Test seam: install a raw sink (handler-test fakes). */
  public fun setAgentSinkForTests(sink: HandlerAgentSink?) {
    this.agentHandler = sink
  }

  /** Port of `_open_database_or_none` (ipinfo_handler.py:93). */
  public fun openDatabaseOrNone(): com.maxmind.db.Reader? {
    return try {
      com.maxmind.db.Reader(dbPath.toFile())
    } catch (e: Exception) {
      logger.severe("IPInfo database at $dbPath is corrupted, removing: $e")
      try {
        Files.deleteIfExists(dbPath)
      } catch (ignored: Exception) {}
      null
    }
  }

  /** Port of `_apply_opened_reader` (ipinfo_handler.py:104). */
  public fun applyOpenedReader(reader: com.maxmind.db.Reader?) {
    if (reader != null) {
      this.reader = reader
      lastRefreshed = Instant.now()
    }
  }

  /** Port of `_write_database_atomically` (ipinfo_handler.py:109). */
  public fun writeDatabaseAtomically(content: ByteArray) {
    val tmpPath = dbPath.resolveSibling(dbPath.fileName.toString() + ".tmp")
    try {
      Files.write(tmpPath, content)
      Files.move(tmpPath, dbPath, StandardCopyOption.REPLACE_EXISTING)
    } catch (e: Exception) {
      try {
        Files.deleteIfExists(tmpPath)
      } catch (ignored: Exception) {}
      throw e
    }
  }

  /** Port of `initialize` (ipinfo_handler.py:120). */
  override suspend fun initialize() {
    try {
      Files.createDirectories(dbPath.parent)

      val redis = redisHandler
      if (redis != null) {
        val cachedDb =
            try {
              redis.getKey("ipinfo", "database")
            } catch (e: Exception) {
              logger.warning("Cached GeoIP database unavailable: $e")
              null
            }
        if (cachedDb != null) {
          val bytes =
              when (cachedDb) {
                is ByteArray -> cachedDb
                is String -> cachedDb.toByteArray(Charsets.ISO_8859_1)
                else -> cachedDb.toString().toByteArray(Charsets.ISO_8859_1)
              }
          writeDatabaseAtomically(bytes)
          applyOpenedReader(openDatabaseOrNone())
          return
        }
      }

      try {
        if (!Files.exists(dbPath) || isDbOutdated()) {
          downloadDatabase()
        }
      } catch (e: Exception) {
        logger.severe(
            "IPInfo database download failed, keeping existing reader: " + describeDownloadError(e),
        )
        if (agentHandler != null) {
          sendGeoEvent(
              eventType = EventTypes.EVENT_GEO_LOOKUP_FAILED,
              ipAddress = "system",
              actionTaken = "database_download_failed",
              reason = "Failed to download IPInfo database: " + describeDownloadError(e),
          )
        }
        return
      }

      if (Files.exists(dbPath)) {
        applyOpenedReader(openDatabaseOrNone())
      }
    } finally {
      initializationAttempted = true
    }
  }

  /** Port of `_send_geo_event` (ipinfo_handler.py:164). */
  public suspend fun sendGeoEvent(
      eventType: String,
      ipAddress: String,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val handler = agentHandler ?: return
    try {
      handler.sendEvent(
          linkedMapOf<String, Any?>(
              "event_type" to eventType,
              "ip_address" to ipAddress,
              "action_taken" to actionTaken,
              "reason" to reason,
              "rule_type" to metadata["rule_type"],
              "handler_name" to IPINFO_HANDLER_NAME,
              "metadata" to metadata,
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send geo event to agent: $e")
    }
  }

  /** Port of `_download_database` (ipinfo_handler.py:194): retries with 1s, 2s backoff. */
  public suspend fun downloadDatabase() {
    downloadOverride?.let {
      it()
      return
    }
    val baseUrl = "https://ipinfo.io/data/free/country_asn.mmdb"
    val headers = mapOf("Authorization" to "Bearer $token")
    val retries = downloadRetries
    var backoff = 1L

    for (attempt in 0 until retries) {
      try {
        val response =
            withContext(Dispatchers.IO) {
              val builder = HttpRequest.newBuilder().uri(URI.create(baseUrl)).GET()
              headers.forEach { (k, v) -> builder.header(k, v) }
              client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray())
            }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
          throw HttpStatusException(
              response.statusCode(),
              "HTTP ${response.statusCode()} for $baseUrl",
          )
        }
        val content = response.body()
        writeDatabaseAtomically(content)

        val redis = redisHandler
        if (redis != null) {
          try {
            val dbContent = String(Files.readAllBytes(dbPath), Charsets.ISO_8859_1)
            redis.setKey("ipinfo", "database", dbContent, ttl = maxAge)
          } catch (e: Exception) {
            logger.warning("Failed to cache GeoIP database in Redis: $e")
          }
        }
        return
      } catch (e: Exception) {
        if (attempt == retries - 1) {
          throw e
        }
        delay(backoff * 1000)
        backoff *= 2
      }
    }
  }

  /** Port of `_is_db_outdated` (ipinfo_handler.py:232). */
  public fun isDbOutdated(): Boolean {
    if (!Files.exists(dbPath)) {
      return true
    }
    val age = nowSeconds() - Files.getLastModifiedTime(dbPath).toMillis() / 1000.0
    return age > maxAge
  }

  /** Port of `get_country` (ipinfo_handler.py:239). */
  override fun getCountry(ip: String): String? {
    countryLookupOverride?.let {
      return it(ip)
    }
    val currentReader = reader
    if (currentReader == null) {
      if (initializationAttempted) {
        logger.warning(
            "Geo-IP reader unavailable after a failed initialization " +
                "attempt; returning None for $ip. Check the IPInfo token and " +
                "network reachability, then call refresh() to retry.",
        )
      } else {
        logger.warning("Geo-IP reader uninitialized; returning None for $ip")
      }
      return null
    }

    return try {
      val record = currentReader.get(InetAddress.getByName(ip), MmdbCountryRecord::class.java)
      record?.country?.takeIf { it.isNotEmpty() }
    } catch (e: Exception) {
      if (agentHandler != null) {
        scope.launch {
          sendGeoEvent(
              eventType = EventTypes.EVENT_GEO_LOOKUP_FAILED,
              ipAddress = ip,
              actionTaken = "lookup_failed",
              reason = "Geographic lookup failed: ${e.javaClass.simpleName}",
          )
        }
      }
      null
    }
  }

  /** Port of `check_country_access` (ipinfo_handler.py:276). */
  public suspend fun checkCountryAccess(
      ip: String,
      blockedCountries: List<String>,
      whitelistCountries: List<String>? = null,
  ): Pair<Boolean, String?> {
    val country = getCountry(ip)

    if (country == null) {
      if (!whitelistCountries.isNullOrEmpty()) {
        return false to null
      }
      return true to null
    }

    if (!whitelistCountries.isNullOrEmpty() && country !in whitelistCountries) {
      sendGeoEvent(
          eventType = EventTypes.EVENT_COUNTRY_BLOCKED,
          ipAddress = ip,
          actionTaken = "request_blocked",
          reason = "Country $country not in allowed list",
          metadata = mapOf("country" to country, "rule_type" to "country_whitelist"),
      )
      return false to country
    }

    if (country in blockedCountries) {
      sendGeoEvent(
          eventType = EventTypes.EVENT_COUNTRY_BLOCKED,
          ipAddress = ip,
          actionTaken = "request_blocked",
          reason = "Country $country is blocked",
          metadata = mapOf("country" to country, "rule_type" to "country_blacklist"),
      )
      return false to country
    }

    return true to country
  }

  /** Port of `close` (ipinfo_handler.py:313). */
  override fun close() {
    try {
      reader?.close()
    } catch (e: Exception) {
      // Python propagates reader.close() errors; maxminddb close raises OSError.
      throw e
    } finally {
      reader = null
    }
  }

  /** Port of `refresh` (ipinfo_handler.py:317). */
  override suspend fun refresh() {
    try {
      downloadDatabase()
    } catch (e: Exception) {
      logger.severe("IPInfo refresh failed: ${describeDownloadError(e)}")
      return
    } finally {
      initializationAttempted = true
    }

    if (!Files.exists(dbPath)) {
      return
    }

    val newReader = openDatabaseOrNone() ?: return

    close()
    reader = newReader
    lastRefreshed = Instant.now()
  }

  /** Port of `initialize_redis` (ipinfo_handler.py:337). */
  override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {
    this.redisHandler = redisHandler
    initialize()
  }

  /** Test seam mirroring `manager._initialization_attempted = ...`. */
  public fun setInitializationAttempted(value: Boolean) {
    initializationAttempted = value
  }

  /** Test seam mirroring `manager.reader = ...`. */
  public fun setReaderForTests(value: com.maxmind.db.Reader?) {
    reader = value
  }

  /**
   * Test seam mirroring the python tests' `patch.object(reader, "get")`: when set, getCountry
   * resolves through it instead of the mmdb reader. Production code never sets it.
   */
  @Volatile public var countryLookupOverride: ((ip: String) -> String?)? = null

  /** Test seam mirroring the python tests' aiohttp download mocks. */
  @Volatile public var downloadOverride: (suspend () -> Unit)? = null
}
