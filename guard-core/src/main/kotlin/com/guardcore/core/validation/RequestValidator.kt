package com.guardcore.core.validation

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.EventTypes
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.MiddlewareEventBusProtocol
import com.guardcore.util.PathMatching
import com.guardcore.util.RequestLogging
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.logging.Logger

/**
 * Port of `guard_core/core/validation/context.py` (context.py:7): ValidationContext, the
 * context-object DI carrier for [RequestValidator].
 */
public class ValidationContext(
    public val config: SecurityConfig,
    public val logger: Logger,
    public val eventBus: MiddlewareEventBusProtocol,
)

/**
 * Port of `guard_core/core/validation/validator.py` (validator.py:18): RequestValidator. The path
 * matching helpers live in `com.guardcore.util.PathMatching` (the W1 port of
 * `core/validation/path_matching.py`); this class carries the per-request validation surfaces.
 */
public class RequestValidator(
    public val context: ValidationContext,
) {
  public val logger: Logger
    get() = context.logger

  private val hourMinuteFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")

  /** Python `_path_excluded_event_cache` (validator.py:21): TTLCache(1000, 300). */
  private val pathExcludedEventCache: com.guardcore.handlers.TtlCache<String, Boolean> =
      com.guardcore.handlers.TtlCache(maxsize = 1000, ttlSeconds = 300.0)

  private var normalizedExcludePaths: List<String> = emptyList()
  private var normalizedExcludePathsSource: List<String>? = null

  /** Python `is_request_https` (validator.py:27). */
  public fun isRequestHttps(request: GuardRequest): Boolean {
    var isHttps = request.urlScheme == "https"

    if (
        context.config.trustXForwardedProto &&
            context.config.trustedProxies.isNotEmpty() &&
            request.clientHost != null
    ) {
      if (isTrustedProxy(request.clientHost!!)) {
        val forwardedProto = request.headers["X-Forwarded-Proto"] ?: ""
        isHttps = isHttps || forwardedProto.lowercase() == "https"
      }
    }

    return isHttps
  }

  /** Python `is_trusted_proxy` (validator.py:41). */
  public fun isTrustedProxy(connectingIp: String): Boolean {
    for (proxy in context.config.trustedProxies) {
      if ("/" !in proxy) {
        if (connectingIp == proxy) {
          return true
        }
      } else {
        if (IpNetwork.parse(proxy).contains(parseAddress(connectingIp))) {
          return true
        }
      }
    }
    return false
  }

  /** Python async `check_time_window` (validator.py:51): UTC-only form. */
  public suspend fun checkTimeWindow(timeRestrictions: Map<String, String>): Boolean {
    return try {
      val startTime = timeRestrictions.getValue("start")
      val endTime = timeRestrictions.getValue("end")

      val currentTime = LocalDateTime.now(ZoneOffset.UTC)
      val currentHourMinute = currentTime.format(hourMinuteFormat)

      if (startTime > endTime) {
        currentHourMinute >= startTime || currentHourMinute <= endTime
      } else {
        startTime <= currentHourMinute && currentHourMinute <= endTime
      }
    } catch (e: Exception) {
      context.logger.severe("Error checking time window: $e")
      true
    }
  }

  /** Python `_current_normalized_exclude_paths` (validator.py:70). */
  private fun currentNormalizedExcludePaths(): List<String> {
    val currentSource = context.config.excludePaths.toList()
    if (currentSource != normalizedExcludePathsSource) {
      normalizedExcludePaths = PathMatching.normalizeExcludePaths(currentSource)
      normalizedExcludePathsSource = currentSource
    }
    return normalizedExcludePaths
  }

  /** Python async `is_path_excluded` (validator.py:77). */
  public suspend fun isPathExcluded(request: GuardRequest): Boolean {
    val normalizedPath = PathMatching.normalizeUrlPath(request.urlPath) ?: return false

    if (!PathMatching.pathMatchesExclusions(normalizedPath, currentNormalizedExcludePaths())) {
      return false
    }

    val cacheKey = sha256Hex(normalizedPath)
    if (pathExcludedEventCache[cacheKey] == null) {
      pathExcludedEventCache[cacheKey] = true
      val safePath =
          RequestLogging.redactEndpointForDisplay(
              request.urlPath,
              context.config.logSensitiveParams,
              context.config.logSensitiveBodyFields,
              context.config.logSensitiveHeaders,
          )
      context.eventBus.sendMiddlewareEvent(
          EventTypes.EVENT_PATH_EXCLUDED,
          request,
          "security_checks_bypassed",
          "Path $safePath excluded from security checks",
          linkedMapOf(
              "excluded_path" to safePath,
              "configured_exclusions" to context.config.excludePaths.toList(),
          ),
      )
    }

    return true
  }

  private fun sha256Hex(value: String): String =
      java.security.MessageDigest.getInstance("SHA-256")
          .digest(value.toByteArray(Charsets.UTF_8))
          .joinToString("") { "%02x".format(it) }
}
