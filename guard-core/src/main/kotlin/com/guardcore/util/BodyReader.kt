package com.guardcore.util

import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.asBoundedBodyReader

/**
 * Port of `guard_core/_utils/body_reader.py` (body_reader.py:1-186): timeout-bounded body reads,
 * capped body prefixes and the detection cap warnings.
 *
 * The `_straddle_overlap_bytes` seam depends on the W2 pattern engine (sus_patterns_handler,
 * body_reader.py:46-58); until registered it returns 0, which is the Python function's own
 * failure-path result.
 */
public object BodyReader {
  internal val CONTENT_LENGTH_REGEX = Regex("[0-9]+")

  /** Port of `_parse_content_length` (body_reader.py:17). */
  internal fun parseContentLength(value: String): Int? {
    val stripped = value.trim()
    if (!CONTENT_LENGTH_REGEX.matches(stripped)) return null
    val parsed = stripped.toLongOrNull() ?: return null
    return if (parsed > 0 && parsed <= Int.MAX_VALUE) parsed.toInt()
    else if (parsed > Int.MAX_VALUE) Int.MAX_VALUE else null
  }

  /** Port of `_DEFAULT_BODY_READ_TIMEOUT` (body_reader.py:30). */
  public const val DEFAULT_BODY_READ_TIMEOUT: Double = 3.0

  /** Port of `_DEFAULT_BODY_READ_MAX_CONCURRENT` (body_reader.py:31). */
  public const val DEFAULT_BODY_READ_MAX_CONCURRENT: Int = 64

  /** Port of `_MAX_STRADDLE_OVERLAP_BYTES` (body_reader.py:32). */
  internal const val MAX_STRADDLE_OVERLAP_BYTES: Int = 256

  /** Seam: longest compiled pattern length, registered by the W2 engine. */
  @Volatile public var straddleOverlapBytesProvider: (() -> Int)? = null

  private fun straddleOverlapBytes(): Int = straddleOverlapBytesProvider?.invoke() ?: 0

  /** Port of `_safe_read` (body_reader.py:35): null on any failure/timeout. */
  public suspend fun safeRead(reader: suspend () -> ByteArray, timeoutSeconds: Double): ByteArray? =
      try {
        kotlinx.coroutines.withTimeout((timeoutSeconds * 1000).toLong()) { reader() }
      } catch (_: Exception) {
        null
      }

  private const val CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"

  /** Cache entry: (source request, fetched byte count, cached prefix). */
  internal class PrefixCacheEntry(
      val source: GuardRequest,
      val fetchedBytes: Int,
      val bytes: ByteArray,
  )

  /** Port of `_read_and_cache_body` (body_reader.py:64-93). */
  internal suspend fun readAndCacheBody(
      request: GuardRequest,
      maxBytes: Int,
      timeout: Double,
      reader: suspend () -> ByteArray,
  ): ByteArray? {
    val cached = request.state.getAttr(CAPPED_BODY_PREFIX_STATE_ATTR) as? PrefixCacheEntry
    if (cached != null && cached.source === request && cached.fetchedBytes >= maxBytes) {
      return cached.bytes.copyOfRange(0, minOf(maxBytes, cached.bytes.size))
    }
    val prefix = safeRead(reader, timeout) ?: return null
    val capped = prefix.copyOfRange(0, minOf(maxBytes, prefix.size))
    request.state.setAttr(
        CAPPED_BODY_PREFIX_STATE_ATTR,
        PrefixCacheEntry(request, maxBytes, capped),
    )
    return capped
  }

  /** Port of `_capped_body_fetch_size` (body_reader.py:96). */
  private fun cappedBodyFetchSize(maxBytes: Int): Int = maxBytes + straddleOverlapBytes()

  /** Port of `_read_capped_body_prefix` (body_reader.py:100-114). */
  private suspend fun readCappedBodyPrefix(
      request: GuardRequest,
      maxBytes: Int,
      timeout: Double,
  ): ByteArray? {
    val bounded = request.asBoundedBodyReader() ?: return null
    val fetchBytes = cappedBodyFetchSize(maxBytes)
    return readAndCacheBody(
        request,
        fetchBytes,
        timeout,
        { bounded.readBodyPrefix(fetchBytes) },
    )
  }

  /** Port of `_warn_body_inspect_bytes_cap_reached` (body_reader.py:117). */
  private fun warnBodyInspectBytesCapReached(maxBytes: Int, clientIp: String) {
    DetectionScanContext.guardLogger.warning(
        "detection_max_body_inspect_bytes ($maxBytes) reached for client $clientIp; only the " +
            "first $maxBytes bytes of the request body are scanned",
    )
  }

  /** Port of `_warn_body_inspect_bytes_cap_reached_no_bounded_reader` (body_reader.py:127). */
  private fun warnBodyInspectBytesCapReachedNoBoundedReader(maxBytes: Int, clientIp: String) {
    DetectionScanContext.guardLogger.warning(
        "detection_max_body_inspect_bytes ($maxBytes) reached for client $clientIp; the " +
            "request body is not read because the adapter does not implement a " +
            "bounded reader (read_body_prefix)",
    )
  }

  /** Port of `_read_oversized_declared_body` (body_reader.py:139-159). */
  private suspend fun readOversizedDeclaredBody(
      request: GuardRequest,
      maxBytes: Int,
      timeout: Double,
      clientIp: String,
  ): ByteArray? {
    val bounded = request.asBoundedBodyReader()
    if (bounded == null) {
      warnBodyInspectBytesCapReachedNoBoundedReader(maxBytes, clientIp)
      return null
    }
    warnBodyInspectBytesCapReached(maxBytes, clientIp)
    val fetchBytes = cappedBodyFetchSize(maxBytes)
    return readAndCacheBody(
        request,
        fetchBytes,
        timeout,
        { bounded.readBodyPrefix(fetchBytes) },
    )
  }

  /** Port of `_read_capped_body` (body_reader.py:162-186). */
  public suspend fun readCappedBody(
      request: GuardRequest,
      config: com.guardcore.config.SecurityConfig?,
      clientIp: String = "",
  ): ByteArray? {
    if (config == null) {
      return safeRead({ request.body() }, DEFAULT_BODY_READ_TIMEOUT)
    }
    val maxBytes = config.detectionMaxBodyInspectBytes
    val timeout = config.bodyReadTimeout
    val contentLength = request.headers["content-length"]
    if (contentLength != null) {
      val parsed = parseContentLength(contentLength)
      if (parsed != null) {
        if (parsed > maxBytes) {
          return readOversizedDeclaredBody(request, maxBytes, timeout, clientIp)
        }
        return readAndCacheBody(request, maxBytes, timeout, { request.body() })
      }
    }
    return readCappedBodyPrefix(request, maxBytes, timeout)
  }
}
