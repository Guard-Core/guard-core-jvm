package com.guardcore.util

import com.guardcore.config.BlockHook
import com.guardcore.protocols.GuardRequest
import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import java.util.logging.Logger

/**
 * Port of `guard_core/_utils/request_logging.py`: URL/header/blob redaction entry points and
 * `log_activity`.
 */
public object RequestLogging {
  /** Port of `_DEFAULT_SENSITIVE_LOG_HEADERS` (request_logging.py:22). */
  private val DEFAULT_SENSITIVE_LOG_HEADERS: Set<String> =
      setOf("authorization", "proxy-authorization", "cookie", "x-api-key")

  /** Port of `_DEFAULT_SENSITIVE_LOG_FIELDS` (request_logging.py:26). */
  private val DEFAULT_SENSITIVE_LOG_FIELDS: Set<String> =
      setOf(
          "access_token",
          "refresh_token",
          "api_key",
          "apikey",
          "token",
          "password",
          "secret",
          "client_secret",
          "signature",
      )

  /** Port of `_merge_sensitive_names` (request_logging.py:41). */
  internal fun mergeSensitiveNames(defaults: Set<String>, extra: Set<String>?): Set<String> =
      if (extra == null) {
        defaults
      } else {
        defaults + extra.map { it.lowercase() }
      }

  /** Port of `_merge_sensitive_log_headers` (request_logging.py:49). */
  internal fun mergeSensitiveLogHeaders(extra: Set<String>?): Set<String> =
      mergeSensitiveNames(DEFAULT_SENSITIVE_LOG_HEADERS, extra)

  /**
   * Port of `_resolve_json_depth_cap` (request_logging.py:53). The Python function reads the
   * detection scan-budget context (set by `_scan_value_budget`,
   * guard_core/_utils/detection_scan.py:46); the W1 budget holder starts at the same module default
   * (32) and the W2 engine wires the live values through `DetectionScanContext`.
   */
  private fun resolveJsonDepthCap(): Int = DetectionScanContext.jsonDepthCapValue()

  /** Port of `_json_redact_text` (request_logging.py:59). */
  private fun jsonRedactText(
      text: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String? {
    val parsed =
        try {
          PyJson.loads(text)
        } catch (_: com.guardcore.errors.PyRecursionError) {
          return "[REDACTED]"
        } catch (_: PyJson.JsonDecodeError) {
          return null
        }
    if (parsed !is Map<*, *> && parsed !is List<*>) return null
    LoggingUtils.jsonDepthCapHit.set(false)
    val redacted =
        LoggingUtils.redactSensitiveJson(parsed, sensitive, sensitiveBodyFields, maxDepth)
    if (LoggingUtils.jsonDepthCapHit.get()) return "[REDACTED]"
    if (redacted == parsed) return null
    return PyJson.dumps(redacted, ensureAscii = false)
  }

  /** Port of `_redact_json_or_pairs_segment` (request_logging.py:84). */
  private fun redactJsonOrPairsSegment(
      segment: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String {
    val decoded = PairValueScan.boundedPercentDecode(segment, plusToSpace = false)
    val redactedText = jsonRedactText(decoded, sensitive, sensitiveBodyFields, maxDepth)
    if (redactedText != null) return PyUrllib.quote(redactedText, safe = "")
    return PairRedaction.redactPairsInText(segment, sensitive, sensitiveBodyFields, maxDepth)
  }

  /** Port of `_redact_path_segment` (request_logging.py:99). */
  private fun redactPathSegment(
      segment: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String {
    val sepIndex = segment.indexOf(';')
    val proper: String
    val rest: String
    val hasSep: Boolean
    if (sepIndex == -1) {
      proper = segment
      rest = ""
      hasSep = false
    } else {
      proper = segment.substring(0, sepIndex)
      rest = segment.substring(sepIndex + 1)
      hasSep = true
    }
    val redactedProper = redactJsonOrPairsSegment(proper, sensitive, sensitiveBodyFields, maxDepth)
    if (!hasSep) return redactedProper
    val redactedRest = redactJsonOrPairsSegment(rest, sensitive, sensitiveBodyFields, maxDepth)
    return listOf(redactedProper, redactedRest).joinToString(";")
  }

  /** Port of `_redact_whole_path_as_json` (request_logging.py:117). */
  private fun redactWholePathAsJson(
      path: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String? {
    val prefix = if (path.startsWith("/")) "/" else ""
    val decoded =
        PairValueScan.boundedPercentDecode(path.substring(prefix.length), plusToSpace = false)
    val redactedText = jsonRedactText(decoded, sensitive, sensitiveBodyFields, maxDepth)
    return if (redactedText == null) null else prefix + redactedText
  }

  /** Port of `_split_path_segments` (request_logging.py:131). */
  internal fun splitPathSegments(path: String): List<String> {
    val segments = ArrayList<String>()
    val current = StringBuilder()
    var quoteChar = ' '
    var escaped = false
    for (ch in path) {
      if (quoteChar != ' ') {
        current.append(ch)
        when {
          escaped -> escaped = false
          ch == '\\' -> escaped = true
          ch == quoteChar -> quoteChar = ' '
        }
        continue
      }
      if (ch in PairValueScan.QUOTE_CHARS) {
        quoteChar = ch
        current.append(ch)
        continue
      }
      if (ch == '/') {
        segments.add(current.toString())
        current.setLength(0)
        continue
      }
      current.append(ch)
    }
    segments.add(current.toString())
    return segments
  }

  /** Port of `_redact_sensitive_path` (request_logging.py:159). */
  private fun redactSensitivePath(
      path: String,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String {
    val whole = redactWholePathAsJson(path, sensitive, sensitiveBodyFields, maxDepth)
    if (whole != null) return whole
    return splitPathSegments(path).joinToString("/") {
      redactPathSegment(it, sensitive, sensitiveBodyFields, maxDepth)
    }
  }

  /** Port of `_merge_sensitive_log_body_fields` (request_logging.py:176). */
  internal fun mergeSensitiveLogBodyFields(extra: Set<String>?): Set<String> =
      mergeSensitiveNames(DEFAULT_SENSITIVE_LOG_FIELDS, extra)

  /** Port of `_redact_sensitive_headers` (request_logging.py:180). */
  internal fun redactSensitiveHeaders(
      headers: Map<String, String>,
      sensitiveHeaders: Set<String>?,
      sensitiveBodyFields: Set<String>? = null,
      sensitiveParams: Set<String>? = null,
  ): Map<String, String> {
    val sensitive = mergeSensitiveLogHeaders(sensitiveHeaders)
    val result = LinkedHashMap<String, String>()
    for ((key, value) in headers) {
      result[key] =
          if (key.trim().lowercase() in sensitive) {
            "[REDACTED]"
          } else {
            redactBlobForDisplay(value, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)
          }
    }
    return result
  }

  private val URL_UNSAFE_CONTROL_TRANSLATION: Map<Char, String> =
      mapOf('\t' to "%09", '\r' to "%0D", '\n' to "%0A")

  /** Port of `_escape_url_unsafe_controls` (request_logging.py:200). */
  private fun escapeUrlUnsafeControls(url: String): String {
    if (url.none { it == '\t' || it == '\r' || it == '\n' }) return url
    val out = StringBuilder(url.length)
    for (ch in url) {
      out.append(URL_UNSAFE_CONTROL_TRANSLATION[ch] ?: ch.toString())
    }
    return out.toString()
  }

  /** Port of `_redact_netloc_password` (request_logging.py:206). */
  private fun redactNetlocPassword(netloc: String): String {
    if ('@' !in netloc) return netloc
    val atIdx = netloc.lastIndexOf('@')
    val userinfo = netloc.substring(0, atIdx)
    val hostport = netloc.substring(atIdx + 1)
    val colonIdx = userinfo.indexOf(':')
    if (colonIdx == -1) return netloc
    val user = userinfo.substring(0, colonIdx)
    return "$user:[REDACTED]@$hostport"
  }

  /**
   * Port of `redact_url_for_display` (request_logging.py:216). This is the public redaction entry
   * point for URLs.
   */
  public fun redactUrlForDisplay(
      url: String,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>? = null,
      sensitiveHeaders: Set<String>? = null,
  ): String {
    val escapedUrl = escapeUrlUnsafeControls(url)
    val parts = PyUrllib.urlsplit(escapedUrl)
    val bodyFields = mergeSensitiveLogBodyFields(sensitiveBodyFields)
    val sensitive = mergedSensitiveNames(sensitiveParams, bodyFields, sensitiveHeaders)
    val maxDepth = resolveJsonDepthCap()
    val redactedPath = redactSensitivePath(parts.path, sensitive, bodyFields, maxDepth)
    if (
        parts.query.isEmpty() &&
            parts.fragment.isEmpty() &&
            '@' !in parts.netloc &&
            redactedPath == parts.path
    ) {
      return escapedUrl
    }
    val redactedQuery = redactJsonOrPairsSegment(parts.query, sensitive, bodyFields, maxDepth)
    val redactedFragment = redactJsonOrPairsSegment(parts.fragment, sensitive, bodyFields, maxDepth)
    return PyUrllib.urlunsplit(
        parts.scheme,
        redactNetlocPassword(parts.netloc),
        redactedPath,
        redactedQuery,
        redactedFragment,
    )
  }

  /** Port of the `_redact_sensitive_query_params` alias (request_logging.py:256). */
  internal fun redactSensitiveQueryParams(
      url: String,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>? = null,
      sensitiveHeaders: Set<String>? = null,
  ): String = redactUrlForDisplay(url, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)

  /** Port of `redact_endpoint_for_display` (request_logging.py:259). */
  public fun redactEndpointForDisplay(
      value: String,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>? = null,
      sensitiveHeaders: Set<String>? = null,
  ): String = redactUrlForDisplay(value, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)

  /** Port of `_XML_ELEMENT_RE` (request_logging.py:270). */
  private val XML_ELEMENT_REGEX = Regex("<([A-Za-z_][\\w.:-]*)>([^<]*)</\\1>")

  /** Port of `_redact_xml_elements` (request_logging.py:273). */
  internal fun redactXmlElements(text: String, sensitive: Set<String>): String =
      XML_ELEMENT_REGEX.replace(text) { match ->
        val name = match.groupValues[1]
        if (name.lowercase() !in sensitive) {
          match.value
        } else {
          "<$name>[REDACTED]</$name>"
        }
      }

  /** Port of `_merged_sensitive_names` (request_logging.py:283). */
  internal fun mergedSensitiveNames(
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>,
      sensitiveHeaders: Set<String>? = null,
  ): Set<String> =
      mergeSensitiveNames(DEFAULT_SENSITIVE_LOG_FIELDS, sensitiveParams) +
          sensitiveBodyFields +
          mergeSensitiveLogHeaders(sensitiveHeaders)

  /** Port of `redact_blob_for_display` (request_logging.py:295). */
  public fun redactBlobForDisplay(
      text: String,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>?,
      sensitiveHeaders: Set<String>? = null,
  ): String {
    val maxDepth = resolveJsonDepthCap()
    val bodyFields = mergeSensitiveLogBodyFields(sensitiveBodyFields)
    val sensitive = mergedSensitiveNames(sensitiveParams, bodyFields, sensitiveHeaders)
    var jsonRedacted = jsonRedactText(text, sensitive, bodyFields, maxDepth)
    if (jsonRedacted == null) {
      jsonRedacted =
          jsonRedactText(
              PairValueScan.boundedPercentDecode(text),
              sensitive,
              bodyFields,
              maxDepth,
          )
    }
    if (jsonRedacted != null) return jsonRedacted
    val xmlRedacted = redactXmlElements(text, sensitive)
    return PairRedaction.redactPairsInText(xmlRedacted, sensitive, bodyFields, maxDepth)
  }

  /** Port of `redact_header_value_for_display` (request_logging.py:317). */
  public fun redactHeaderValueForDisplay(
      value: String,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>?,
      sensitiveHeaders: Set<String>? = null,
  ): String {
    if (value.isEmpty()) return value
    return redactBlobForDisplay(value, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)
  }

  /** Port of `_extract_request_context` (request_logging.py:330). */
  private fun extractRequestContext(
      request: GuardRequest,
      sensitiveHeaders: Set<String>?,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>?,
  ): Map<String, Any?> {
    val cachedIp = IpExtraction.stateClientIp(request)
    val clientHost: String? = request.clientHost
    val clientIp =
        when {
          !cachedIp.isNullOrEmpty() -> cachedIp
          clientHost != null -> IpExtraction.canonicalizeIp(clientHost)
          else -> IpExtraction.UNKNOWN_CLIENT_IDENTITY
        }
    return linkedMapOf(
        "client_ip" to clientIp,
        "method" to request.method,
        "url" to
            redactSensitiveQueryParams(
                request.urlFull,
                sensitiveParams,
                sensitiveBodyFields,
                sensitiveHeaders,
            ),
        "headers" to
            redactSensitiveHeaders(
                request.headers,
                sensitiveHeaders,
                sensitiveBodyFields,
                sensitiveParams,
            ),
    )
  }

  /** Port of `_build_log_message_for_request` (request_logging.py:359). */
  private fun buildLogMessageForRequest(context: Map<String, Any?>): Pair<String, String> {
    val message = "Request from"
    val details = "$message ${context["client_ip"]}: ${context["method"]} ${context["url"]}"
    val reasonMessage = "Headers: ${context["headers"]}"
    return details to reasonMessage
  }

  /** Port of `_build_log_message_for_suspicious` (request_logging.py:366). */
  private fun buildLogMessageForSuspicious(
      context: Map<String, Any?>,
      reason: String,
      passiveMode: Boolean,
      triggerInfo: String,
  ): Pair<String, String> {
    if (passiveMode) {
      val message = "[PASSIVE MODE] Penetration attempt detected from"
      val details = "$message ${context["client_ip"]}: ${context["method"]} ${context["url"]}"
      val triggerMessage = if (triggerInfo.isNotEmpty()) "Trigger: $triggerInfo" else ""
      var reasonMessage = "Headers: ${context["headers"]}"
      if (triggerMessage.isNotEmpty()) {
        reasonMessage = "$triggerMessage - $reasonMessage"
      }
      return details to reasonMessage
    }
    val message = "Suspicious activity detected from"
    val details = "$message ${context["client_ip"]}: ${context["method"]} ${context["url"]}"
    val reasonMessage = "Reason: $reason - Headers: ${context["headers"]}"
    return details to reasonMessage
  }

  /** Port of `_build_log_message_generic` (request_logging.py:389). */
  private fun buildLogMessageGeneric(
      context: Map<String, Any?>,
      logType: String,
      reason: String,
  ): Pair<String, String> {
    val message = "${logType.replaceFirstChar { it.uppercaseChar() }} from"
    val details = "$message ${context["client_ip"]}: ${context["method"]} ${context["url"]}"
    val reasonMessage = "Details: $reason - Headers: ${context["headers"]}"
    return details to reasonMessage
  }

  /** Port of `_dispatch_block_hook` (request_logging.py:398). */
  private suspend fun dispatchBlockHook(
      request: GuardRequest,
      logType: String,
      checkName: String?,
      reason: String,
      triggerInfo: String,
      passiveMode: Boolean,
      onBlock: BlockHook?,
      sensitiveParams: Set<String>?,
      sensitiveBodyFields: Set<String>?,
      sensitiveHeaders: Set<String>?,
  ) {
    if (logType != "suspicious") return
    if (!passiveMode) {
      BlockEvents.setBlockStash(
          request,
          linkedMapOf(
              "reason" to reason,
              "trigger_info" to triggerInfo,
          ),
      )
      return
    }
    BlockEvents.fireBlockHook(
        onBlock,
        request,
        checkName ?: "",
        reason,
        triggerInfo,
        true,
        null,
        sensitiveParams,
        sensitiveBodyFields,
        sensitiveHeaders,
    )
  }

  /** Port of `log_activity` (request_logging.py:432). */
  public suspend fun logActivity(
      request: GuardRequest,
      logger: Logger,
      logType: String = "request",
      reason: String = "",
      passiveMode: Boolean = false,
      triggerInfo: String = "",
      level: String? = "WARNING",
      checkName: String? = null,
      mutedCheckLogs: Set<String>? = null,
      onBlock: BlockHook? = null,
      sensitiveHeaders: Set<String>? = null,
      sensitiveParams: Set<String>? = null,
      sensitiveBodyFields: Set<String>? = null,
  ) {
    dispatchBlockHook(
        request,
        logType,
        checkName,
        reason,
        triggerInfo,
        passiveMode,
        onBlock,
        sensitiveParams,
        sensitiveBodyFields,
        sensitiveHeaders,
    )
    if (level == null) return
    if (checkName != null && mutedCheckLogs != null && checkName in mutedCheckLogs) return
    val context =
        extractRequestContext(request, sensitiveHeaders, sensitiveParams, sensitiveBodyFields)
    val pair =
        when (logType) {
          "request" -> buildLogMessageForRequest(context)
          "suspicious" -> buildLogMessageForSuspicious(context, reason, passiveMode, triggerInfo)
          else -> buildLogMessageGeneric(context, logType, reason)
        }
    val msg = "${pair.first} - ${pair.second}"
    LoggingUtils.logAtLevel(logger, level, msg)
  }
}
