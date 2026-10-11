package com.guardcore.util

import com.guardcore.engine.detection.BinaryIslands
import com.guardcore.util.py.PyUrllib

/**
 * Port of `guard_core/_utils/body_form_scan.py` (G-7c, body_form_scan.py:12-201): the urlencoded
 * form scanner and the multipart body scanner (the email.parser port is the focused
 * multipart/form-data reader below).
 */
public object BodyFormScan {
  /** Python `_FORM_FIELD_CONTEXT` / `_MULTIPART_FIELD_CONTEXT` (body_form_scan.py:12-13). */
  public const val FORM_FIELD_CONTEXT: String = "request_body:form_field"
  public const val MULTIPART_FIELD_CONTEXT: String = "request_body:multipart_field"

  /** Port of `urllib.parse.parse_qsl(..., keep_blank_values=True)` (body_form_scan.py:30). */
  private fun parseQsl(rawBody: String): List<Pair<String, String>> {
    val out = mutableListOf<Pair<String, String>>()
    for (field in rawBody.split("&")) {
      if (field.isEmpty()) continue
      val eq = field.indexOf('=')
      val name: String
      val value: String
      if (eq < 0) {
        name = PyUrllib.unquotePlus(field)
        value = ""
      } else {
        name = PyUrllib.unquotePlus(field.substring(0, eq))
        value = PyUrllib.unquotePlus(field.substring(eq + 1))
      }
      out.add(name to value)
    }
    return out
  }

  /** Python async `_scan_form_body` (body_form_scan.py:16). */
  public suspend fun scanFormBody(
      rawBody: String,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
  ): BodyJsonScan.ScanHit {
    for ((name, value) in parseQsl(rawBody)) {
      if (name.lowercase() in excludedBodyFields) {
        continue
      }
      val nameHit =
          DetectionScan.scanComponentName(
              name,
              "request_body",
              "form field name '$name'",
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
          )
      if (nameHit.first) {
        return BodyJsonScan.ScanHit(
            true,
            "Form field name '$name': ${nameHit.second}",
            nameHit.third,
        )
      }
      val hit =
          BodyContentScan.scanBodyField(
              value,
              name,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveBodyFields,
              context = FORM_FIELD_CONTEXT,
              sensitiveParams = sensitiveParams,
          )
      if (hit.detected) {
        return hit
      }
    }
    return BodyJsonScan.ScanHit.MISS
  }

  /** Python `_island_payload_entries` (body_form_scan.py:62). */
  private fun islandPayloadEntries(
      exclusionKey: String?,
      label: String,
      payload: String,
  ): List<Triple<String?, String, String>> =
      BinaryIslands.extractBinaryIslands(payload, DetectionScanBudget.binaryIslandMinRunLength())
          .map { Triple(exclusionKey, label, it) }

  /** Python `_part_payload_entries` (body_form_scan.py:71). */
  private fun partPayloadEntries(
      exclusionKey: String?,
      label: String,
      filename: String?,
      payload: String?,
  ): List<Triple<String?, String, String>> {
    if (payload == null) {
      return emptyList()
    }
    if (filename != null && BinaryIslands.valueIsBinaryLike(payload)) {
      return islandPayloadEntries(exclusionKey, label, payload)
    }
    if (payload.isEmpty()) {
      return emptyList()
    }
    return listOf(Triple(exclusionKey, label, payload))
  }

  /** One parsed multipart part: headers plus payload (the email.message.Message subset). */
  public class MultipartPart(
      public val headers: List<Pair<String, String>>,
      public val payload: String?,
  ) {
    /** Python `part.get_param("name", header="content-disposition")`. */
    public fun getParamName(): String? = contentDispositionParam("name")

    /** Python `part.get_filename()`. */
    public fun getFilename(): String? = contentDispositionParam("filename")

    private fun contentDispositionParam(param: String): String? {
      val disposition =
          headers.firstOrNull { it.first.lowercase() == "content-disposition" }?.second
              ?: return null
      // RFC 2183 parameter scan: `key=value` pairs separated by ';', values optionally quoted.
      for (segment in disposition.split(";").drop(1)) {
        val seg = segment.trim()
        val eq = seg.indexOf('=')
        if (eq <= 0) continue
        val key = seg.substring(0, eq).trim().lowercase()
        if (key != param) continue
        var value = seg.substring(eq + 1).trim()
        if (value.startsWith("\"") && value.endsWith("\"") && value.length >= 2) {
          value = value.substring(1, value.length - 1)
        }
        return value
      }
      return null
    }
  }

  /** Python `_multipart_part_entries` (body_form_scan.py:83). */
  public fun multipartPartEntries(part: MultipartPart): List<Triple<String?, String, String>> {
    val entries = mutableListOf<Triple<String?, String, String>>()
    val name = part.getParamName()
    val filename = part.getFilename()
    val exclusionKey = name
    val label = exclusionKey ?: "file"
    if (filename != null) {
      val sanitizedFilename = filename.replace("\"", "").replace("'", "")
      entries.add(Triple(exclusionKey, label, "filename=\"$sanitizedFilename\""))
    }
    for ((headerName, headerValue) in part.headers) {
      entries.add(Triple(exclusionKey, label, "$headerName: $headerValue"))
    }
    entries.addAll(partPayloadEntries(exclusionKey, label, filename, part.payload))
    return entries
  }

  /**
   * Python `_multipart_text_parts` (body_form_scan.py:102): the email.parser read over
   * `Content-Type: <content_type>` + raw body. Returns null when the body is not multipart.
   */
  public fun multipartTextParts(
      rawBody: String,
      contentType: String,
  ): List<Triple<String?, String, String>>? {
    val boundary =
        Regex("boundary=\"?([^\";]+)\"?", RegexOption.IGNORE_CASE)
            .find(contentType)
            ?.groupValues
            ?.get(1) ?: return null
    val delimiter = "--$boundary"
    val segments = rawBody.split(delimiter)
    if (segments.size < 2) {
      return null
    }
    val parts = mutableListOf<Triple<String?, String, String>>()
    for (segment in segments.drop(1)) {
      // Each segment after the delimiter starts with \r\n or - (closing marker) and runs to \r\n.
      var body = segment
      if (body.startsWith("--")) {
        break // closing boundary
      }
      body = body.removePrefix("\r\n").removePrefix("\n")
      val headerEnd = body.indexOf("\r\n\r\n")
      val sepLen = 4
      if (headerEnd < 0) {
        val altEnd = body.indexOf("\n\n")
        if (altEnd < 0) {
          continue
        }
        val headerBlock = body.substring(0, altEnd)
        val payload = body.substring(altEnd + 2).removeSuffix("\r\n").removeSuffix("\n")
        parts.addAll(multipartPartEntries(MultipartPart(parseHeaderBlock(headerBlock), payload)))
        continue
      }
      val headerBlock = body.substring(0, headerEnd)
      val payload = body.substring(headerEnd + sepLen).removeSuffix("\r\n").removeSuffix("\n")
      parts.addAll(multipartPartEntries(MultipartPart(parseHeaderBlock(headerBlock), payload)))
    }
    return parts
  }

  /** Header block parser (unfolded like email.parser over compat32). */
  private fun parseHeaderBlock(block: String): List<Pair<String, String>> {
    val headers = mutableListOf<Pair<String, String>>()
    val lines = block.split("\r\n", "\n")
    var lastKey: String? = null
    for (line in lines) {
      if (line.isEmpty()) continue
      if ((line.startsWith(" ") || line.startsWith("\t")) && lastKey != null) {
        // continuation: fold into the previous value (compat32 keeps the raw folding)
        val idx = headers.indexOfFirst { it.first == lastKey }
        if (idx >= 0) {
          headers[idx] = lastKey to (headers[idx].second + " " + line.trim())
        }
        continue
      }
      val colon = line.indexOf(':')
      if (colon <= 0) continue
      lastKey = line.substring(0, colon).trim()
      headers.add(lastKey to line.substring(colon + 1).trim())
    }
    return headers
  }

  /** Python async `_scan_multipart_part` (body_form_scan.py:120). */
  public suspend fun scanMultipartPart(
      exclusionKey: String?,
      label: String,
      value: String,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
  ): BodyJsonScan.ScanHit? {
    if (exclusionKey != null && exclusionKey.lowercase() in excludedBodyFields) {
      return null
    }
    val nameHit =
        DetectionScan.scanComponentName(
            label,
            "request_body",
            "multipart field name '$label'",
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
        )
    if (nameHit.first) {
      return BodyJsonScan.ScanHit(
          true,
          "Multipart field name '$label': ${nameHit.second}",
          nameHit.third,
      )
    }
    val hit =
        BodyContentScan.scanBodyField(
            value,
            label,
            enabledCategories,
            clientIp,
            correlationId,
            logLevel,
            sensitiveBodyFields,
            context = MULTIPART_FIELD_CONTEXT,
            sensitiveParams = sensitiveParams,
        )
    if (hit.detected) {
      return hit
    }
    return null
  }

  /** Python async `_scan_multipart_body` (body_form_scan.py:163). */
  public suspend fun scanMultipartBody(
      rawBody: String,
      contentType: String,
      excludedBodyFields: Set<String>,
      enabledCategories: Set<String>?,
      clientIp: String,
      correlationId: String,
      logLevel: String?,
      sensitiveBodyFields: Set<String> = emptySet(),
      sensitiveParams: Set<String> = emptySet(),
  ): BodyJsonScan.ScanHit {
    val parts = multipartTextParts(rawBody, contentType)
    if (parts == null) {
      return BodyContentScan.scanBlobBody(
          rawBody,
          enabledCategories,
          clientIp,
          correlationId,
          logLevel,
          forceRedacted = true,
      )
    }
    for ((exclusionKey, label, value) in parts) {
      val hit =
          scanMultipartPart(
              exclusionKey,
              label,
              value,
              excludedBodyFields,
              enabledCategories,
              clientIp,
              correlationId,
              logLevel,
              sensitiveBodyFields,
              sensitiveParams,
          )
      if (hit != null) {
        return hit
      }
    }
    return BodyJsonScan.ScanHit.MISS
  }
}
