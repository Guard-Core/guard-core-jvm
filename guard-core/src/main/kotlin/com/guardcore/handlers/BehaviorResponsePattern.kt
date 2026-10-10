package com.guardcore.handlers

import com.guardcore.protocols.BoundedResponseBodyReader
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.BodyReader
import kotlinx.serialization.json.booleanOrNull

/**
 * Port of `guard_core/handlers/_behavior_json_pattern.py` (BehaviorJsonPatternMixin) and
 * `_behavior_response_pattern.py` (BehaviorResponsePatternMixin) as extensions over
 * [BehaviorTracker].
 */

/** Port of `_parse_pattern` (_behavior_json_pattern.py:5). */
public fun parseBehaviorPattern(pattern: String): Pair<String, String>? {
  if (!pattern.contains("==")) {
    return null
  }
  val path = pattern.substringBefore("==").trim()
  val expected = pattern.substringAfter("==").trim().trim('"', '\'')
  return path to expected
}

/** Port of `_handle_array_match` (_behavior_json_pattern.py:14). */
public fun handleBehaviorArrayMatch(current: Any?, part: String, expected: String): Boolean {
  val key = part.removeSuffix("[]")

  val map = current as? Map<*, *> ?: return false
  if (!map.containsKey(key)) {
    return false
  }

  val list = map[key] as? List<*> ?: return false

  return list.any { item -> item.toString().lowercase() == expected.lowercase() }
}

/** Port of `_traverse_json_path` (_behavior_json_pattern.py:26). */
public fun traverseBehaviorJsonPath(data: Any?, path: String): Any? {
  var current: Any? = data
  for (part in path.split(".")) {
    val map = current as? Map<*, *> ?: return null
    if (!map.containsKey(part)) {
      return null
    }
    current = map[part]
  }
  return current
}

/** Port of `_match_json_pattern` (_behavior_json_pattern.py:34). */
public fun matchBehaviorJsonPattern(data: Any?, pattern: String): Boolean {
  return try {
    val parsed = parseBehaviorPattern(pattern) ?: return false
    val (path, expected) = parsed

    var current: Any? = data
    for (part in path.split(".")) {
      if (part.endsWith("[]")) {
        return handleBehaviorArrayMatch(current, part, expected)
      }

      val map = current as? Map<*, *> ?: return false
      if (!map.containsKey(part)) {
        return false
      }
      current = map[part]
    }

    current.toString().lowercase() == expected.lowercase()
  } catch (e: Exception) {
    false
  }
}

/** Port of `_log_body_unavailable` (_behavior_response_pattern.py:24). */
public fun BehaviorTracker.logBodyUnavailable(pattern: String) {
  if (bodyUnavailableLogCache.get(pattern) != null) {
    return
  }
  bodyUnavailableLogCache[pattern] = true
  logger.warning(
      "return_pattern rule with pattern " +
          "'${DetectionScanRedaction.redactPatternSource(pattern)}' could not be evaluated: " +
          "the response does not support bounded body reading " +
          "(BoundedResponseBodyReader), so its body cannot be inspected",
  )
}

/** Port of `_read_response_body_prefix` (_behavior_response_pattern.py:37). */
public suspend fun BehaviorTracker.readResponseBodyPrefix(
    response: GuardResponse,
    pattern: String,
): ByteArray? {
  if (!config.behaviorScanResponseBody) {
    return null
  }

  val reader = response as? BoundedResponseBodyReader
  if (reader == null) {
    logBodyUnavailable(pattern)
    return null
  }

  val maxBytes = config.behaviorMaxResponseBodyInspectBytes
  val prefix =
      BodyReader.safeRead(
          { reader.readBodyPrefix(maxBytes) },
          config.bodyReadTimeout,
      )

  if (prefix == null) {
    logBodyUnavailable(pattern)
    return null
  }

  return prefix.take(maxBytes).toByteArray()
}

/** Port of `_check_response_pattern` (_behavior_response_pattern.py:58). */
public suspend fun BehaviorTracker.checkResponsePattern(
    response: GuardResponse,
    pattern: String,
): Boolean? {
  return try {
    if (pattern.startsWith("status:")) {
      val expectedStatus = pattern.substringAfter(':').toInt()
      return response.statusCode == expectedStatus
    }

    val rawBody = readResponseBodyPrefix(response, pattern)
    if (rawBody == null) {
      return null
    }

    if (rawBody.isEmpty()) {
      return false
    }

    val bodyStr = String(rawBody, Charsets.UTF_8)

    if (pattern.startsWith("json:")) {
      val jsonPattern = pattern.substringAfter(':')
      return try {
        val responseJson = PyJsonLike.parse(bodyStr)
        matchBehaviorJsonPattern(responseJson, jsonPattern)
      } catch (e: Exception) {
        false
      }
    }

    if (pattern.startsWith("regex:")) {
      val regexPattern = pattern.substringAfter(':')
      return Regex(regexPattern, RegexOption.IGNORE_CASE).containsMatchIn(bodyStr)
    }

    bodyStr.lowercase().contains(pattern.lowercase())
  } catch (e: Exception) {
    logger.severe("Error checking response pattern: $e")
    false
  }
}

internal object PyJsonLike {
  private val json = kotlinx.serialization.json.Json

  /** Python json.loads of a response body (objects become string-keyed maps). */
  fun parse(text: String): Any? = parseValue(json.parseToJsonElement(text))

  private fun parseValue(element: kotlinx.serialization.json.JsonElement): Any? =
      when (element) {
        is kotlinx.serialization.json.JsonObject ->
            element.entries.associate { (k, v) -> k to parseValue(v) }
        is kotlinx.serialization.json.JsonArray -> element.map { parseValue(it) }
        is kotlinx.serialization.json.JsonPrimitive ->
            when {
              element.isString -> element.content
              element.booleanOrNull != null -> element.booleanOrNull
              else -> element.longOrNull ?: element.doubleOrNull ?: element.content
            }
        kotlinx.serialization.json.JsonNull -> null
      }

  private val kotlinx.serialization.json.JsonPrimitive.longOrNull: Long?
    get() = content.toLongOrNull()

  private val kotlinx.serialization.json.JsonPrimitive.doubleOrNull: Double?
    get() = content.toDoubleOrNull()
}
