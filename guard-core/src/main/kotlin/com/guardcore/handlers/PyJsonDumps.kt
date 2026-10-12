package com.guardcore.handlers

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Python `json.dumps` renderers for the Redis JSON blobs (byte-exact separators):
 * - pyJsonDumps: `json.dumps` defaults (", " item separator, ": " key separator, ensure_ascii).
 * - pydanticJsonDumps: pydantic v2 `model_dump_json` (compact separators, UTF-8).
 */
public object PyJsonDumps {
  /** json.dumps(obj) with default separators and ensure_ascii=True. */
  public fun dumps(element: JsonElement): String = render(element, compact = false)

  /** pydantic model_dump_json style: compact separators, non-ASCII kept as UTF-8. */
  public fun dumpsCompact(element: JsonElement): String = render(element, compact = true)

  private fun render(element: JsonElement, compact: Boolean): String {
    val itemSep = if (compact) "," else ", "
    val keySep = if (compact) ":" else ": "
    // ensure_ascii is the json.dumps default (True) while pydantic model_dump_json
    // keeps non-ASCII as UTF-8: the flag is the INVERSE of the compact selector.
    val ensureAscii = !compact
    return when (element) {
      is JsonObject ->
          element.entries.joinToString(itemSep, "{", "}") { (k, v) ->
            renderString(k, ensureAscii) + keySep + render(v, compact)
          }
      is JsonArray -> element.joinToString(itemSep, "[", "]") { render(it, compact) }
      is JsonNull -> "null"
      is JsonPrimitive ->
          if (element.isString) renderString(element.content, ensureAscii) else element.content
    }
  }

  /** json.dumps string escaping; ensure_ascii escapes non-ASCII as unicode escapes. */
  private fun renderString(text: String, ensureAscii: Boolean): String {
    val sb = StringBuilder()
    sb.append('"')
    for (ch in text) {
      when {
        ch == '"' -> sb.append("\\\"")
        ch == '\\' -> sb.append("\\\\")
        ch == '\n' -> sb.append("\\n")
        ch == '\r' -> sb.append("\\r")
        ch == '\t' -> sb.append("\\t")
        ch == '\b' -> sb.append("\\b")
        ch == '' -> sb.append("\\f")
        ch < ' ' -> sb.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
        ensureAscii && ch.code > 0x7e ->
            sb.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
        else -> sb.append(ch)
      }
    }
    sb.append('"')
    return sb.toString()
  }
}
