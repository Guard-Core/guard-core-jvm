package com.guardcore.util

import com.guardcore.util.py.PyJson
import com.guardcore.util.py.PyUrllib
import java.util.IdentityHashMap
import java.util.Locale
import java.util.logging.FileHandler
import java.util.logging.Formatter
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
import java.util.logging.StreamHandler

/**
 * Port of `guard_core/_utils/logging_utils.py`: log sanitizing, the iterative sensitive-JSON
 * redaction traversal, level-mapped logging, the JSON formatter and custom logger setup.
 */
public object LoggingUtils {
  private val JSON_LEAF_START_CHARS: Set<Char> = setOf('{', '[')

  /**
   * Port of the `_json_depth_cap_hit` context var (logging_utils.py:15). The flag is set and read
   * inside a single synchronous redaction traversal, so a ThreadLocal is a faithful carrier for it
   * on the JVM.
   */
  internal val jsonDepthCapHit: ThreadLocal<Boolean> =
      object : ThreadLocal<Boolean>() {
        override fun initialValue(): Boolean = false
      }

  /**
   * Port of `_sanitize_for_log` (logging_utils.py:20): control characters become \n / \r / \t
   * escapes and every non-ASCII character becomes a backslash-u hex escape (Python formats the code
   * point, so astral code points emit five-six hex digits, exactly as the f-string does).
   */
  internal fun sanitizeForLog(value: String): String {
    if (value.isEmpty()) return value
    val sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    val out = StringBuilder(sanitized.length)
    var i = 0
    while (i < sanitized.length) {
      val ch = sanitized[i]
      when {
        // Python iterates code points; iterate the same way on the JVM.
        Character.isHighSurrogate(ch) &&
            i + 1 < sanitized.length &&
            Character.isLowSurrogate(sanitized[i + 1]) -> {
          val code = Character.toCodePoint(ch, sanitized[i + 1])
          if (code in 32..126) {
            out.appendCodePoint(code)
          } else {
            out.append("\\u").append(code.toString(16).padStart(4, '0'))
          }
          i += 2
        }
        else -> {
          val code = ch.code
          if (code in 32..126) {
            out.append(ch)
          } else {
            out.append("\\u").append(code.toString(16).padStart(4, '0'))
          }
          i++
        }
      }
    }
    return out.toString()
  }

  /**
   * Port of `_sanitize_for_reporting` (logging_utils.py:43). Python re-encodes
   * surrogateescape-decoded strings replacing unpaired surrogates with backslash escapes; on the
   * JVM strings are always valid UTF-16, so the only work is escaping lone surrogates.
   */
  internal fun sanitizeForReporting(value: String): String {
    val out = StringBuilder(value.length)
    var i = 0
    while (i < value.length) {
      val ch = value[i]
      if (
          Character.isHighSurrogate(ch) &&
              i + 1 < value.length &&
              Character.isLowSurrogate(value[i + 1])
      ) {
        out.append(ch).append(value[i + 1])
        i += 2
      } else if (Character.isSurrogate(ch)) {
        out.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
        i++
      } else {
        out.append(ch)
        i++
      }
    }
    return out.toString()
  }

  /** Port of `_nested_json_leaf_candidate` (logging_utils.py:49). */
  private fun nestedJsonLeafCandidate(value: String): String? {
    val first = value.firstOrNull() ?: return null
    if (first in JSON_LEAF_START_CHARS) return value
    if (first != '%') return null
    val decoded = PairValueScan.boundedPercentDecode(value)
    return if (decoded.firstOrNull() in JSON_LEAF_START_CHARS) decoded else null
  }

  /** Port of `_try_redact_nested_json_leaf` (logging_utils.py:58). */
  private fun tryRedactNestedJsonLeaf(
      value: String,
      leafSensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String? {
    val candidate = nestedJsonLeafCandidate(value) ?: return null
    // Python catches ValueError only (logging_utils.py:69).
    val parsed =
        try {
          PyJson.loads(candidate)
        } catch (_: PyJson.JsonDecodeError) {
          return null
        }
    val redacted = redactSensitiveJson(parsed, leafSensitive, sensitiveBodyFields, maxDepth)
    if (redacted == parsed) return null
    return PyJson.dumps(redacted, ensureAscii = false)
  }

  /** Port of `_redact_json_string_leaf` (logging_utils.py:79). */
  private fun redactJsonStringLeaf(
      value: String,
      leafSensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): String {
    val nestedJson = tryRedactNestedJsonLeaf(value, leafSensitive, sensitiveBodyFields, maxDepth)
    if (nestedJson != null) return nestedJson
    val xmlRedacted = RequestLogging.redactXmlElements(value, leafSensitive)
    return PairRedaction.redactPairsInText(
        xmlRedacted,
        leafSensitive,
        sensitiveBodyFields,
        maxDepth,
    )
  }

  /** Port of `_redact_json_child` (logging_utils.py:100). */
  private fun redactJsonChild(
      key: Any?,
      item: Any?,
      sourceIsDict: Boolean,
      depth: Int,
      maxDepth: Int,
      leafSensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      stack: MutableList<Triple<Any?, Any?, Int>>,
  ): Any? {
    if (sourceIsDict && (key?.toString()?.lowercase() ?: "") in sensitiveBodyFields) {
      return "[REDACTED]"
    }
    if (item is String) {
      return redactJsonStringLeaf(item, leafSensitive, sensitiveBodyFields, maxDepth)
    }
    if (item !is Map<*, *> && item !is List<*>) return item
    val childDepth = depth + 1
    if (childDepth >= maxDepth) {
      jsonDepthCapHit.set(true)
      return "[REDACTED]"
    }
    val child: Any = if (item is Map<*, *>) LinkedHashMap<Any?, Any?>() else ArrayList<Any?>()
    stack.add(Triple(item, child, childDepth))
    return child
  }

  /**
   * Port of `_redact_sensitive_json` (logging_utils.py:127): the iterative stack traversal that
   * redacts sensitive keys, string leaves (via nested JSON / XML / pair redaction) and containers
   * past the depth cap.
   */
  internal fun redactSensitiveJson(
      value: Any?,
      sensitive: Set<String>,
      sensitiveBodyFields: Set<String>,
      maxDepth: Int,
  ): Any? {
    if (value !is Map<*, *> && value !is List<*>) return value
    if (maxDepth <= 1) return "[REDACTED]"
    val leafSensitive: Set<String> = sensitive + sensitiveBodyFields
    val root: Any = if (value is Map<*, *>) LinkedHashMap<Any?, Any?>() else ArrayList<Any?>()
    val stack = ArrayList<Triple<Any?, Any?, Int>>()
    stack.add(Triple(value, root, 1))
    while (stack.isNotEmpty()) {
      val frame = stack.removeAt(stack.size - 1)
      val source = frame.first
      val target = frame.second
      val depth = frame.third
      val sourceIsDict = source is Map<*, *>
      val entries: List<Pair<Any?, Any?>> =
          if (sourceIsDict) {
            (source as Map<*, *>).entries.map { it.key to it.value }
          } else {
            (source as List<*>).withIndex().map { it.index to it.value }
          }
      for ((key, item) in entries) {
        val redactedItem =
            redactJsonChild(
                key,
                item,
                sourceIsDict,
                depth,
                maxDepth,
                leafSensitive,
                sensitiveBodyFields,
                stack,
            )
        when (target) {
          is MutableMap<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            (target as MutableMap<Any?, Any?>)[key] = redactedItem
          }
          is MutableList<*> -> {
            @Suppress("UNCHECKED_CAST") (target as MutableList<Any?>).add(redactedItem)
          }
        }
      }
    }
    return root
  }

  /**
   * Port of `_log_at_level` (logging_utils.py:162). Python CRITICAL maps to java.util.logging
   * SEVERE (the highest JUL level).
   */
  public fun logAtLevel(logger: Logger, level: String?, msg: String) {
    val sanitized = sanitizeForReporting(msg)
    when (level) {
      "INFO" -> logger.info(sanitized)
      "DEBUG" -> logger.fine(sanitized)
      "WARNING" -> logger.warning(sanitized)
      "ERROR" -> logger.severe(sanitized)
      "CRITICAL" -> logger.severe(sanitized)
    }
  }

  /** Port of `JsonFormatter` (logging_utils.py:176). */
  public class JsonLogFormatter : Formatter() {
    override fun format(record: LogRecord): String {
      val entry =
          linkedMapOf(
              "timestamp" to formatTime(record),
              "level" to record.level.name,
              "logger" to record.loggerName,
              "message" to record.message,
          )
      return PyJson.dumps(entry, ensureAscii = true) + System.lineSeparator()
    }
  }

  /** Mirrors logging.Formatter.formatTime: "%Y-%m-%d %H:%M:%S,mmm". */
  internal fun formatTime(record: LogRecord): String {
    val cal = java.util.Calendar.getInstance()
    cal.timeInMillis = record.millis
    return String.format(
        Locale.ROOT,
        "%04d-%02d-%02d %02d:%02d:%02d,%03d",
        cal.get(java.util.Calendar.YEAR),
        cal.get(java.util.Calendar.MONTH) + 1,
        cal.get(java.util.Calendar.DAY_OF_MONTH),
        cal.get(java.util.Calendar.HOUR_OF_DAY),
        cal.get(java.util.Calendar.MINUTE),
        cal.get(java.util.Calendar.SECOND),
        cal.get(java.util.Calendar.MILLISECOND),
    )
  }

  /**
   * The text format of logging_utils.py:192: "[%(name)s] %(asctime)s - %(levelname)s -
   * %(message)s".
   */
  public class TextGuardFormatter : Formatter() {
    override fun format(record: LogRecord): String {
      val message = formatMessage(record)
      return "[${record.loggerName}] ${formatTime(record)} - ${record.level.name} - " +
          message +
          System.lineSeparator()
    }
  }

  /** Port of `_create_formatter` (logging_utils.py:189). */
  internal fun createFormatter(logFormat: String): Formatter =
      if (logFormat == "json") JsonLogFormatter() else TextGuardFormatter()

  /**
   * Port of the `_YieldToHostRootHandlers` filter (logging_utils.py:195): let the host root logger
   * own the record when it has handlers configured. The JVM equivalent is useParentHandlers; guard
   * installs its own handlers with parent propagation disabled instead.
   */
  internal const val OWN_HANDLER_MARKER = "guard_core_installed"

  private val OWN_HANDLERS = IdentityHashMap<Any, Boolean>()

  /**
   * Port of `setup_custom_logging` (logging_utils.py:203): replace only the handlers this function
   * installed, add a console handler (and an optional file handler), and set the INFO level.
   */
  public fun setupCustomLogging(logFile: String? = null, logFormat: String = "text"): Logger {
    val logger = Logger.getLogger("guard_core")
    for (handler in logger.handlers.toList()) {
      if (isOwnHandler(handler)) {
        handler.close()
        logger.removeHandler(handler)
      }
    }
    val formatter = createFormatter(logFormat)
    val consoleHandler = ConsoleGuardHandler(formatter)
    markOwn(consoleHandler)
    logger.addHandler(consoleHandler)
    if (logFile != null) {
      try {
        val path = java.nio.file.Paths.get(logFile)
        val parent = path.parent
        if (parent != null && !java.nio.file.Files.exists(parent)) {
          java.nio.file.Files.createDirectories(parent)
        }
        val fileHandler = FileGuardHandler(logFile, formatter)
        markOwn(fileHandler)
        logger.addHandler(fileHandler)
      } catch (e: Exception) {
        logger.warning("Failed to create log file $logFile: $e")
      }
    }
    logger.level = Level.INFO
    logger.useParentHandlers = false
    return logger
  }

  private fun isOwnHandler(handler: Any): Boolean = OWN_HANDLERS.containsKey(handler)

  private fun markOwn(handler: Any) {
    OWN_HANDLERS[handler] = true
  }

  /** Console handler mirroring logging.StreamHandler (stderr stream). */
  internal class ConsoleGuardHandler(formatter: Formatter) : StreamHandler(System.err, formatter) {
    init {
      level = Level.ALL
    }

    override fun publish(record: LogRecord) {
      super.publish(record)
      flush()
    }
  }

  /** File handler mirroring logging.FileHandler (append mode). */
  internal class FileGuardHandler(
      logFile: String,
      formatter: Formatter,
  ) : FileHandler(logFile, true) {
    init {
      setFormatter(formatter)
      level = Level.ALL
    }

    override fun publish(record: LogRecord) {
      super.publish(record)
      flush()
    }
  }
}

/** Re-export of unquote for the redaction test helpers. */
internal fun pyUnquote(text: String): String = PyUrllib.unquote(text)
