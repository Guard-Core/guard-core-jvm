package com.guardcore.handlers

import com.guardcore.config.SecurityConfig

/** Python `ALLOWED_PREFLIGHT_REQUEST_HEADER` (cors_handler.py:6). */
public const val ALLOWED_PREFLIGHT_REQUEST_HEADER: String = "access-control-request-method"

/**
 * Port of `CorsPreflightResponse` (cors_handler.py:9): the frozen dataclass for preflight
 * responses.
 */
public class CorsPreflightResponse(
    public val statusCode: Int,
    public val headers: Map<String, String> = linkedMapOf(),
    public val body: String = "",
) {
  override fun equals(other: Any?): Boolean =
      other is CorsPreflightResponse &&
          other.statusCode == statusCode &&
          other.headers == headers &&
          other.body == body

  override fun hashCode(): Int {
    var result = statusCode
    result = result * 31 + headers.hashCode()
    result = result * 31 + body.hashCode()
    return result
  }
}

/** Port of `is_preflight` (cors_handler.py:16). */
public fun isPreflight(method: String, headers: Map<String, String>): Boolean {
  if (method.uppercase() != "OPTIONS") {
    return false
  }
  return headers.keys.any { it.lowercase() == ALLOWED_PREFLIGHT_REQUEST_HEADER }
}

private fun lowerHeaders(headers: Map<String, String>): Map<String, String> =
    headers.entries.associate { (k, v) -> k.lowercase() to v }

/**
 * Port of `guard_core/handlers/cors_handler.py` (CorsHandler): request-shape CORS decisions for
 * preflight and actual requests.
 */
public class CorsHandler(
    config: SecurityConfig,
) {
  public val config: SecurityConfig = config

  private val enabled: Boolean = config.enableCors
  private val allowAll: Boolean
  private val allowOrigins: Set<String>
  private val allowMethods: List<String>
  private val allowHeaders: List<String>
  private val allowAllHeaders: Boolean
  private val allowCredentials: Boolean
  private val maxAge: Int
  private val exposeHeaders: List<String>

  init {
    if (!enabled) {
      allowAll = false
      allowOrigins = linkedSetOf()
      allowMethods = emptyList()
      allowHeaders = emptyList()
      allowAllHeaders = false
      allowCredentials = false
      maxAge = 600
      exposeHeaders = emptyList()
    } else {
      val origins = config.corsAllowOrigins.toList()
      val wildcard = "*" in origins
      if (wildcard && config.corsAllowCredentials) {
        throw IllegalArgumentException(
            "CORS misconfiguration: wildcard origin '*' is incompatible " +
                "with cors_allow_credentials=True",
        )
      }
      allowAll = wildcard
      allowOrigins = origins.toSet()
      allowMethods = (config.corsAllowMethods.ifEmpty { listOf("GET") }).map { it.uppercase() }
      allowHeaders = config.corsAllowHeaders.map { it.lowercase() }
      allowAllHeaders = "*" in allowHeaders
      allowCredentials = config.corsAllowCredentials
      maxAge = config.corsMaxAge.takeIf { it != 0 } ?: 600
      exposeHeaders = config.corsExposeHeaders.toList()
    }
  }

  /** Port of `is_origin_allowed` (cors_handler.py:63). */
  public fun isOriginAllowed(origin: String): Boolean {
    if (!enabled) {
      return false
    }
    if (allowAll) {
      return true
    }
    return origin in allowOrigins
  }

  private fun validatePreflightOrigin(
      origin: String,
      responseHeaders: MutableMap<String, String>,
      failures: MutableList<String>,
  ) {
    if (isOriginAllowed(origin)) {
      responseHeaders["Access-Control-Allow-Origin"] =
          if (allowAll && !allowCredentials) "*" else origin
    } else {
      failures.add("origin")
    }
  }

  private fun validatePreflightMethod(requestedMethod: String, failures: MutableList<String>) {
    if (requestedMethod !in allowMethods) {
      failures.add("method")
    }
  }

  private fun validatePreflightHeaders(
      requestedHeaders: List<String>,
      requestedHeadersRaw: String,
      responseHeaders: MutableMap<String, String>,
      failures: MutableList<String>,
  ) {
    if (allowAllHeaders) {
      if (requestedHeadersRaw.isNotEmpty()) {
        responseHeaders["Access-Control-Allow-Headers"] = requestedHeadersRaw
      }
    } else if (requestedHeaders.any { it !in allowHeaders }) {
      failures.add("headers")
    }
  }

  /** Port of `build_preflight_response` (cors_handler.py:104). */
  public fun buildPreflightResponse(requestHeaders: Map<String, String>): CorsPreflightResponse {
    val headers = lowerHeaders(requestHeaders)
    val origin = headers["origin"] ?: ""
    val requestedMethod = (headers["access-control-request-method"] ?: "").uppercase()
    val requestedHeadersRaw = headers["access-control-request-headers"] ?: ""
    val requestedHeaders =
        requestedHeadersRaw.split(",").mapNotNull { piece ->
          val trimmed = piece.trim().lowercase()
          trimmed.ifEmpty { null }
        }

    val failures = mutableListOf<String>()
    val responseHeaders = linkedMapOf<String, String>("Vary" to "Origin")

    validatePreflightOrigin(origin, responseHeaders, failures)
    validatePreflightMethod(requestedMethod, failures)
    validatePreflightHeaders(requestedHeaders, requestedHeadersRaw, responseHeaders, failures)

    responseHeaders["Access-Control-Allow-Methods"] = allowMethods.joinToString(", ")
    responseHeaders["Access-Control-Max-Age"] = maxAge.toString()

    if (allowCredentials) {
      responseHeaders["Access-Control-Allow-Credentials"] = "true"
    }

    return if (failures.isNotEmpty()) {
      CorsPreflightResponse(
          statusCode = 400,
          headers = responseHeaders,
          body = "Disallowed CORS: ${failures.joinToString(", ")}",
      )
    } else {
      CorsPreflightResponse(statusCode = 200, headers = responseHeaders, body = "OK")
    }
  }

  /** Port of `build_response_headers` (cors_handler.py:144). */
  public fun buildResponseHeaders(requestHeaders: Map<String, String>): Map<String, String> {
    if (!enabled) {
      return linkedMapOf()
    }
    val headers = lowerHeaders(requestHeaders)
    val origin = headers["origin"] ?: ""
    if (origin.isEmpty()) {
      return linkedMapOf()
    }

    val result = linkedMapOf<String, String>("Vary" to "Origin")

    if (allowAll && !allowCredentials) {
      result["Access-Control-Allow-Origin"] = "*"
    } else if (isOriginAllowed(origin)) {
      result["Access-Control-Allow-Origin"] = origin
    } else {
      return linkedMapOf()
    }

    if (allowCredentials) {
      result["Access-Control-Allow-Credentials"] = "true"
    }

    if (exposeHeaders.isNotEmpty()) {
      result["Access-Control-Expose-Headers"] = exposeHeaders.joinToString(", ")
    }

    return result
  }
}
