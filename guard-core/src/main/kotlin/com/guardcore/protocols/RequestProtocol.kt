package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/request_protocol.py`: GuardRequest (request_protocol.py:9) and
 * BoundedBodyReader (request_protocol.py:85).
 */
public interface GuardRequest {
  /** Python property `url_path` (request_protocol.py:20). */
  public val urlPath: String

  /** Python property `url_scheme` (request_protocol.py:23). */
  public val urlScheme: String

  /** Python property `url_full` (request_protocol.py:26). */
  public val urlFull: String

  /** Python method `url_replace_scheme` (request_protocol.py:29). */
  public fun urlReplaceScheme(scheme: String): String

  /** Python property `method` (request_protocol.py:32). */
  public val method: String

  /** Python property `client_host` (request_protocol.py:35). */
  public val clientHost: String?

  /** Python property `headers` (request_protocol.py:38). */
  public val headers: Map<String, String>

  /** Python property `query_params` (request_protocol.py:41). */
  public val queryParams: Map<String, String>

  /**
   * Python async `body` (request_protocol.py:44). Safe to call repeatedly (cached by the adapter).
   */
  public suspend fun body(): ByteArray

  /** Python property `state` (request_protocol.py:47): per-request scratch. */
  public val state: RequestState

  /** Python property `scope` (request_protocol.py:50): the raw ASGI scope. */
  public val scope: Map<String, Any?>
}

/** Per-request scratch object standing in for the Python `request.state` bag. */
public interface RequestState {
  /** Attribute bag access mirroring Python setattr/getattr on request.state. */
  public fun getAttr(name: String): Any?

  public fun setAttr(name: String, value: Any?)
}

/**
 * Port of `BoundedBodyReader` (request_protocol.py:85): optional capability to read a size-capped
 * prefix of the request body.
 */
public interface BoundedBodyReader {
  /** Python async `read_body_prefix` (request_protocol.py:125). */
  public suspend fun readBodyPrefix(maxBytes: Int): ByteArray
}

/** True when [request] also implements the bounded-reader capability. */
public fun GuardRequest.asBoundedBodyReader(): BoundedBodyReader? = this as? BoundedBodyReader
