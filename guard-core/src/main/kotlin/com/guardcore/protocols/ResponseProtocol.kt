package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/response_protocol.py`: GuardResponse (response_protocol.py:9),
 * GuardResponseFactory (response_protocol.py:29) and BoundedResponseBodyReader
 * (response_protocol.py:55).
 */
public interface GuardResponse {
  /** Python property `status_code` (response_protocol.py:18). */
  public val statusCode: Int

  /** Python property `headers` (response_protocol.py:21); mutable. */
  public val headers: MutableMap<String, String>

  /** Python property `body` (response_protocol.py:24). */
  public val body: ByteArray?
}

/** Port of `GuardResponseFactory` (response_protocol.py:29). */
public interface GuardResponseFactory {
  /** Python method `create_response` (response_protocol.py:40). */
  public fun createResponse(content: String, statusCode: Int): GuardResponse

  /** Python method `create_redirect_response` (response_protocol.py:43). */
  public fun createRedirectResponse(url: String, statusCode: Int): GuardResponse
}

/**
 * Port of `BoundedResponseBodyReader` (response_protocol.py:55): optional capability to read a
 * size-capped prefix of the response body without disrupting delivery of the remainder to the
 * client.
 */
public interface BoundedResponseBodyReader {
  /** Python async `read_body_prefix` (response_protocol.py:117). */
  public suspend fun readBodyPrefix(maxBytes: Int): ByteArray
}
