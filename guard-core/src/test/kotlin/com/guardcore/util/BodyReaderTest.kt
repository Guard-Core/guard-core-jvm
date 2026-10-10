package com.guardcore.util

import com.guardcore.protocols.BoundedBodyReader
import com.guardcore.protocols.RequestState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking

/** Ports of tests/test_utils/test_body_inspection_cap.py (core cases). */
class BodyReaderTest {
  private open class FakeRequest(
      private val contentLength: String?,
      private val bounded: Boolean = false,
      private val bodyBytes: ByteArray = "x".repeat(64).toByteArray(),
  ) : com.guardcore.protocols.GuardRequest {
    override val urlPath = "/"
    override val urlScheme = "http"
    override val urlFull = "http://t/"
    override val method = "POST"
    override val clientHost: String? = null
    override val headers =
        if (contentLength != null) mapOf("content-length" to contentLength) else emptyMap()
    override val queryParams = emptyMap<String, String>()
    override val state: RequestState =
        object : RequestState {
          private val bag = mutableMapOf<String, Any?>()

          override fun getAttr(name: String): Any? = bag[name]

          override fun setAttr(name: String, value: Any?) {
            bag[name] = value
          }
        }
    override val scope = emptyMap<String, Any?>()

    override fun urlReplaceScheme(scheme: String) = urlFull

    override suspend fun body(): ByteArray = bodyBytes
  }

  private class BoundedRequest(
      private val maxReturn: Int,
  ) : FakeRequest(contentLength = null, bounded = true), BoundedBodyReader {
    override suspend fun readBodyPrefix(maxBytes: Int): ByteArray =
        "y".repeat(minOf(maxBytes, maxReturn)).toByteArray()
  }

  private fun config(maxBytes: Int, timeout: Double = 3.0): com.guardcore.config.SecurityConfig =
      com.guardcore.config
          .SecurityConfigBuilder()
          .apply {
            detectionMaxBodyInspectBytes = maxBytes
            bodyReadTimeout = timeout
          }
          .build()

  @Test
  fun testOversizedDeclaredBodyUsesBoundedReader() {
    runBlocking {
      val request = FakeRequest(contentLength = "100000")
      val read = BodyReader.readCappedBody(request, config(1024), "1.2.3.4")
      // No bounded reader capability: body is not read at all and null is
      // returned (body_reader.py:139-148 warning path).
      assertNull(read)
    }
  }

  @Test
  fun testWithinCapReadsFullBody() {
    runBlocking {
      val request = FakeRequest(contentLength = "64")
      val read = BodyReader.readCappedBody(request, config(1024))
      assertEquals(64, read?.size)
    }
  }

  @Test
  fun testNoContentLengthWithoutBoundedReaderYieldsNull() {
    runBlocking {
      val request = FakeRequest(contentLength = null, bounded = false)
      assertNull(BodyReader.readCappedBody(request, config(1024)))
    }
  }

  @Test
  fun testNullConfigFallsBackToPlainBodyRead() {
    runBlocking {
      val request = FakeRequest(contentLength = null, bounded = false)
      assertEquals(64, BodyReader.readCappedBody(request, null)?.size)
    }
  }

  @Test
  fun testBoundedReaderCapsThePrefix() {
    runBlocking {
      val request = BoundedRequest(maxReturn = 32)
      val read = BodyReader.readCappedBody(request, config(1024))
      assertEquals(32, read?.size)
    }
  }
}
