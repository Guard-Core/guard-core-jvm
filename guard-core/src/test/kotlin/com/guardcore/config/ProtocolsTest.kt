package com.guardcore.config

import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.BoundedBodyReader
import com.guardcore.protocols.BoundedResponseBodyReader
import com.guardcore.protocols.CloudIpStoreFactory
import com.guardcore.protocols.CloudIpStoreProtocol
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.GuardResponse
import com.guardcore.protocols.GuardResponseFactory
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.protocols.RequestState
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Ports of tests/test_protocols/: every protocol is implementable by a framework adapter and
 * exposes the full member surface.
 */
class ProtocolsTest {
  private class FakeRedis : RedisHandlerProtocol {
    override suspend fun getKey(namespace: String, key: String): Any? = null

    override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean =
        true

    override suspend fun delete(namespace: String, key: String): Int = 1

    override suspend fun keys(pattern: String): List<String> = emptyList()

    override suspend fun initialize() {}

    override fun getConnection(): GuardRedisConnection =
        object : GuardRedisConnection {
          override val client: Any? = null

          override fun close() {}
        }
  }

  private class FakeAgent : AgentHandlerProtocol {
    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun sendEvent(event: Any?) {}

    override suspend fun sendMetric(metric: Any?) {}

    override suspend fun start() {}

    override suspend fun stop() {}

    override suspend fun flushBuffer() {}

    override suspend fun getDynamicRules(): Any? = null

    override suspend fun healthCheck(): Boolean = true
  }

  private class FakeGeo : GeoIPHandler {
    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

    override suspend fun initializeAgent(agentHandler: AgentHandlerProtocol) {}

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  private class FakeResponse : GuardResponse {
    override val statusCode: Int = 403
    override val headers: MutableMap<String, String> = mutableMapOf()
    override val body: ByteArray? = null
  }

  private class FakeFactory : GuardResponseFactory {
    override fun createResponse(content: String, statusCode: Int): GuardResponse = FakeResponse()

    override fun createRedirectResponse(url: String, statusCode: Int): GuardResponse =
        FakeResponse()
  }

  private class FakeMiddleware : GuardMiddlewareProtocol {
    override val config: SecurityConfig = SecurityConfigBuilder().build()
    override val logger: Logger = Logger.getLogger("test")
    override val lastCloudIpRefresh: Int = 0
    override val suspiciousRequestCounts: MutableMap<String, MutableMap<String, Int>> =
        mutableMapOf()
    override val eventBus: Any? = null
    override val routeResolver: Any? = null
    override val responseFactory: Any? = null
    override val rateLimitHandler: Any? = null
    override val agentHandler: AgentHandlerProtocol? = null
    override val geoIpHandler: GeoIPHandler? = null
    override val guardResponseFactory: GuardResponseFactory? = null

    override suspend fun createErrorResponse(
        statusCode: Int,
        defaultMessage: String,
    ): GuardResponse = FakeResponse()

    override suspend fun refreshCloudIpRanges() {}
  }

  private class FakeBoundedRequest : BoundedBodyReader {
    override suspend fun readBodyPrefix(maxBytes: Int): ByteArray = ByteArray(0)
  }

  private class FakeBoundedResponse : BoundedResponseBodyReader {
    override suspend fun readBodyPrefix(maxBytes: Int): ByteArray = ByteArray(0)
  }

  @Test
  fun testProtocolsAreImplementable() {
    kotlinx.coroutines.runBlocking {
      val redis: RedisHandlerProtocol = FakeRedis()
      val agent: AgentHandlerProtocol = FakeAgent()
      val geo: GeoIPHandler = FakeGeo()
      val factory: GuardResponseFactory = FakeFactory()
      val middleware: GuardMiddlewareProtocol = FakeMiddleware()
      val boundedRequest: BoundedBodyReader = FakeBoundedRequest()
      val boundedResponse: BoundedResponseBodyReader = FakeBoundedResponse()
      val cloudFactory: CloudIpStoreFactory = { _ ->
        object : CloudIpStoreProtocol {
          override suspend fun get(provider: String): Set<String>? = null

          override suspend fun set(provider: String, ranges: Set<String>, ttl: Int?) {}

          override suspend fun clear() {}
        }
      }
      assertTrue(redis.getConnection() is GuardRedisConnection)
      assertTrue(agent.healthCheck()::class.simpleName != null)
      assertTrue(geo.getCountry("1.2.3.4") == null)
      assertTrue(factory.createResponse("x", 403).statusCode == 403)
      assertTrue(middleware.config is SecurityConfig)
      assertTrue(boundedRequest.readBodyPrefix(1)::class.simpleName != null)
      assertTrue(boundedResponse.readBodyPrefix(1)::class.simpleName != null)
      assertTrue(cloudFactory(redis) is CloudIpStoreProtocol)
    }
  }

  @Test
  fun testRequestStateSurface() {
    val state =
        object : RequestState {
          private val bag = mutableMapOf<String, Any?>()

          override fun getAttr(name: String): Any? = bag[name]

          override fun setAttr(name: String, value: Any?) {
            bag[name] = value
          }
        }
    state.setAttr("client_ip", "1.2.3.4")
    assertEquals("1.2.3.4", state.getAttr("client_ip"))
  }
}
