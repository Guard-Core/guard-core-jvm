package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/redis_protocol.py` (redis_protocol.py:8): the namespaced async
 * key-value store every handler that persists shared state resolves through.
 */
public interface RedisHandlerProtocol {
  /** Python async `get_key` (redis_protocol.py:20). */
  public suspend fun getKey(namespace: String, key: String): Any?

  /** Python async `set_key` (redis_protocol.py:23). */
  public suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int? = null): Boolean?

  /** Python async `delete` (redis_protocol.py:34). */
  public suspend fun delete(namespace: String, key: String): Int?

  /** Python async `keys` (redis_protocol.py:38). */
  public suspend fun keys(pattern: String): List<String>?

  /** Python async `initialize` (redis_protocol.py:42). */
  public suspend fun initialize()

  /**
   * Python sync `get_connection` (redis_protocol.py:45) returns an async context manager yielding
   * the raw client; the JVM idiom is a closeable handle exposing the client.
   */
  public fun getConnection(): GuardRedisConnection
}

/** JVM idiom mapping for the Python `AsyncContextManager[Any]` yield value. */
public interface GuardRedisConnection : AutoCloseable {
  /** The raw client handle for operations outside this protocol. */
  public val client: Any?
}
