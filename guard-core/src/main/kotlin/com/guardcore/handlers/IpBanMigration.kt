package com.guardcore.handlers

import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.IpExtraction

/**
 * Port of `guard_core/handlers/_ipban_migration.py` (IpBanMigrationMixin) as extensions over
 * [IpBanManager].
 */

/** Python `_BANNED_IPS_NAMESPACE` (_ipban_migration.py:7). */
public const val BANNED_IPS_NAMESPACE: String = "banned_ips"

/**
 * Port of `_close_if_unusable` (_ipban_migration.py:10): the Python duck-type guard for mock
 * connection managers. The JVM surface is typed ([RedisHandlerProtocol] always exposes
 * getConnection), so the guard holds; kept for call-site parity.
 */
public fun closeIfUnusable(obj: Any?, requiredAttr: String): Boolean = obj != null

/** Port of `initialize_redis` (_ipban_migration.py:22). */
public suspend fun IpBanManager.initializeBanRedis(redisHandler: RedisHandlerProtocol?) {
  this.redisHandler = redisHandler
  migrateLegacyBanKeys()
}

/** Port of `_migrate_legacy_ban_keys` (_ipban_migration.py:26). */
public suspend fun IpBanManager.migrateLegacyBanKeys() {
  val redis = redisHandler ?: return
  val prefix = "${redisPrefixOf(redis)}$BANNED_IPS_NAMESPACE:"
  val connection = redis.getConnection()
  val ops = connection.client as? RedisOperations
  if (ops == null) {
    // `_close_if_unusable`: the connection manager does not expose the usable
    // surface -> close it and skip (python logs "redis connection unavailable").
    try {
      connection.close()
    } catch (ignored: Exception) {}
    logger.warning("Legacy ban-key migration skipped: redis connection unavailable")
    return
  }
  try {
    val keys = ops.scan("$prefix*")
    for (key in keys) {
      migrateOneBanKey(redis, key, prefix)
    }
  } catch (e: Exception) {
    logger.warning("Legacy ban-key migration skipped: $e")
  }
}

/** Port of `_migrate_one_ban_key` (_ipban_migration.py:46). */
public suspend fun IpBanManager.migrateOneBanKey(
    conn: com.guardcore.protocols.RedisHandlerProtocol,
    key: String,
    prefix: String,
) {
  val rawIp = key.removePrefix(prefix)
  val canonicalIp = IpExtraction.canonicalizeIp(rawIp)
  if (canonicalIp == rawIp) {
    return
  }

  val ops = redisOperationsFor(conn)
  val pipeResult = ops.transaction { tx ->
    tx.get(key)
    tx.pTtl(key)
  }
  val value = pipeResult.getOrNull(0)?.toString()
  val oldPttl = (pipeResult.getOrNull(1) as? Number)?.toLong() ?: -1L

  if (oldPttl <= 0) {
    ops.del(key)
    return
  }

  val canonicalKey = "$prefix$canonicalIp"
  val newPttl = ops.pTtl(canonicalKey)
  if (newPttl < oldPttl) {
    ops.pSetEx(canonicalKey, value ?: "", oldPttl)
  }
  ops.del(key)
}

private fun redisOperationsFor(redis: RedisHandlerProtocol): RedisOperations =
    redis.getConnection().client as? RedisOperations
        ?: error("redis connection did not return an operations handle")
