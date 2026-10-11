package com.guardcore.handlers

import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.protocols.RedisHandlerProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ports of the _suspatterns_registry.py custom-pattern registry surface that W3 owns (add/remove
 * with the `patterns:custom` Redis schema, restore-on-initialize, events).
 */
class SusPatternsRegistryTest {
  init {
    SusPatternsRegistry.redisHandler = null
    SusPatternsRegistry.agentHandler = null
    runTest { SusPatternsRegistry.reset() }
  }

  @Test
  fun addPatternCustomCompilesAndStores() = runTest {
    val added = SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true)
    assertTrue(added)
    assertTrue("corpuspattern-[a-z]+" in SusPatternsRegistry.getCustomPatterns())
    SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true)
  }

  @Test
  fun addPatternUnsafeRejected() = runTest {
    val added = SusPatternsRegistry.addPattern("(a+)+$", custom = true)
    assertFalse(added)
    assertFalse("(a+)+$" in SusPatternsRegistry.getCustomPatterns())
  }

  @Test
  fun addPatternCustomPersistsCommaJoinedToRedis() = runTest {
    val redis = RecordingRedis()
    SusPatternsRegistry.redisHandler = redis

    assertTrue(SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true))
    assertEquals(1, redis.setKeyCalls.size)
    val (namespace, key) = redis.setKeyCalls[0].first to redis.setKeyCalls[0].second
    assertEquals("patterns", namespace)
    assertEquals("custom", key)
    assertEquals("corpuspattern-[a-z]+", redis.setKeyCalls[0].third)

    SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true)
    SusPatternsRegistry.redisHandler = null
  }

  @Test
  fun removePatternCustomDeletesFromRedis() = runTest {
    val redis = RecordingRedis()
    SusPatternsRegistry.redisHandler = redis
    SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true)

    assertTrue(SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true))
    val last = redis.setKeyCalls.last()
    assertEquals("", last.third)
    assertFalse("corpuspattern-[a-z]+" in SusPatternsRegistry.getCustomPatterns())
    SusPatternsRegistry.redisHandler = null
  }

  @Test
  fun removePatternUnknownReturnsFalse() = runTest {
    assertFalse(SusPatternsRegistry.removePattern("never-added-xyz", custom = true))
  }

  @Test
  fun removePatternDefaultRemovesFromTable() = runTest {
    val engine = SusPatternsManager.shared()
    val savedPatterns = engine.patterns.toList()
    val savedCompiled = engine.compiledPatterns.toList()
    val before = SusPatternsRegistry.getDefaultPatterns().size
    val victim = SusPatternsRegistry.getDefaultPatterns().first()
    assertTrue(SusPatternsRegistry.removePattern(victim, custom = false))
    assertEquals(before - 1, SusPatternsRegistry.getDefaultPatterns().size)
    assertFalse(victim in SusPatternsRegistry.getDefaultPatterns())
    // The registry is process-global: restore the table byte-exact so later suites scan
    // against the full set (the reference conftest restores the pattern table per test).
    engine.patterns.clear()
    engine.patterns.addAll(savedPatterns)
    engine.compiledPatterns.clear()
    engine.compiledPatterns.addAll(savedCompiled)
    assertEquals(before, SusPatternsRegistry.getDefaultPatterns().size)
  }

  @Test
  fun initializeRedisRestoresPersistedPatterns() = runTest {
    val redis = RecordingRedis()
    redis.getKeyReturns[("patterns" to "custom")] = "corpuspattern-[a-z]+"
    SusPatternsRegistry.redisHandler = redis

    SusPatternsRegistry.initializeRedis(redis)

    assertTrue("corpuspattern-[a-z]+" in SusPatternsRegistry.getCustomPatterns())
    SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true)
    SusPatternsRegistry.redisHandler = null
  }

  @Test
  fun initializeRedisSkipsUnsafePersistedPatterns() = runTest {
    val redis = RecordingRedis()
    redis.getKeyReturns[("patterns" to "custom")] = "(a+)+$"
    SusPatternsRegistry.redisHandler = redis

    captureLogs("guard_core.handlers.suspatterns", java.util.logging.Level.WARNING) { capture ->
      SusPatternsRegistry.initializeRedis(redis)
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Skipped restoring persisted pattern")
          },
      )
    }
    assertFalse("(a+)+$" in SusPatternsRegistry.getCustomPatterns())
    SusPatternsRegistry.redisHandler = null
  }

  @Test
  fun initializeRedisWithoutHandlerIsNoop() = runTest {
    SusPatternsRegistry.redisHandler = null
    SusPatternsRegistry.initializeRedis(null)
    assertNull(SusPatternsRegistry.redisHandler)
  }

  @Test
  fun patternEventsEmitted() = runTest {
    val agent = RecordingAgent()
    SusPatternsRegistry.agentHandler = agent

    assertTrue(SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true))
    assertTrue(SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true))

    assertEquals(2, agent.events.size)
    assertEquals("pattern_added", agent.events[0]["event_type"])
    assertEquals("pattern_removed", agent.events[1]["event_type"])
    assertEquals("sus_patterns", agent.events[0]["handler_name"])
    SusPatternsRegistry.agentHandler = null
  }

  @Test
  fun getAllPatternsIncludesCustom() = runTest {
    val defaultsBefore = SusPatternsRegistry.getAllPatterns().size
    assertTrue(SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true))
    assertEquals(defaultsBefore + 1, SusPatternsRegistry.getAllPatterns().size)
    SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true)
  }

  /** The redis_interop corpus case: add_pattern writes the pinned key/value byte-exact. */
  @Test
  fun interopCustomPatternRegistryWrite() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val store = object : RedisHandlerProtocol by redis {}
      SusPatternsRegistry.redisHandler = store

      assertTrue(SusPatternsRegistry.addPattern("corpuspattern-[a-z]+", custom = true))

      val raw = redis.operations()!!.get("${config.redisPrefix}patterns:custom")
      assertEquals("corpuspattern-[a-z]+", raw)
      val ttl = redis.operations()!!.pTtl("${config.redisPrefix}patterns:custom")
      assertEquals(-1L, ttl)

      SusPatternsRegistry.removePattern("corpuspattern-[a-z]+", custom = true)
      SusPatternsRegistry.redisHandler = null
    } finally {
      redis.close()
    }
  }
}
