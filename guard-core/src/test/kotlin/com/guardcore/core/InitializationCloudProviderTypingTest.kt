package com.guardcore.core

import com.guardcore.core.initialization.HandlerInitializer
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.RedisManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_initialization_cloud_provider_typing.py (async half; the sync-mirror
 * half is N/A by construction on the JVM - the facade's blocking bridge is the recorded idiom
 * mapping): the initializer forwards the block_cloud_providers SET to the cloud handler unmodified.
 */
class InitializationCloudProviderTypingTest {
  @Test
  fun asyncInitializerPassesSetToCloudHandler() {
    coreRunTest {
      val config = coreTestConfig {
        enableRedis = true
        lazyInit = false
        blockCloudProviders = setOf("AWS", "GCP")
      }
      // A real (unconnected) RedisManager instance: the initializer hands it to the member
      // handlers; provider-range fetch failures are swallowed by the reference's error handling.
      val redisHandler = RedisManager.getInstance(config)

      val init =
          HandlerInitializer(
              config = config,
              redisHandler = redisHandler,
          )

      val cloud = CloudManager.getInstance()
      try {
        init.initializeRedisHandlers()
      } catch (e: Exception) {
        // A dead redis endpoint must not fail the pass-through contract; the reference patches the
        // member initializers, the JVM swallows fetch errors at the same seams.
      }
      assertEquals(
          cloud.redisHandler,
          redisHandler,
          "the cloud handler must receive the initializer's redis handler",
      )
      // The provider set reached the cloud handler: one ipRanges entry per configured provider
      // (empty after the failed fetch, exactly the reference's per-provider bookkeeping).
      val touched = cloud.ipRanges.keys.filter { it == "AWS" || it == "GCP" }.toSet()
      assertEquals(setOf("AWS", "GCP"), touched, "the block_cloud_providers set must flow through")
      assertTrue(cloud.store is com.guardcore.handlers.RedisCloudIpStore)
    }
  }
}
