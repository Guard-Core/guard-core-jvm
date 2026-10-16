package com.guardcore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking

class GuardCoreTest {
  @Test
  fun engineVersionIsPinnedInLockstep() {
    assertEquals("4.4.1", GuardCore.engineVersion)
  }

  @Test
  fun infoReportsTheLockstepEngineVersion() = runBlocking {
    assertEquals("guard-core-jvm 4.4.1 (engine 4.4.1)", GuardCore.info())
  }
}
