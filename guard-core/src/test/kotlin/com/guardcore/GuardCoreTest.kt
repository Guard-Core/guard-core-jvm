package com.guardcore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking

class GuardCoreTest {
  @Test
  fun engineVersionIsPinnedInLockstep() {
    assertEquals("4.3.2", GuardCore.engineVersion)
  }

  @Test
  fun infoReportsTheLockstepEngineVersion() = runBlocking {
    assertEquals("guard-core-jvm 4.3.2 (engine 4.3.2)", GuardCore.info())
  }
}
