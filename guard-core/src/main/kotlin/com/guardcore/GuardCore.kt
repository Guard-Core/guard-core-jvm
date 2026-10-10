package com.guardcore

import com.guardcore.engine.GuardCoreEngine
import kotlinx.coroutines.delay

/**
 * W0 facade placeholder. Proves the engine dependency and coroutine wiring end to end; the real
 * adapter-facing API lands in W1+.
 */
public object GuardCore {
  /** Engine version this facade is locked to (mirror-lockstep with guard-core 4.3.2). */
  public val engineVersion: String
    get() = GuardCoreEngine.VERSION

  /** Trivial suspend placeholder; kept until the real facade surface ships. */
  public suspend fun info(): String {
    delay(1)
    return "guard-core-jvm 4.3.2 (engine $engineVersion)"
  }
}
