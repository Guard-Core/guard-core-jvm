package com.guardcore

import com.guardcore.engine.GuardCoreEngine
import kotlinx.coroutines.delay

/**
 * W0 facade placeholder. Proves the engine dependency and coroutine wiring end to end; the real
 * adapter-facing API lands in W1+.
 */
public object GuardCore {
  /** Engine version this facade is locked to (mirror-lockstep with guard-core 4.4.0). */
  public val engineVersion: String
    get() = GuardCoreEngine.VERSION

  init {
    // Facade initialization wires the handler-backed seams (geo factory G-2, cloud checker G-6);
    // python performs the same wiring lazily inside the config validators.
    com.guardcore.handlers.HandlerSeams.register()
  }

  /** Trivial suspend placeholder; kept until the real facade surface ships. */
  public suspend fun info(): String {
    delay(1)
    return "guard-core-jvm 4.4.0 (engine $engineVersion)"
  }
}
