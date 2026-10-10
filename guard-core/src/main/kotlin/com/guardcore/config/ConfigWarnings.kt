package com.guardcore.config

import java.util.logging.Logger

/**
 * Warnings emitted by SecurityConfig construction and mutation. Python uses
 * `warnings.warn(UserWarning)` (observable via pytest.warns); the JVM idiom routes them to the
 * "guard_core.models" logger at WARNING level, and the ported tests capture log records instead.
 */
public object ConfigWarnings {
  internal val logger: Logger = Logger.getLogger("guard_core.models")

  /** Python warnings.warn(UserWarning) equivalent. */
  public fun warn(message: String) {
    logger.warning(message)
  }
}
