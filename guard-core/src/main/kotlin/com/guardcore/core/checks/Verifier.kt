package com.guardcore.core.checks

import java.util.concurrent.CompletionStage

/**
 * Port of `guard_core/core/checks/_verifier.py` (_verifier.py:7): awaits awaitable verifier
 * results. The JVM awaitable analog is [CompletionStage]; everything else passes through.
 */
public object Verifier {
  public suspend fun resolveVerifierResult(value: Any?): Any? {
    if (value is CompletionStage<*>) {
      return value.toCompletableFuture().join()
    }
    return value
  }

  /** Python truthiness for the verifier result gate (`if not result:`). */
  public fun truthy(value: Any?): Boolean =
      when (value) {
        null -> false
        is Boolean -> value
        is Number -> value.toDouble() != 0.0
        is String -> value.isNotEmpty()
        is Collection<*> -> value.isNotEmpty()
        is Map<*, *> -> value.isNotEmpty()
        is Array<*> -> value.isNotEmpty()
        else -> true
      }
}
