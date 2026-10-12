package com.guardcore.engine.py

import java.util.concurrent.Callable
import java.util.concurrent.FutureTask
import java.util.concurrent.LinkedBlockingQueue

/**
 * The shared regex scan pool.
 *
 * Port of compiler.shared_regex_executor (guard_core/detection_engine/compiler.py:20-38): the
 * reference runs regex work on a 4-worker thread pool. The JVM pool exists for a second reason:
 * java.util.regex recurses per group-repetition iteration, so the table's `(?:(?!\n).)*` scans over
 * long inputs need the large thread stack the pool carries (64 MiB, the established workaround for
 * Pattern's recursion depth). The hard match deadline (DeadlineCharSequence) aborts the match
 * inside the worker, so a catastrophic pattern never pins a pool thread - the JVM analog of the
 * reference's future-timeout.
 */
public object RegexWorkers {
  private const val WORKERS: Int = 4
  // 512 MiB of reserved (not committed) stack: java.util.regex recurses per group
  // repetition, and the 256 KiB corpus workloads drive ~256k nested frames through the
  // "negated-newline star" scans. Reservation is virtual; commit grows only as used.
  private const val STACK_SIZE_BYTES: Long = 512L * 1024 * 1024

  private val tasks = LinkedBlockingQueue<FutureTask<*>>()

  private fun workerLoop() {
    while (true) {
      // FutureTask.run captures every Throwable into the future, so the worker loop
      // cannot be killed by a task failure.
      tasks.take().run()
    }
  }

  private val started: Boolean by lazy {
    for (index in 0 until WORKERS) {
      val runnable = Runnable { workerLoop() }
      val worker = Thread(null, runnable, "guard-regex-$index", STACK_SIZE_BYTES)
      worker.isDaemon = true
      worker.start()
    }
    true
  }

  /** Submits [block] to the big-stack pool and awaits its result (rethrows failures). */
  public fun <T> submit(block: () -> T): T {
    check(started)
    val future = FutureTask(Callable { block() })
    tasks.put(future)
    return future.get()
  }
}
