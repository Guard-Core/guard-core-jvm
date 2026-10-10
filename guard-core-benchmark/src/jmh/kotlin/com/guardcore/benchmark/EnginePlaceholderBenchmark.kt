package com.guardcore.benchmark

import com.guardcore.engine.GuardCoreEngine
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode

/** No-op placeholder proving the JMH wiring compiles and runs; real benches land in W1+. */
@BenchmarkMode(Mode.AverageTime)
open class EnginePlaceholderBenchmark {
  @Benchmark fun placeholder(): Int = GuardCoreEngine.VERSION.hashCode()
}
