package fr.acinq.lightning.iceberg

import kotlin.math.ceil
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sqrt

/**
 * Statistics for the Iceberg measurements, ported from the eclair fork's IcebergBenchmark.scala.
 * Deliberately identical math: the numbers are only comparable across the two implementations if
 * the same estimator produced them.
 */
data class Stats(
    val iterations: Int,
    val meanNanos: Double,
    val medianNanos: Double,
    val stddevNanos: Double,
    val minNanos: Double,
    val maxNanos: Double,
    val p95Nanos: Double
) {
    /** Coefficient of variation (stddev/mean) -- a quick "is this measurement noisy" signal, cheap enough to always compute. */
    val cv: Double get() = if (meanNanos == 0.0) 0.0 else stddevNanos / meanNanos

    companion object {
        fun from(samples: DoubleArray): Stats {
            val n = samples.size
            require(n > 0) { "need at least 1 sample" }
            val sorted = samples.sorted()
            val mean = samples.sum() / n
            // Sample variance (Bessel's correction, n-1): these are samples of a distribution, not the distribution.
            val variance = if (n > 1) samples.sumOf { (it - mean).pow(2) } / (n - 1) else 0.0
            val median = if (n % 2 == 0) (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0 else sorted[n / 2]
            val p95Index = maxOf(0, min(n - 1, ceil(0.95 * n).toInt() - 1))
            return Stats(n, mean, median, sqrt(variance), sorted.first(), sorted.last(), sorted[p95Index])
        }

        /** Lag-1 autocorrelation of the series: how much one iteration's timing predicts the next one's. */
        fun lag1(xs: DoubleArray): Double {
            val n = xs.size
            if (n < 3) return 0.0
            val m = xs.sum() / n
            var num = 0.0
            var den = 0.0
            for (i in 0 until n) {
                val d = xs[i] - m
                den += d * d
                if (i + 1 < n) num += d * (xs[i + 1] - m)
            }
            return if (den == 0.0) 0.0 else num / den
        }

        /**
         * 95% confidence interval of the mean of [deltas], widened for lag-1 autocorrelation:
         * consecutive iterations of a state machine are not iid (JIT state, allocator state), and
         * pretending they are understates the interval. Only positive correlation widens the
         * interval; negative is clamped to zero, and the clamp at 0.95 keeps the factor finite.
         */
        fun ci95(deltas: DoubleArray): Pair<Double, Double> {
            val s = from(deltas)
            val ci95Iid = 1.96 * s.stddevNanos / sqrt(s.iterations.toDouble())
            val r = maxOf(0.0, min(0.95, lag1(deltas)))
            return Pair(ci95Iid * sqrt((1.0 + r) / (1.0 - r)), ci95Iid)
        }

        /** Nearest-rank percentile (ceil), matching the eclair side exactly. */
        fun percentile(sorted: List<Double>, q: Double): Double =
            if (sorted.isEmpty()) 0.0 else sorted[min(sorted.size - 1, maxOf(0, ceil(sorted.size * q).toInt() - 1))]
    }
}

/** Warm up until BOTH floors have elapsed: a count floor alone lets a fast machine skip warmup, a time floor alone lets a slow one. */
data class Warmup(val minIterations: Int, val minMillis: Long) {
    fun isDone(iterations: Int, elapsedNanos: Long): Boolean = iterations >= minIterations && elapsedNanos >= minMillis * 1_000_000
}

/** A volatile sink so the JIT cannot prove a timed result unused and eliminate the work that produced it (JMH Blackhole-style). */
object Sink {
    @Volatile
    var value: Any? = null
    fun consume(v: Any?) {
        value = v
    }
}
