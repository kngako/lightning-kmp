package fr.acinq.lightning.iceberg

import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.channel.LNChannel
import fr.acinq.lightning.channel.TestsHelper
import fr.acinq.lightning.channel.states.Normal
import fr.acinq.lightning.crypto.FundingSigner
import fr.acinq.lightning.crypto.IcebergFundingSigner
import fr.acinq.lightning.crypto.IcebergSigner
import fr.acinq.lightning.utils.msat
import java.io.File
import java.io.PrintWriter
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random
import kotlin.math.abs
import kotlin.system.measureNanoTime

/**
 * The direct, paired measurement of what one Iceberg group-backed funding signer costs per payment,
 * ported from the eclair fork's IcebergCycleMeasurementRun.scala.
 *
 * WHAT IS MEASURED. Two channels are open simultaneously: a bare one (stock private-key funding
 * signer) and one whose Bob side is an Iceberg t-of-n group. Each iteration pays once on each, back
 * to back, with the order counterbalanced, and the DELTA is computed per-iteration -- not as a
 * difference of means -- so both halves of every comparison see identical machine state (JIT,
 * allocator, GC, frequency scaling). The delta is the measured quantity; the absolute cycle times
 * are context.
 *
 * DO NOT PARALLELISE THIS, and do not run it alongside anything else on the machine. It is a timing
 * measurement; the paired design works precisely because concurrent load would reintroduce exactly
 * the variance the design removes.
 *
 * A payment cycle is: makeCmdAdd -> addHtlc -> crossSign (1st commitment_signed/revoke_and_ack
 * round) -> fulfillHtlc -> crossSign (2nd round). The group side's signer calls (and only those)
 * are timed separately by [TimingFundingSigner], giving group_crypto_us / bare_crypto_us /
 * net_crypto_us, and residual_us = added_us - net_crypto_us, which should be near zero: the whole
 * added cost should be the signer swap.
 *
 * Balance is recycled by one UNTIMED reverse payment every [RecycleEvery] cycles, with counting and
 * timing paused (that crypto is real work but not the timed payment's), followed by a GC settle so
 * recycling never lands in a timed region.
 *
 * Usage: IcebergCycleMeasurementRun <output-dir>
 * System properties: -Diceberg.iterations=1500 -Diceberg.iterations.aux=500
 *                    -Diceberg.grid=full|sparse|headline -Diceberg.grid.seed=20260829
 *                    -Diceberg.warmup.iterations=20 -Diceberg.warmup.millis=500
 */
object IcebergCycleMeasurementRun {

    private val PaymentAmount = 1_000_000.msat // 1,000 sat, as on the eclair side
    private const val RecycleEvery = 100

    /** The stages of one payment cycle. `whole` is the total; `make_cmd_add` is command construction, excluded from "channel work". */
    private val Stages = listOf("make_cmd_add", "add_htlc", "cross_sign_1", "fulfill_htlc", "cross_sign_2", "whole")

    private data class Config(val t: Int, val n: Int) {
        val quorum: Int = 2 * t - 1
        override fun toString(): String = "$t-of-$n"
    }

    /** The legal grid: t in 2..5, n in (2t-1)..10, subject to t <= (n+1)/2 (2-of-2 and 3-of-4 are inexpressible). */
    private val FullGrid: List<Config> = (2..5).flatMap { t -> (2 * t - 1..10).filter { n -> t <= (n + 1) / 2 }.map { n -> Config(t, n) } }
    private val SparseGrid: List<Config> = (2..5).flatMap { t -> listOf(2 * t - 1, (2 * t - 1 + 10) / 2, 10).distinct().filter { n -> t <= (n + 1) / 2 && n <= 10 }.map { n -> Config(t, n) } }
    private val HeadlineGrid = listOf(Config(2, 4), Config(3, 7))

    /**
     * Wraps a [FundingSigner] and times (in addition to counting, via [CountingFundingSigner]) the
     * group operations a channel asks for. Counting and timing pause during the untimed
     * balance-restoring reverse payments (see the recycle step in the main loop): that crypto is
     * real work but not the timed payment's, so it must not land in the crypto totals.
     */
    private class TimingFundingSigner(underlying: FundingSigner) : CountingFundingSigner(underlying) {
        private val nanos = AtomicLong(0)
        private val calls = AtomicLong(0)
        private val counting = AtomicBoolean(true)

        fun pauseCounting() = counting.set(false)
        fun resumeCounting() = counting.set(true)

        // Time only the wrapped call; the base's per-method counters and round split are reused.
        override fun <A> record(counter: AtomicLong, call: () -> A): A {
            if (!counting.get()) return call()
            val t0 = System.nanoTime()
            try {
                return call()
            } finally {
                nanos.addAndGet(System.nanoTime() - t0)
                calls.incrementAndGet()
                counter.incrementAndGet()
            }
        }

        val totalNanos: Long get() = nanos.get()
        val totalCalls: Long get() = calls.get()
        fun reset() {
            nanos.set(0); calls.set(0); resetCounts()
        }
    }

    /** One side of the comparison: a pair of channels plus the (timed) signer on bob's side. */
    private class Arm(val alice: LNChannel<Normal>, val bob: LNChannel<Normal>, val signer: TimingFundingSigner)

    /** One payment cycle on [arm], returning the new channel states and per-stage nanoseconds. */
    private fun payCycle(arm: Arm): Pair<Arm, Map<String, Long>> {
        val stages = LinkedHashMap<String, Long>()
        var mark = System.nanoTime()
        fun lap(name: String) {
            val now = System.nanoTime()
            stages[name] = now - mark
            mark = now
        }
        val preimage = randomBytes32()
        val (_, cmdAdd) = TestsHelper.makeCmdAdd(PaymentAmount, arm.bob.staticParams.nodeParams.nodeId, arm.alice.currentBlockHeight.toLong(), preimage)
        lap("make_cmd_add")
        val (alice1, bob1, htlc) = TestsHelper.addHtlc(cmdAdd, arm.alice, arm.bob)
        lap("add_htlc")
        val (alice2, bob2) = TestsHelper.crossSign(alice1, bob1)
        lap("cross_sign_1")
        val (alice3, bob3) = TestsHelper.fulfillHtlc(htlc.id, preimage, alice2, bob2)
        lap("fulfill_htlc")
        val (bob4, alice4) = TestsHelper.crossSign(bob3, alice3)
        lap("cross_sign_2")
        stages["whole"] = stages.values.sum()
        Sink.consume(alice4.commitments.localCommitIndex + bob4.commitments.localCommitIndex)
        return Pair(Arm(alice4, bob4, arm.signer), stages)
    }

    /** One UNTIMED reverse payment (bob -> alice) that repays what the last [cycles] forward payments moved, with signer counting/timing paused. */
    private fun recycle(arm: Arm, cycles: Int): Arm {
        arm.signer.pauseCounting()
        try {
            val recycleAmount = (PaymentAmount.msat * cycles).msat
            val preimage = randomBytes32()
            val (_, cmdAdd) = TestsHelper.makeCmdAdd(recycleAmount, arm.alice.staticParams.nodeParams.nodeId, arm.bob.currentBlockHeight.toLong(), preimage)
            val (bob1, alice1, htlc) = TestsHelper.addHtlc(cmdAdd, arm.bob, arm.alice)
            val (bob2, alice2) = TestsHelper.crossSign(bob1, alice1)
            val (bob3, alice3) = TestsHelper.fulfillHtlc(htlc.id, preimage, bob2, alice2)
            val (alice4, bob4) = TestsHelper.crossSign(alice3, bob3)
            Sink.consume(alice4.commitments.localCommitIndex)
            return Arm(alice4, bob4, arm.signer)
        } finally {
            arm.signer.resumeCounting()
        }
    }

    /** A GC settle after recycling, so the recycling GC never lands in a timed region. */
    private fun quiesce() {
        System.gc()
        Thread.sleep(50)
    }

    private fun openBareArm(): Arm {
        // The bare arm's signer is wrapped too, so bare crypto is measured, not inferred. The
        // injected key is just a fresh private key: the channel takes its funding pubkey from it.
        val signer = TimingFundingSigner(FundingSigner.PrivateKeyFundingSigner(randomKey()))
        val (alice, bob, _) = TestsHelper.reachNormal(bobFundingSigner = signer)
        return Arm(alice, bob, signer)
    }

    private fun openGroupArm(config: Config): Arm {
        val group = IcebergSigner.keygen(config.n, config.t, randomBytes32().toByteArray())
        val signer = TimingFundingSigner(IcebergFundingSigner(group))
        val (alice, bob, _) = TestsHelper.reachNormal(bobFundingSigner = signer)
        return Arm(alice, bob, signer)
    }

    /** Warm up until both floors of [warmup] have elapsed, paying on both arms; signers are reset afterwards by the caller. */
    private fun warmUp(bare: Arm, group: Arm, warmup: Warmup): Pair<Arm, Arm> {
        var b = bare
        var g = group
        val t0 = System.nanoTime()
        var i = 0
        while (!warmup.isDone(i, System.nanoTime() - t0)) {
            b = payCycle(b).first
            g = payCycle(g).first
            i += 1
            if (i % RecycleEvery == 0) {
                b = recycle(b, RecycleEvery); g = recycle(g, RecycleEvery); quiesce()
            }
        }
        return Pair(b, g)
    }

    /**
     * Global JVM warmup before ANY measurement: batches of payments until the per-cycle time
     * stabilizes within 2%, so the first configuration measured is not systematically slower.
     */
    private fun warmUpJvm() {
        println("warming up the JVM (until per-cycle time stabilizes within 2%, max 8 batches of 40)")
        var arm = openBareArm()
        var previous = Double.MAX_VALUE
        for (batch in 1..8) {
            val nanos = measureNanoTime {
                repeat(40) { arm = payCycle(arm).first }
                arm = recycle(arm, 40)
            }
            val perCycle = nanos / 40.0
            val drift = abs(perCycle - previous) / previous
            println("  batch $batch: ${perCycle / 1000.0} us/cycle (drift ${fmt1(drift * 100)}%)")
            if (drift < 0.02) return
            previous = perCycle
        }
    }

    private fun us(nanos: Double): Double = nanos / 1000.0

    // CSVs must use a dot decimal separator regardless of the machine's locale.
    private fun fmt1(x: Double): String = String.format(Locale.ROOT, "%.1f", x)
    private fun fmt2(x: Double): String = String.format(Locale.ROOT, "%.2f", x)
    private fun fmt3(x: Double): String = String.format(Locale.ROOT, "%.3f", x)
    private fun fmt4(x: Double): String = String.format(Locale.ROOT, "%.4f", x)

    @JvmStatic
    fun main(args: Array<String>) {
        val iterations = System.getProperty("iceberg.iterations", "1500").toInt()
        val auxIterations = System.getProperty("iceberg.iterations.aux", "500").toInt()
        val warmup = Warmup(
            System.getProperty("iceberg.warmup.iterations", "20").toInt(),
            System.getProperty("iceberg.warmup.millis", "500").toLong()
        )
        val gridArg = System.getProperty("iceberg.grid", "full")
        val gridSeed = System.getProperty("iceberg.grid.seed", "20260829").toLong()
        val grid = when (gridArg) {
            "full" -> FullGrid
            "sparse" -> SparseGrid
            "headline" -> HeadlineGrid
            else -> throw IllegalArgumentException("unknown -Diceberg.grid=$gridArg (expected full, sparse or headline)")
        }.shuffled(Random(gridSeed))

        val dir = File(args.getOrElse(0) { defaultOutputDir() })
        dir.mkdirs()
        println("output -> ${dir.absolutePath}")

        // ---- cold stage pass: the bare arm before any warmup -----------------------------------
        // What a payment costs before the JIT has seen the code, per stage. Compared against
        // cycle_stages_bare_warm.csv it shows how much of the cycle is warmup artifact.
        run {
            var arm = openBareArm()
            val samples = Stages.associateWith { ArrayList<Double>() }
            repeat(auxIterations) {
                val r = payCycle(arm)
                arm = r.first
                r.second.forEach { (s, ns) -> samples.getValue(s).add(ns.toDouble()) }
                if ((it + 1) % RecycleEvery == 0) {
                    arm = recycle(arm, RecycleEvery); quiesce()
                }
            }
            writeStages(File(dir, "cycle_stages_bare.csv"), samples.mapValues { Stats.from(it.value.toDoubleArray()) })
        }

        // ---- warm stage pass: same thing, JIT warm ----------------------------------------------
        warmUpJvm()
        run {
            var arm = openBareArm()
            val w = warmUp(arm, arm, warmup) // warming one arm twice is fine; it is the same code
            arm = w.first
            val samples = Stages.associateWith { ArrayList<Double>() }
            repeat(auxIterations) {
                val r = payCycle(arm)
                arm = r.first
                r.second.forEach { (s, ns) -> samples.getValue(s).add(ns.toDouble()) }
                if ((it + 1) % RecycleEvery == 0) {
                    arm = recycle(arm, RecycleEvery); quiesce()
                }
            }
            writeStages(File(dir, "cycle_stages_bare_warm.csv"), samples.mapValues { Stats.from(it.value.toDoubleArray()) })
        }

        // ---- the paired grid ---------------------------------------------------------------------
        val costOut = PrintWriter(File(dir, "cost_per_payment.csv"))
        costOut.println("t,n,quorum,bare_us,iceberg_us,added_us,ci95_us,ci95_iid_us,autocorr_lag1,median_us,p95_us,p99_us,resolved,pct_of_full_cycle,pct_of_channel_work,group_crypto_us,bare_crypto_us,net_crypto_us,residual_us,signer_calls_per_payment,round_one_calls_per_payment,round_two_calls_per_payment,redundant_round_one_calls_per_payment,iterations")
        val samplesOut = PrintWriter(File(dir, "paired_samples.csv"))
        samplesOut.println("t,n,iteration,bare_us,iceberg_us,delta_us")

        var bareCycleMeanNanos = 0.0
        var bareChannelWorkNanos = 0.0
        for (config in grid) {
            println("=== $config (quorum ${config.quorum}) ===")
            var bare = openBareArm()
            var group = openGroupArm(config)
            val w = warmUp(bare, group, warmup)
            bare = w.first; group = w.second
            bare.signer.reset(); group.signer.reset()

            val bareSamples = ArrayList<Double>(iterations)
            val groupSamples = ArrayList<Double>(iterations)
            val deltaSamples = ArrayList<Double>(iterations)
            for (i in 0 until iterations) {
                val bareFirst = i % 2 == 0
                if (bareFirst) {
                    val rb = payCycle(bare); bare = rb.first
                    val rg = payCycle(group); group = rg.first
                    val b = rb.second.getValue("whole").toDouble()
                    val g = rg.second.getValue("whole").toDouble()
                    bareSamples.add(b); groupSamples.add(g); deltaSamples.add(g - b)
                    samplesOut.println("${config.t},${config.n},$i,${fmt1(us(b))},${fmt1(us(g))},${fmt1(us(g - b))}")
                } else {
                    val rg = payCycle(group); group = rg.first
                    val rb = payCycle(bare); bare = rb.first
                    val b = rb.second.getValue("whole").toDouble()
                    val g = rg.second.getValue("whole").toDouble()
                    bareSamples.add(b); groupSamples.add(g); deltaSamples.add(g - b)
                    samplesOut.println("${config.t},${config.n},$i,${fmt1(us(b))},${fmt1(us(g))},${fmt1(us(g - b))}")
                }
                if ((i + 1) % RecycleEvery == 0) {
                    bare = recycle(bare, RecycleEvery); group = recycle(group, RecycleEvery); quiesce()
                }
            }

            val bareStats = Stats.from(bareSamples.toDoubleArray())
            val groupStats = Stats.from(groupSamples.toDoubleArray())
            val deltas = deltaSamples.toDoubleArray()
            val deltaStats = Stats.from(deltas)
            val added = deltaStats.meanNanos
            val (ci95, ci95Iid) = Stats.ci95(deltas)
            val lag1Delta = Stats.lag1(deltas)
            val sortedDeltas = deltas.sorted()
            val resolved = abs(added) > ci95
            val groupCryptoUs = us(group.signer.totalNanos.toDouble() / iterations)
            val bareCryptoUs = us(bare.signer.totalNanos.toDouble() / iterations)
            val netCryptoUs = groupCryptoUs - bareCryptoUs
            val residualUs = us(added) - netCryptoUs
            // NB: the pct_of_* columns are written as 0.0 here and recomputed by
            // fillPercentageColumns once the stage pass has produced the denominators.
            costOut.println(
                "${config.t},${config.n},${config.quorum},${fmt1(us(bareStats.meanNanos))},${fmt1(us(groupStats.meanNanos))}," +
                    "${fmt1(us(added))},${fmt1(ci95 / 1000.0)},${fmt1(ci95Iid / 1000.0)},${fmt3(lag1Delta)}," +
                    "${fmt1(us(Stats.percentile(sortedDeltas, 0.50)))},${fmt1(us(Stats.percentile(sortedDeltas, 0.95)))},${fmt1(us(Stats.percentile(sortedDeltas, 0.99)))}," +
                    "$resolved,${fmt2(0.0)},${fmt2(0.0)}," +
                    "${fmt1(groupCryptoUs)},${fmt1(bareCryptoUs)},${fmt1(netCryptoUs)},${fmt1(residualUs)}," +
                    "${fmt2(group.signer.totalCalls.toDouble() / iterations)},${fmt2(group.signer.roundOneCalls.toDouble() / iterations)}," +
                    "${fmt2(group.signer.roundTwoCalls.toDouble() / iterations)},${fmt2(group.signer.redundantRoundOneCalls.toDouble() / iterations)},$iterations"
            )
            costOut.flush() // a long grid must survive a crash at the last configuration
            println("   added ${fmt1(us(added))} us/payment (ci95 ${fmt1(ci95 / 1000.0)}), crypto net ${fmt1(netCryptoUs)} us, residual ${fmt1(residualUs)} us")
        }
        samplesOut.close()

        // ---- paired stage pass at the headline 3-of-7 configuration --------------------------------
        run {
            val config = Config(3, 7)
            println("=== paired stage pass at $config ===")
            var bare = openBareArm()
            var group = openGroupArm(config)
            val w = warmUp(bare, group, warmup)
            bare = w.first; group = w.second
            val paired = Stages.associateWith { Triple(ArrayList<Double>(), ArrayList<Double>(), ArrayList<Double>()) }
            val stageSamplesOut = PrintWriter(File(dir, "paired_stage_samples.csv"))
            stageSamplesOut.println("iteration,stage,bare_us,group_us,delta_us")
            repeat(auxIterations) { i ->
                val rb = payCycle(bare); bare = rb.first
                val rg = payCycle(group); group = rg.first
                Stages.forEach { s ->
                    val (bs, gs, ds) = paired.getValue(s)
                    val b = rb.second.getValue(s).toDouble(); val g = rg.second.getValue(s).toDouble()
                    bs.add(b); gs.add(g); ds.add(g - b)
                    stageSamplesOut.println("$i,$s,${fmt1(us(b))},${fmt1(us(g))},${fmt1(us(g - b))}")
                }
                if ((i + 1) % RecycleEvery == 0) {
                    bare = recycle(bare, RecycleEvery); group = recycle(group, RecycleEvery); quiesce()
                }
            }
            stageSamplesOut.close()
            writeStages(File(dir, "cycle_stages_group.csv"), Stages.associateWith { s -> Stats.from(paired.getValue(s).second.toDoubleArray()) })
            writeStages(File(dir, "cycle_stages_paired_bare.csv"), Stages.associateWith { s -> Stats.from(paired.getValue(s).first.toDoubleArray()) })
            val w2 = PrintWriter(File(dir, "cycle_stages_paired.csv"))
            w2.println("stage,iterations,bare_mean_us,group_mean_us,delta_mean_us,delta_ci95_us,delta_ci95_iid_us,autocorr_lag1,delta_median_us,delta_p95_us")
            Stages.forEach { s ->
                val ds = paired.getValue(s).third.toDoubleArray()
                val (ci95, ci95Iid) = Stats.ci95(ds)
                val stats = Stats.from(ds)
                w2.println("$s,${stats.iterations},${fmt1(us(Stats.from(paired.getValue(s).first.toDoubleArray()).meanNanos))},${fmt1(us(Stats.from(paired.getValue(s).second.toDoubleArray()).meanNanos))},${fmt1(us(stats.meanNanos))},${fmt1(ci95 / 1000.0)},${fmt1(ci95Iid / 1000.0)},${fmt3(Stats.lag1(ds))},${fmt1(us(stats.medianNanos))},${fmt1(us(stats.p95Nanos))}")
            }
            w2.close()
            // Now that the warm bare-arm stage split exists, the percentage columns of the grid can
            // be computed against the real denominators.
            val bareWhole = paired.getValue("whole").first
            val bareMakeCmdAdd = paired.getValue("make_cmd_add").first
            bareCycleMeanNanos = bareWhole.average()
            bareChannelWorkNanos = bareCycleMeanNanos - bareMakeCmdAdd.average()
        }
        costOut.close()

        // The percentage columns were written with 0.0 placeholders during the grid loop (the
        // denominators are only known after the stage pass): rewrite them now.
        fillPercentageColumns(File(dir, "cost_per_payment.csv"), us(bareCycleMeanNanos), us(bareChannelWorkNanos))

        writeProvenance(File(dir, "provenance.txt"), iterations, auxIterations, warmup, gridArg, gridSeed, grid)
        writeReadme(File(dir, "README.md"), iterations, auxIterations, gridArg)
        // A partial directory looks exactly like a complete one, because rows are flushed as they are
        // produced. This is the only thing that distinguishes them.
        File(dir, "COMPLETE").writeText("all ${grid.size} configurations measured\n")
        println("done: ${grid.size} configurations, $iterations paired iterations each")
    }

    private fun writeStages(file: File, stages: Map<String, Stats>) {
        val w = PrintWriter(file)
        w.println("stage,iterations,mean_us,median_us,stddev_us,min_us,max_us,p95_us,cv")
        Stages.forEach { s ->
            val x = stages.getValue(s)
            w.println("$s,${x.iterations},${fmt1(us(x.meanNanos))},${fmt1(us(x.medianNanos))},${fmt1(us(x.stddevNanos))},${fmt1(us(x.minNanos))},${fmt1(us(x.maxNanos))},${fmt1(us(x.p95Nanos))},${fmt4(x.cv)}")
        }
        w.close()
    }

    /** Recompute pct_of_full_cycle and pct_of_channel_work in place (they need the stage-pass denominators). */
    private fun fillPercentageColumns(file: File, fullCycleUs: Double, channelWorkUs: Double) {
        val lines = file.readLines().toMutableList()
        val header = lines[0].split(",")
        val iAdded = header.indexOf("added_us")
        val iFull = header.indexOf("pct_of_full_cycle")
        val iWork = header.indexOf("pct_of_channel_work")
        for (i in 1 until lines.size) {
            val cols = lines[i].split(",").toMutableList()
            val added = cols[iAdded].toDouble()
            cols[iFull] = fmt2(added / fullCycleUs * 100)
            cols[iWork] = fmt2(added / channelWorkUs * 100)
            lines[i] = cols.joinToString(",")
        }
        file.writeText(lines.joinToString("\n") + "\n")
    }

    private fun defaultOutputDir(): String {
        val ts = DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss").withZone(ZoneOffset.UTC).format(Instant.now())
        return File(findBenchmarkRoot(), "outputs/$ts-lightning-kmp-cost-per-payment").absolutePath
    }

    /** Walk up from the working directory until the benchmark repository root (has PINS.txt and outputs/). */
    private fun findBenchmarkRoot(): File {
        var dir = File(System.getProperty("user.dir")).absoluteFile
        while (true) {
            if (File(dir, "PINS.txt").exists() && File(dir, "outputs").isDirectory) return dir
            dir = dir.parentFile ?: return File(System.getProperty("user.dir")).absoluteFile
        }
    }

    private fun gitHead(dir: File): String = try {
        val p = ProcessBuilder("git", "-C", dir.absolutePath, "rev-parse", "HEAD").redirectErrorStream(true).start()
        p.inputStream.bufferedReader().readText().trim().take(12).ifEmpty { "unknown" }.also { p.waitFor() }
    } catch (_: Throwable) {
        "unknown"
    }

    private fun cpuModel(): String = try {
        File("/proc/cpuinfo").readLines().firstOrNull { it.startsWith("model name") }?.substringAfter(':')?.trim() ?: "unknown"
    } catch (_: Throwable) {
        "unknown"
    }

    private fun writeProvenance(file: File, iterations: Int, auxIterations: Int, warmup: Warmup, gridArg: String, gridSeed: Long, grid: List<Config>) {
        val root = findBenchmarkRoot()
        val pinsFile = File(root, "PINS.txt")
        val pinsHash = if (pinsFile.exists()) {
            try {
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                digest.digest(pinsFile.readBytes()).joinToString("") { "%02x".format(it) }
            } catch (_: Throwable) {
                "unknown"
            }
        } else "unknown"
        file.writeText(
            buildString {
                appendLine("run_dir=${file.parentFile.name}")
                appendLine("date_utc=${DateTimeFormatter.ISO_INSTANT.format(Instant.now())}")
                appendLine("implementation=lightning-kmp")
                appendLine("cpu=${cpuModel()}")
                appendLine("cores=${Runtime.getRuntime().availableProcessors()}")
                appendLine("java=${System.getProperty("java.version")}")
                appendLine("heap_max_mb=${Runtime.getRuntime().maxMemory() / (1024 * 1024)}")
                appendLine("iterations_per_configuration=$iterations  iterations_aux=$auxIterations")
                appendLine("warmup_min_iterations=${warmup.minIterations}  warmup_min_millis=${warmup.minMillis}")
                appendLine("grid=$gridArg  grid_seed=$gridSeed  configurations=${grid.size}")
                appendLine("payment_amount_msat=${PaymentAmount.msat}  recycle_every=$RecycleEvery")
                appendLine("benchmark-iceberg=${gitHead(root)}")
                appendLine("lightning-kmp=${gitHead(File(root, "sources/lightning-kmp"))}")
                appendLine("pins_sha256=$pinsHash")
            }
        )
    }

    private fun writeReadme(file: File, iterations: Int, auxIterations: Int, gridArg: String) {
        file.writeText(
            """
            # lightning-kmp: cost per payment of an Iceberg group-backed funding signer
            
            A paired measurement: two channels are open at once, one stock and one whose Bob side is
            an Iceberg t-of-n group (`IcebergFundingSigner`); each iteration pays once on each, back
            to back, counterbalanced, and the delta is computed per-iteration. The delta is the
            measured quantity. See `sources/lightning-kmp/ICEBERG-PORT.md` for the port itself and
            `outputs/README.md` for how this directory relates to the report.
            
            A payment cycle is: makeCmdAdd -> addHtlc -> crossSign -> fulfillHtlc -> crossSign.
            Parameters: $iterations paired iterations per configuration, $auxIterations for the
            stage passes, grid=$gridArg.
            
            ## Files
            
            - `cost_per_payment.csv` -- one row per (t,n): paired delta statistics (added_us with the
              autocorrelation-widened 95% CI), the signer-call costs measured through
              TimingFundingSigner (group_crypto_us / bare_crypto_us / net_crypto_us), residual_us
              (added minus net crypto; near zero means the whole added cost is the signer swap), and
              the observed signer-call counts per payment.
            - `paired_samples.csv` -- the raw per-iteration timings the grid rows are computed from.
            - `cycle_stages_bare.csv` / `cycle_stages_bare_warm.csv` -- per-stage cost of a stock
              payment before and after JVM warmup: how much of the cycle is warmup artifact.
            - `cycle_stages_group.csv` -- per-stage cost of a payment on the group-backed channel at
              the headline 3-of-7 configuration.
            - `cycle_stages_paired.csv` / `cycle_stages_paired_bare.csv` / `paired_stage_samples.csv`
              -- the paired stage split at 3-of-7 (per-stage deltas with CIs) and its raw samples.
            - `provenance.txt` -- what ran, on what machine, from which source.
            - `COMPLETE` -- written only when every configuration finished; a directory without it is
              a killed run and its numbers are not usable.
            
            ## Column notes
            
            - `added_us` = mean per-iteration delta (group arm minus bare arm) of a whole payment cycle.
            - `ci95_us` widens the iid interval by sqrt((1+r)/(1-r)) with r the lag-1 autocorrelation
              of the deltas (clamped to [0, 0.95]); `resolved` = |added| > ci95.
            - `pct_of_full_cycle` / `pct_of_channel_work` divide added_us by the bare arm's whole
              cycle, respectively the cycle minus command construction (make_cmd_add).
            - Signer-call counts are per payment: every seam method enters round one (a nonce
              derivation over the 2t-1 quorum); only the signing methods reach round two.
            """.trimIndent() + "\n"
        )
    }
}
