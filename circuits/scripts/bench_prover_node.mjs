#!/usr/bin/env node
// Phase F W4 — Node-side WASM prover benchmark.
//
// Measures snarkjs.groth16.fullProve wall time + RSS peak for both circuits.
// Output: ../.phase_f_w4_baseline_node.json  (relative to circuits/, written to mvp-backend-w4 root).
//
// Run: cd circuits && node scripts/bench_prover_node.mjs [iters]

import { groth16 } from 'snarkjs';
import fs from 'node:fs';
import path from 'node:path';

const ITERS = parseInt(process.argv[2] || '5', 10);
const WARMUP = 1;

const CIRCUITS_DIR = path.resolve(process.cwd());
const OUT = path.resolve(CIRCUITS_DIR, '..', '.phase_f_w4_baseline_node.json');

function stats(arr) {
    const sorted = [...arr].sort((a, b) => a - b);
    const n = sorted.length;
    const median = n % 2 === 0
        ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
        : sorted[Math.floor(n / 2)];
    return {
        n,
        min_ms: +sorted[0].toFixed(2),
        median_ms: +median.toFixed(2),
        max_ms: +sorted[n - 1].toFixed(2),
        avg_ms: +(sorted.reduce((a, b) => a + b, 0) / n).toFixed(2),
        raw_ms: sorted.map((x) => +x.toFixed(2)),
    };
}

async function bench(label, wasmPath, zkeyPath, inputPath) {
    const input = JSON.parse(fs.readFileSync(inputPath));

    // memory poller
    let peakRssMb = 0;
    let peakHeapMb = 0;
    const poller = setInterval(() => {
        const m = process.memoryUsage();
        peakRssMb = Math.max(peakRssMb, m.rss / 1024 / 1024);
        peakHeapMb = Math.max(peakHeapMb, m.heapUsed / 1024 / 1024);
    }, 25);

    // warmup
    for (let i = 0; i < WARMUP; i++) {
        await groth16.fullProve(input, wasmPath, zkeyPath);
    }

    const times = [];
    for (let i = 0; i < ITERS; i++) {
        const t0 = process.hrtime.bigint();
        await groth16.fullProve(input, wasmPath, zkeyPath);
        const t1 = process.hrtime.bigint();
        times.push(Number(t1 - t0) / 1e6);
    }

    clearInterval(poller);

    const s = stats(times);
    s.peak_rss_mb = +peakRssMb.toFixed(1);
    s.peak_heap_mb = +peakHeapMb.toFixed(1);
    console.log(`[${label}] n=${ITERS} (warmup=${WARMUP})`);
    console.log(`  min=${s.min_ms}ms  median=${s.median_ms}ms  max=${s.max_ms}ms  avg=${s.avg_ms}ms`);
    console.log(`  peak_rss=${s.peak_rss_mb}MB  peak_heap=${s.peak_heap_mb}MB`);
    return s;
}

async function main() {
    console.log(`Node ${process.version} — ${process.platform}/${process.arch}`);
    console.log(`iters=${ITERS} warmup=${WARMUP}`);
    console.log('');

    const deposit = await bench(
        'deposit_binding (3343 constraints)',
        'generated/deposit_binding_js/deposit_binding.wasm',
        'generated/deposit_binding_final.zkey',
        'inputs/valid_input.json',
    );

    const withdraw = await bench(
        'withdrawal_proof (16073 constraints)',
        'generated/withdrawal_proof_js/withdrawal_proof.wasm',
        'generated/withdrawal_proof_final.zkey',
        'inputs/withdraw_valid_input.json',
    );

    const result = {
        captured_on: new Date().toISOString(),
        node_version: process.version,
        platform: `${process.platform}/${process.arch}`,
        iters: ITERS,
        warmup: WARMUP,
        deposit_binding: { constraints: 3343, ...deposit },
        withdrawal_proof: { constraints: 16073, ...withdraw },
    };
    fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
    console.log(`\nwrote ${OUT}`);
    process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
