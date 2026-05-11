#!/usr/bin/env node
// Phase F W4 — Node-side benchmark for OPTIMIZED withdrawal_proof (15993 constraints).
// Output: ../.phase_f_w4_optimized_node.json

import { groth16 } from 'snarkjs';
import fs from 'node:fs';
import path from 'node:path';

const ITERS = parseInt(process.argv[2] || '5', 10);
const WARMUP = 1;

const OUT = path.resolve(process.cwd(), '..', '.phase_f_w4_optimized_node.json');

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
    let peakRssMb = 0, peakHeapMb = 0;
    const poller = setInterval(() => {
        const m = process.memoryUsage();
        peakRssMb = Math.max(peakRssMb, m.rss / 1024 / 1024);
        peakHeapMb = Math.max(peakHeapMb, m.heapUsed / 1024 / 1024);
    }, 25);

    for (let i = 0; i < WARMUP; i++) await groth16.fullProve(input, wasmPath, zkeyPath);

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
    console.log(`[${label}] median=${s.median_ms}ms min=${s.min_ms} max=${s.max_ms} peak_rss=${s.peak_rss_mb}MB`);
    return s;
}

// Build a fresh withdraw input that satisfies the OPTIMIZED circuit.
// Since semantics are identical (same Poseidon, same Switcher swap semantics, same publics),
// the existing withdraw_valid_input.json works as-is.
async function main() {
    const withdraw = await bench(
        'withdrawal_proof (OPTIMIZED 15993 constraints)',
        'generated_w4/withdrawal_proof_js/withdrawal_proof.wasm',
        'generated_w4/withdrawal_proof_final.zkey',
        'inputs/withdraw_valid_input.json',
    );
    const result = {
        captured_on: new Date().toISOString(),
        node_version: process.version,
        platform: `${process.platform}/${process.arch}`,
        iters: ITERS,
        warmup: WARMUP,
        withdrawal_proof: { constraints: 15993, ...withdraw },
    };
    fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
    console.log(`\nwrote ${OUT}`);
    process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
