#!/usr/bin/env node
// Phase F W4 — Browser-side WASM prover benchmark via puppeteer.
//
// Spawns a static file server (rooted at mvp-backend-w4/) + headless Chrome,
// loads circuits/scripts/bench_prover_browser.html, waits for window.__benchResult,
// dumps to ../.phase_f_w4_baseline_browser.json.
//
// Uses /Applications/Google Chrome.app/Contents/MacOS/Google Chrome to avoid downloading Chromium.
// Run: cd circuits && node scripts/bench_prover_browser.mjs [iters]

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(CIRCUITS_DIR, '..');
const OUT = path.join(REPO_ROOT, '.phase_f_w4_baseline_browser.json');

const ITERS = parseInt(process.argv[2] || '5', 10);
const PORT = 18765;
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const MIME = {
    '.html': 'text/html',
    '.js':   'application/javascript',
    '.mjs':  'application/javascript',
    '.json': 'application/json',
    '.wasm': 'application/wasm',
    '.zkey': 'application/octet-stream',
};

function serveStatic(rootDir) {
    return http.createServer((req, res) => {
        try {
            const url = new URL(req.url, 'http://localhost');
            let fsPath = path.join(rootDir, decodeURIComponent(url.pathname));
            // realpath to follow symlinks (needed for generated/*_final.zkey)
            try { fsPath = fs.realpathSync(fsPath); } catch (_) {}
            if (!fsPath.startsWith('/')) { res.writeHead(403); res.end(); return; }
            if (!fs.existsSync(fsPath)) { res.writeHead(404); res.end('not found: ' + url.pathname); return; }
            const stat = fs.statSync(fsPath);
            if (stat.isDirectory()) { res.writeHead(403); res.end(); return; }
            const ext = path.extname(fsPath).toLowerCase();
            res.writeHead(200, {
                'Content-Type': MIME[ext] || 'application/octet-stream',
                'Content-Length': stat.size,
                // Required for performance.memory (best-effort)
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Cross-Origin-Embedder-Policy': 'require-corp',
            });
            fs.createReadStream(fsPath).pipe(res);
        } catch (e) {
            res.writeHead(500); res.end(String(e));
        }
    });
}

async function main() {
    const server = serveStatic(REPO_ROOT);
    await new Promise((resolve) => server.listen(PORT, resolve));
    console.log(`static server: http://localhost:${PORT}/  (root=${REPO_ROOT})`);

    let browser;
    try {
        browser = await puppeteer.launch({
            executablePath: CHROME,
            headless: 'new',
            args: ['--no-sandbox', '--enable-precise-memory-info', '--js-flags=--expose-gc'],
        });
        const page = await browser.newPage();
        page.on('console', (msg) => {
            const t = msg.type();
            if (t === 'error' || t === 'warning') console.log(`[browser ${t}] ${msg.text()}`);
        });

        const url = `http://localhost:${PORT}/circuits/scripts/bench_prover_browser.html?iters=${ITERS}`;
        console.log('navigating to', url);
        await page.goto(url, { waitUntil: 'load' });

        // Wait for __benchResult or __benchError up to 10 min.
        const deadline = Date.now() + 10 * 60 * 1000;
        let result = null;
        while (Date.now() < deadline) {
            const status = await page.evaluate(() => ({
                done: !!window.__benchResult,
                err: window.__benchError,
            }));
            if (status.err) throw new Error('browser error: ' + status.err);
            if (status.done) {
                result = await page.evaluate(() => window.__benchResult);
                break;
            }
            await new Promise((r) => setTimeout(r, 2000));
        }
        if (!result) throw new Error('timed out waiting for bench result');

        // Log a summary
        console.log('\nresults:');
        console.log(`  deposit median: ${result.deposit_binding.median_ms}ms`);
        console.log(`  withdraw median: ${result.withdrawal_proof.median_ms}ms`);
        console.log(`  user-agent: ${result.user_agent}`);
        fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
        console.log(`\nwrote ${OUT}`);
    } finally {
        if (browser) await browser.close();
        server.close();
    }
}

main().catch((e) => { console.error(e); process.exit(1); });
