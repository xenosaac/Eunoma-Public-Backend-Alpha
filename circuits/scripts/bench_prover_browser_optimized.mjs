#!/usr/bin/env node
// Browser bench for optimized withdrawal_proof.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(CIRCUITS_DIR, '..');
const OUT = path.join(REPO_ROOT, '.phase_f_w4_optimized_browser.json');

const ITERS = parseInt(process.argv[2] || '5', 10);
const PORT = 18766;
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const MIME = {
    '.html': 'text/html', '.js': 'application/javascript', '.mjs': 'application/javascript',
    '.json': 'application/json', '.wasm': 'application/wasm', '.zkey': 'application/octet-stream',
};

function serveStatic(rootDir) {
    return http.createServer((req, res) => {
        try {
            const url = new URL(req.url, 'http://localhost');
            let fsPath = path.join(rootDir, decodeURIComponent(url.pathname));
            try { fsPath = fs.realpathSync(fsPath); } catch (_) {}
            if (!fs.existsSync(fsPath)) { res.writeHead(404); res.end('not found: ' + url.pathname); return; }
            const stat = fs.statSync(fsPath);
            if (stat.isDirectory()) { res.writeHead(403); res.end(); return; }
            const ext = path.extname(fsPath).toLowerCase();
            res.writeHead(200, {
                'Content-Type': MIME[ext] || 'application/octet-stream',
                'Content-Length': stat.size,
            });
            fs.createReadStream(fsPath).pipe(res);
        } catch (e) { res.writeHead(500); res.end(String(e)); }
    });
}

async function main() {
    const server = serveStatic(REPO_ROOT);
    await new Promise((r) => server.listen(PORT, r));
    let browser;
    try {
        browser = await puppeteer.launch({
            executablePath: CHROME, headless: 'new',
            args: ['--no-sandbox', '--enable-precise-memory-info'],
        });
        const page = await browser.newPage();
        page.on('console', (msg) => { const t=msg.type(); if (t==='error'||t==='warning') console.log(`[browser ${t}] ${msg.text()}`); });
        const url = `http://localhost:${PORT}/circuits/scripts/bench_prover_browser_optimized.html?iters=${ITERS}`;
        console.log('navigating to', url);
        await page.goto(url, { waitUntil: 'load' });
        const deadline = Date.now() + 10*60*1000;
        let result = null;
        while (Date.now() < deadline) {
            const s = await page.evaluate(() => ({ done: !!window.__benchResult, err: window.__benchError }));
            if (s.err) throw new Error('browser error: ' + s.err);
            if (s.done) { result = await page.evaluate(() => window.__benchResult); break; }
            await new Promise((r)=>setTimeout(r, 2000));
        }
        if (!result) throw new Error('timeout');
        console.log(`withdraw median: ${result.withdrawal_proof.median_ms}ms`);
        fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
        console.log(`wrote ${OUT}`);
    } finally {
        if (browser) await browser.close();
        server.close();
    }
}
main().catch((e)=>{ console.error(e); process.exit(1); });
