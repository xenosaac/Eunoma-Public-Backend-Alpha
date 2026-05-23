#!/usr/bin/env node
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const ignoredDirs = new Set([".git", "node_modules", "dist", "target", ".next", ".agent-local"]);
const conflicts = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!ignoredDirs.has(entry.name)) walk(join(dir, entry.name));
      continue;
    }
    if (entry.isFile() && / 2\.[^/]+$/.test(entry.name)) {
      const path = join(dir, entry.name);
      if (statSync(path).isFile()) conflicts.push(path.slice(root.length + 1));
    }
  }
}

walk(root);

if (conflicts.length > 0) {
  console.error("iCloud conflict files found:");
  for (const path of conflicts) console.error(`  ${path}`);
  process.exit(1);
}

console.log("no iCloud conflict files found");
