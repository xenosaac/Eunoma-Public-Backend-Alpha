import { defineConfig, configDefaults } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// These files use Node's built-in test runner (`node --test`), NOT vitest.
// Vitest's `*.test.mjs` glob would otherwise sweep them and emit "no test suite
// found" warnings. They run under `npm run test:scripts:node` instead.
const NODE_TEST_RUNNER_FILES = [
  "**/_lib/__tests__/**/*.test.mjs",
  "**/local_v2_withdraw_full.test.mjs",
  "**/local_v2_withdraw_full_balance.test.mjs",
  "**/sigma_position_17_parity.test.mjs",
  "**/local_v2_withdraw_resync.test.mjs",
  "**/note_v3.test.mjs",
  "**/asp_tree.test.mjs",
  "**/asp_refork.test.mjs",
  "**/asp_set_artifact.test.mjs",
];

export default defineConfig({
  test: {
    environment: "node",
    root: here,
    include: ["__tests__/**/*.test.mjs", "_lib/__tests__/**/*.test.mjs"],
    exclude: [...configDefaults.exclude, ...NODE_TEST_RUNNER_FILES],
    testTimeout: 10000,
    pool: "forks",
  },
});
