import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    root: here,
    include: ["__tests__/**/*.test.mjs", "_lib/__tests__/**/*.test.mjs"],
    testTimeout: 10000,
    pool: "forks",
  },
});
