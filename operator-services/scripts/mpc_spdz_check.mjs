#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEOPERATOR_COUNT,
  ED25519_SCALAR_MODULUS,
  MP_SPDZ_COMMIT_DEFAULT,
} from "./_lib/mpc_spdz_constants.mjs";

const MP_SPDZ_COMMIT = process.env.MP_SPDZ_COMMIT ?? MP_SPDZ_COMMIT_DEFAULT;
const PROGRAM = "eunoma_ed25519_scalar_check";
const INPUTS = [11n, 22n, 7n, 9n, 5n, 3n, 4n];
const EXPECTED = {
  sum: "61",
  mul: "63",
  inv: "1",
};

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const installRoot = resolve(serviceRoot, process.env.EUNOMA_MPC_ROOT ?? ".agent-local/mp-spdz");
const manifest = readManifest();
const mpSpdzHome = resolve(
  process.env.MP_SPDZ_HOME ??
    manifest?.mpSpdzHome ??
    `${installRoot}/MP-SPDZ-${MP_SPDZ_COMMIT.slice(0, 12)}`,
);
const python = resolve(
  process.env.MP_SPDZ_PYTHON ?? manifest?.python ?? `${installRoot}/python-venv/bin/python`,
);
const compileRun = resolve(mpSpdzHome, "Scripts/compile-run.py");
const mascot = resolve(mpSpdzHome, "mascot-party.x");
const runtimeEnv = dependencyEnv([
  brewPrefix("libsodium"),
  brewPrefix("openssl@3"),
  brewPrefix("openssl"),
  brewPrefix("boost@1.85"),
  brewPrefix("boost"),
  brewPrefix("gmp"),
].filter(Boolean));
runtimeEnv.PLAYERS = String(DEOPERATOR_COUNT);

if (!existsSync(mpSpdzHome) || !existsSync(compileRun) || !existsSync(mascot)) {
  console.error(JSON.stringify({
    ok: false,
    command: "mpc:check",
    error: "mp_spdz_runtime_missing",
    message: "MP-SPDZ mascot-party.x is missing. Run npm run mpc:bootstrap first.",
    mpSpdzHome,
  }, null, 2));
  process.exit(2);
}

if (!existsSync(python) || !pythonHasModule(python, "gmpy2")) {
  console.error(JSON.stringify({
    ok: false,
    command: "mpc:check",
    error: "mp_spdz_python_runtime_missing",
    message: "MP-SPDZ Python runtime is missing gmpy2. Run npm run mpc:bootstrap first.",
    python,
  }, null, 2));
  process.exit(2);
}

writeSelfTestProgram();
writeInputs();

const result = spawnSync(
  python,
  [
    compileRun,
    "-E",
    "mascot",
    "-P",
    ED25519_SCALAR_MODULUS,
    PROGRAM,
  ],
  {
    cwd: mpSpdzHome,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
    env: runtimeEnv,
  },
);

const combined = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
if (result.status !== 0) {
  process.stderr.write(combined);
  process.exit(result.status ?? 1);
}

assertOutput(combined, "EUNOMA_MPC_SUM", EXPECTED.sum);
assertOutput(combined, "EUNOMA_MPC_MUL", EXPECTED.mul);
assertOutput(combined, "EUNOMA_MPC_INV", EXPECTED.inv);

console.log(JSON.stringify({
  ok: true,
  command: "mpc:check",
  protocol: "mascot",
  parties: DEOPERATOR_COUNT,
  prime: ED25519_SCALAR_MODULUS,
  program: PROGRAM,
  checks: EXPECTED,
}, null, 2));

function writeSelfTestProgram() {
  const sourceDir = resolve(mpSpdzHome, "Programs/Source");
  mkdirSync(sourceDir, { recursive: true });
  writeFileSync(
    resolve(sourceDir, `${PROGRAM}.mpc`),
    [
      "xs = [sint.get_input_from(i) for i in range(7)]",
      "total = xs[0] + xs[1] + xs[2] + xs[3] + xs[4] + xs[5] + xs[6]",
      "product = xs[2] * xs[3]",
      "inverse_check = xs[4] * sint(1).field_div(xs[4])",
      "print_ln('EUNOMA_MPC_SUM=%s', total.reveal())",
      "print_ln('EUNOMA_MPC_MUL=%s', product.reveal())",
      "print_ln('EUNOMA_MPC_INV=%s', inverse_check.reveal())",
      "",
    ].join("\n"),
  );
}

function writeInputs() {
  const inputDir = resolve(mpSpdzHome, "Player-Data");
  mkdirSync(inputDir, { recursive: true });
  for (let party = 0; party < DEOPERATOR_COUNT; party += 1) {
    writeFileSync(resolve(inputDir, `Input-P${party}-0`), `${INPUTS[party].toString()}\n`, {
      mode: 0o600,
    });
  }
}

function assertOutput(output, key, expected) {
  const pattern = new RegExp(`${key}\\s*=\\s*${expected}(?!\\d)`);
  if (!pattern.test(output)) {
    console.error(output);
    throw new Error(`${key} did not equal ${expected}`);
  }
}

function readManifest() {
  const path = resolve(installRoot, "manifest.json");
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

function pythonHasModule(pythonPath, moduleName) {
  const result = spawnSync(pythonPath, ["-c", `import ${moduleName}`], {
    cwd: serviceRoot,
    encoding: "utf8",
    env: runtimeEnv,
  });
  return result.status === 0;
}

function dependencyEnv(prefixes) {
  const env = { ...process.env };
  const includePaths = prefixes.map((prefix) => `${prefix}/include`);
  const libPaths = prefixes.map((prefix) => `${prefix}/lib`);
  const pkgConfigPaths = prefixes.map((prefix) => `${prefix}/lib/pkgconfig`);

  prependPath(env, "CPATH", includePaths);
  prependPath(env, "LIBRARY_PATH", libPaths);
  prependPath(env, "DYLD_LIBRARY_PATH", libPaths);
  prependPath(env, "PKG_CONFIG_PATH", pkgConfigPaths);
  prependPath(env, "CMAKE_PREFIX_PATH", prefixes);
  env.CPPFLAGS = `${includePaths.map((path) => `-I${path}`).join(" ")} ${env.CPPFLAGS ?? ""}`.trim();
  env.LDFLAGS = `${libPaths.map((path) => `-L${path}`).join(" ")} ${env.LDFLAGS ?? ""}`.trim();
  return env;
}

function brewPrefix(formula) {
  const result = spawnSync("brew", ["--prefix", formula], {
    encoding: "utf8",
    env: process.env,
  });
  return result.status === 0 ? result.stdout.trim() : undefined;
}

function prependPath(env, key, values) {
  const filtered = values.filter(Boolean);
  if (filtered.length === 0) return;
  env[key] = [filtered.join(":"), env[key]].filter(Boolean).join(":");
}
