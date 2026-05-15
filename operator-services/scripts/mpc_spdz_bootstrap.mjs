#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus } from "node:os";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEOPERATOR_COUNT,
  ED25519_SCALAR_MODULUS,
  MP_SPDZ_COMMIT_DEFAULT,
  VAULT_EK_INVERSION_PROGRAM,
} from "./_lib/mpc_spdz_constants.mjs";

const MP_SPDZ_REPO = "https://github.com/data61/MP-SPDZ.git";
// Codex P3 #10: refuse to silently honor an MP_SPDZ_COMMIT override. The default is the
// audited commit; overriding it requires explicit operator consent via
// EUNOMA_ALLOW_MP_SPDZ_COMMIT_OVERRIDE=1 (with a loud stderr warning), otherwise we fail
// closed.
const MP_SPDZ_COMMIT_OVERRIDE = process.env.MP_SPDZ_COMMIT;
let MP_SPDZ_COMMIT;
if (MP_SPDZ_COMMIT_OVERRIDE && MP_SPDZ_COMMIT_OVERRIDE !== MP_SPDZ_COMMIT_DEFAULT) {
  if (process.env.EUNOMA_ALLOW_MP_SPDZ_COMMIT_OVERRIDE !== "1") {
    console.error(
      `MP_SPDZ_COMMIT override (${MP_SPDZ_COMMIT_OVERRIDE}) differs from the audited default ` +
        `(${MP_SPDZ_COMMIT_DEFAULT}); refuse to proceed. Set ` +
        `EUNOMA_ALLOW_MP_SPDZ_COMMIT_OVERRIDE=1 to bypass — this is an audit-bypass and should ` +
        `only happen in research/staging hosts.`,
    );
    process.exit(2);
  }
  console.error(
    `WARNING: MP_SPDZ_COMMIT is overridden to ${MP_SPDZ_COMMIT_OVERRIDE} (audited default ` +
      `is ${MP_SPDZ_COMMIT_DEFAULT}). EUNOMA_ALLOW_MP_SPDZ_COMMIT_OVERRIDE=1 was set so the ` +
      `bootstrap will proceed, but the result will NOT be the audited Phase 2 MP-SPDZ runtime.`,
  );
  MP_SPDZ_COMMIT = MP_SPDZ_COMMIT_OVERRIDE;
} else {
  MP_SPDZ_COMMIT = MP_SPDZ_COMMIT_DEFAULT;
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const installRoot = resolve(serviceRoot, process.env.EUNOMA_MPC_ROOT ?? ".agent-local/mp-spdz");
const mpSpdzHome = resolve(
  process.env.MP_SPDZ_HOME ?? `${installRoot}/MP-SPDZ-${MP_SPDZ_COMMIT.slice(0, 12)}`,
);
const python = resolve(process.env.MP_SPDZ_PYTHON ?? `${installRoot}/python-venv/bin/python`);
const jobs = process.env.MP_SPDZ_JOBS ?? String(Math.max(2, Math.min(8, cpuCount())));
const brewDependencyPrefixes = [
  brewPrefix("libsodium"),
  brewPrefix("openssl@3"),
  brewPrefix("openssl"),
  brewPrefix("boost@1.85"),
  brewPrefix("boost"),
  brewPrefix("gmp"),
].filter(Boolean);
const buildEnv = dependencyEnv(brewDependencyPrefixes);

mkdirSync(installRoot, { recursive: true, mode: 0o700 });
ensurePythonRuntime(python);

if (!existsSync(mpSpdzHome)) {
  run("git", ["clone", MP_SPDZ_REPO, mpSpdzHome], serviceRoot);
}

assertGitWorktree(mpSpdzHome);
checkoutPinnedCommit(mpSpdzHome);
run("git", ["submodule", "update", "--init", "--recursive"], mpSpdzHome);
writeConfigMine(mpSpdzHome, brewDependencyPrefixes);
if (process.env.MP_SPDZ_CLEAN === "1") {
  run("make", ["clean"], mpSpdzHome);
}
run("make", [`-j${jobs}`, "mascot-party.x"], mpSpdzHome);

const setupSsl = resolve(mpSpdzHome, "Scripts/setup-ssl.sh");
if (existsSync(setupSsl)) {
  run(setupSsl, [String(DEOPERATOR_COUNT)], mpSpdzHome);
}

const programSource = resolve(serviceRoot, `mpc-programs/${VAULT_EK_INVERSION_PROGRAM}.mpc`);
const programDest = resolve(mpSpdzHome, `Programs/Source/${VAULT_EK_INVERSION_PROGRAM}.mpc`);
const bytecode = resolve(mpSpdzHome, `Programs/Bytecode/${VAULT_EK_INVERSION_PROGRAM}-0.bc`);
const compiledHashFile = resolve(
  mpSpdzHome,
  `Programs/Bytecode/${VAULT_EK_INVERSION_PROGRAM}.eunoma-source-sha256`,
);
const programHash = createHash("sha256")
  .update(readFileSync(programSource))
  .digest("hex");
const recompileNeeded =
  !existsSync(bytecode) ||
  !existsSync(compiledHashFile) ||
  readFileSync(compiledHashFile, "utf8").trim() !== programHash;

if (recompileNeeded) {
  mkdirSync(dirname(programDest), { recursive: true });
  copyFileSync(programSource, programDest);
  run(
    python,
    [
      resolve(mpSpdzHome, "compile.py"),
      "-P",
      ED25519_SCALAR_MODULUS,
      VAULT_EK_INVERSION_PROGRAM,
    ],
    mpSpdzHome,
  );
  if (!existsSync(bytecode)) {
    throw new Error(
      `MP-SPDZ compile did not produce ${bytecode}; check compile.py output above`,
    );
  }
  mkdirSync(dirname(compiledHashFile), { recursive: true });
  writeFileSync(compiledHashFile, `${programHash}\n`, { mode: 0o600 });
}

const manifest = {
  mpSpdzHome,
  repo: MP_SPDZ_REPO,
  commit: MP_SPDZ_COMMIT,
  binary: resolve(mpSpdzHome, "mascot-party.x"),
  python,
  parties: DEOPERATOR_COUNT,
  programs: {
    [VAULT_EK_INVERSION_PROGRAM]: {
      source: programDest,
      bytecode,
      sourceSha256: programHash,
    },
  },
};
writeFileSync(resolve(installRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
  mode: 0o600,
});

console.log(JSON.stringify({ ok: true, command: "mpc:bootstrap", ...manifest }, null, 2));

function checkoutPinnedCommit(cwd) {
  const current = capture("git", ["rev-parse", "HEAD"], cwd).trim();
  if (current === MP_SPDZ_COMMIT) return;

  const dirty = capture("git", ["status", "--porcelain"], cwd).trim();
  if (dirty) {
    throw new Error(
      `MP-SPDZ worktree is not clean at ${cwd}; refusing to checkout ${MP_SPDZ_COMMIT}`,
    );
  }

  const hasCommit = spawnSync("git", ["cat-file", "-e", `${MP_SPDZ_COMMIT}^{commit}`], { cwd });
  if (hasCommit.status !== 0) {
    run("git", ["fetch", "--depth", "1", "origin", MP_SPDZ_COMMIT], cwd);
  }
  run("git", ["checkout", "--detach", MP_SPDZ_COMMIT], cwd);
}

function assertGitWorktree(cwd) {
  const result = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd,
    encoding: "utf8",
  });
  if (result.status !== 0 || result.stdout.trim() !== "true") {
    throw new Error(`MP_SPDZ_HOME is not a git checkout: ${cwd}`);
  }
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
    env: buildEnv,
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function ensurePythonRuntime(pythonPath) {
  if (!existsSync(pythonPath)) {
    run("python3", ["-m", "venv", dirname(dirname(pythonPath))], serviceRoot);
  }
  if (pythonHasModule(pythonPath, "gmpy2")) return;
  run(pythonPath, ["-m", "pip", "install", "--upgrade", "pip"], serviceRoot);
  run(pythonPath, ["-m", "pip", "install", "gmpy2"], serviceRoot);
}

function pythonHasModule(pythonPath, moduleName) {
  const result = spawnSync(pythonPath, ["-c", `import ${moduleName}`], {
    cwd: serviceRoot,
    encoding: "utf8",
    env: buildEnv,
  });
  return result.status === 0;
}

function capture(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: buildEnv,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout;
}

function cpuCount() {
  return cpus().length || 4;
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

function writeConfigMine(cwd, prefixes) {
  const path = resolve(cwd, "CONFIG.mine");
  const existing = existsSync(path) ? readFileSync(path, "utf8") : "";
  const includeFlags = prefixes.map((prefix) => `-I${prefix}/include`).join(" ");
  const libFlags = prefixes.map((prefix) => `-L${prefix}/lib`).join(" ");
  const block = [
    "# EUNOMA_MPC_SPDZ_BEGIN",
    `MY_CFLAGS += ${includeFlags} -Wno-error=deprecated-literal-operator`,
    `MY_LDLIBS += ${libFlags}`,
    "# EUNOMA_MPC_SPDZ_END",
    "",
  ].join("\n");
  const cleaned = existing.replace(
    /# EUNOMA_MPC_SPDZ_BEGIN[\s\S]*?# EUNOMA_MPC_SPDZ_END\n?/,
    "",
  );
  writeFileSync(path, `${cleaned.trimEnd()}\n${block}`);
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
