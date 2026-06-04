import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FastifyBaseLogger } from "fastify";

vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}));

import { spawn } from "node:child_process";
import {
  __resetPipelineInFlightForTests,
  triggerBridgeMaintenance,
} from "../src/bridge_maintenance_pipeline.js";

type FakeChild = EventEmitter & {
  stdout: PassThrough;
  stderr: PassThrough;
};

function fakeLogger(): FastifyBaseLogger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  } as unknown as FastifyBaseLogger;
}

function makeChild(): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  return child;
}

describe("bridge maintenance pipeline", () => {
  const spawnMock = vi.mocked(spawn);
  const children: FakeChild[] = [];

  beforeEach(() => {
    children.length = 0;
    spawnMock.mockReset();
    spawnMock.mockImplementation(() => {
      const child = makeChild();
      children.push(child);
      return child as never;
    });
    __resetPipelineInFlightForTests();
  });

  afterEach(() => {
    __resetPipelineInFlightForTests();
    vi.restoreAllMocks();
  });

  it("queues one rerun when a trigger arrives during an active refresh", async () => {
    const repoRoot = resolve(process.cwd(), "../..");
    triggerBridgeMaintenance({
      repoRoot,
      logger: fakeLogger(),
      extraDepositTxHashes: [`0x${"11".repeat(32)}`],
    });
    await vi.waitFor(() => expect(spawnMock).toHaveBeenCalledTimes(1));

    triggerBridgeMaintenance({
      repoRoot,
      logger: fakeLogger(),
      extraDepositTxHashes: [`0x${"22".repeat(32)}`],
    });
    expect(spawnMock).toHaveBeenCalledTimes(1);

    children[0].emit("exit", 0, null);
    await vi.waitFor(() => expect(spawnMock).toHaveBeenCalledTimes(2));
    const secondEnv = spawnMock.mock.calls[1]?.[2]?.env as Record<string, string> | undefined;
    expect(secondEnv?.EUNOMA_EXTRA_DEPOSIT_TX_HASHES).toBe(`0x${"22".repeat(32)}`);

    children[1].emit("exit", 0, null);
    await vi.waitFor(() => expect(children).toHaveLength(2));
  });
});
