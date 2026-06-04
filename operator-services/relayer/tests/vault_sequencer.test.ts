import { describe, expect, it } from "vitest";
import { VaultSequencer } from "../src/vault_sequencer.js";

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("VaultSequencer", () => {
  it("runs enqueued tasks strictly sequentially (no overlap)", async () => {
    const seq = new VaultSequencer();
    const events: string[] = [];
    let active = 0;
    let maxActive = 0;

    const task = (id: number, delay: number) =>
      seq.runExclusive(async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        events.push(`start-${id}`);
        await tick(delay);
        events.push(`end-${id}`);
        active -= 1;
        return id;
      });

    // Enqueue out of "natural" finish order; the mutex must still serialize them in enqueue order.
    const results = await Promise.all([task(1, 15), task(2, 1), task(3, 5)]);

    expect(maxActive).toBe(1); // never two tasks active at once
    expect(events).toEqual(["start-1", "end-1", "start-2", "end-2", "start-3", "end-3"]);
    expect(results).toEqual([1, 2, 3]);
  });

  it("serializes two concurrent withdraws with DIFFERENT assetAddr on the ONE global vault_sequence (RC5: no per-asset sharding)", async () => {
    // Multi-asset V4: a cUSDC withdraw and an APT withdraw submitted concurrently MUST funnel
    // through the single global VaultSequencer (the on-chain vault_sequence is global, S-A).
    // The sequencer is asset-agnostic by construction (never reads assetAddr), so two requests
    // bound to different assets can never both hold the lock at once.
    const seq = new VaultSequencer();
    const APT = "0x000000000000000000000000000000000000000000000000000000000000000a";
    const CUSDC = "0x00000000000000000000000000000000000000000000000000000000c05d0001";
    let active = 0;
    let maxActive = 0;
    const order: string[] = [];

    const withdraw = (assetAddr: string, label: string, delay: number) =>
      seq.runExclusive(async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        order.push(`enter:${label}:${assetAddr.slice(-4)}`);
        await tick(delay);
        order.push(`exit:${label}:${assetAddr.slice(-4)}`);
        active -= 1;
        return label;
      });

    // cUSDC enqueued first (longer) then APT — they must NOT interleave despite different assets.
    const results = await Promise.all([
      withdraw(CUSDC, "cusdc-wd", 12),
      withdraw(APT, "apt-wd", 1),
    ]);

    expect(maxActive).toBe(1); // single-writer across assets — never two in the critical section
    expect(order).toEqual([
      "enter:cusdc-wd:0001",
      "exit:cusdc-wd:0001",
      "enter:apt-wd:000a",
      "exit:apt-wd:000a",
    ]);
    expect(results).toEqual(["cusdc-wd", "apt-wd"]);
  });

  it("propagates a task's rejection to its caller without poisoning later tasks", async () => {
    const seq = new VaultSequencer();
    const order: string[] = [];

    const ok1 = seq.runExclusive(async () => {
      order.push("ok1");
      return "a";
    });
    const bad = seq.runExclusive(async () => {
      order.push("bad");
      throw new Error("boom");
    });
    const ok2 = seq.runExclusive(async () => {
      order.push("ok2");
      return "b";
    });

    await expect(ok1).resolves.toBe("a");
    await expect(bad).rejects.toThrow("boom");
    await expect(ok2).resolves.toBe("b"); // later task still runs after the failure
    expect(order).toEqual(["ok1", "bad", "ok2"]);
  });
});
