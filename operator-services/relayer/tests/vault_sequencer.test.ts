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
