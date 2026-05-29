import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FileSubmitJournal } from "../src/submit_journal.js";

const tmpFiles: string[] = [];
function tmpPath(name: string): string {
  const p = path.join(os.tmpdir(), `eunoma-journal-test-${name}.jsonl`);
  tmpFiles.push(p);
  if (fs.existsSync(p)) fs.rmSync(p);
  return p;
}
afterEach(() => {
  for (const p of tmpFiles.splice(0)) if (fs.existsSync(p)) fs.rmSync(p);
});

let clock = 1_000;
const now = () => clock++;

describe("FileSubmitJournal (in-memory)", () => {
  it("tracks lastCompletedStep across intent/completed records", () => {
    const j = new FileSubmitJournal({ now });
    const rh = "0xreq1";
    expect(j.lastCompletedStep(rh)).toBe(-1);
    j.recordIntent(rh, 0);
    expect(j.lastCompletedStep(rh)).toBe(-1); // intent alone does not advance
    j.recordCompleted(rh, 0, "0xh0");
    j.recordIntent(rh, 1);
    j.recordCompleted(rh, 1, "0xh1");
    expect(j.lastCompletedStep(rh)).toBe(1);
    expect(j.entries(rh).filter((e) => e.phase === "completed").map((e) => e.txHash)).toEqual([
      "0xh0",
      "0xh1",
    ]);
  });

  it("isolates entries by requestHash", () => {
    const j = new FileSubmitJournal({ now });
    j.recordCompleted("0xreqA", 0, "0xa0");
    j.recordCompleted("0xreqB", 0, "0xb0");
    j.recordCompleted("0xreqB", 1, "0xb1");
    expect(j.lastCompletedStep("0xreqA")).toBe(0);
    expect(j.lastCompletedStep("0xreqB")).toBe(1);
    expect(j.lastCompletedStep("0xreqUnknown")).toBe(-1);
  });
});

describe("FileSubmitJournal (file-backed crash recovery)", () => {
  it("replays a persisted journal on restart", () => {
    const p = tmpPath("replay");
    const j1 = new FileSubmitJournal({ filePath: p, now });
    j1.recordIntent("0xreq", 0);
    j1.recordCompleted("0xreq", 0, "0xh0");
    j1.recordIntent("0xreq", 1);
    j1.recordCompleted("0xreq", 1, "0xh1");
    j1.recordIntent("0xreq", 2); // crash before step 2 completes

    // Simulate restart: a fresh instance loads the same file.
    const j2 = new FileSubmitJournal({ filePath: p, now });
    expect(j2.lastCompletedStep("0xreq")).toBe(1); // resume at step 2
    expect(j2.entries("0xreq").length).toBe(5);
  });

  it("skips a torn trailing line (crash mid-append) without throwing", () => {
    const p = tmpPath("torn");
    const j1 = new FileSubmitJournal({ filePath: p, now });
    j1.recordCompleted("0xreq", 0, "0xh0");
    // Simulate a partial write of the next line (process killed mid-append).
    fs.appendFileSync(p, '{"requestHash":"0xreq","step":1,"pha');

    const j2 = new FileSubmitJournal({ filePath: p, now });
    expect(j2.lastCompletedStep("0xreq")).toBe(0); // torn line ignored
  });
});
