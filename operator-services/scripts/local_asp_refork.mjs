// ASP re-fork epoch orchestrator — V4 0xbow stable-LABEL + change-note inheritance (2026-06-01).
// One epoch:
//   1. screen NEW deposits' senders via Chainalysis (deposit-side, real execution)
//   2. merge CHANGE-NOTE commitments by LABEL INHERITANCE — NO screenAddress call (a change note
//      has no plaintext sender; the parent's on-chain withdraw proof already proved parent ∈ ASP,
//      so the change inherits the parent's approval — re-screening the depositor would re-link
//      deposit↔withdraw, strictly worse). Each change note carries its parent's deposit-scoped LABEL.
//   3. re-screen EXISTING approved senders (revocation): a newly-sanctioned sender → drop that
//      sender's LABEL → drop EVERY commitment sharing that label (parent + all descendant change
//      notes die together; no off-chain edge graph / transitive walk).
//   4. rebuild the ASP LeanIMT from the merged approved commitment set (re-fork, NOT in-place delete)
//   5. publish the full PUBLIC set to IPFS → cid (carries updatedAtUnix for the on-chain
//      ASP_ROOT_TTL_SECS wall-clock window)
//   6. (caller) record root via the asp-recorder delegate on-chain (see aspRecordCliArgs)
//
// Off-chain REST screening → 0 Aptos gas; withdraw makes ZERO KYT calls (change inheritance is
// proof-authorized, not re-screened). Only the on-chain root record costs gas (1 tx/epoch).
import { screenDeposits, makeKytProvider } from "./kyt_provider.mjs";
import { makeAspSetArtifact } from "./local_build_asp_tree.mjs";
import { makeIpfsPublisher } from "./ipfs_publisher.mjs";

const lc = (s) => String(s).toLowerCase();

// Each approved entry: { commitment, sender, label }.
//   - label = the deposit-scoped stable label (parent + descendants share it). Falls back to the
//     commitment (degenerate self-label) for legacy entries with no recorded label.
//   - A CHANGE note has NO sender (sender: "" / null) and carries its parent's label; it is merged
//     by inheritance (the revocation key is the LABEL, never the change note's absent sender).
function labelOf(entry) {
  return lc(entry.label ?? entry.commitment);
}

// state:    { approved: [{commitment, sender, label}] }
// newDeposits: [{commitment, sender, label}]            (deposit-side; screened by sender)
// changeNotes: [{commitment, label, parentCommitment?}] (partial-withdraw; inherited, NOT screened)
// opts: { kyt, ipfs, nowUnix } (kyt/ipfs injectable for tests)
export async function runAspReforkEpoch({
  state = { approved: [] },
  newDeposits = [],
  changeNotes = [],
  opts = {},
}) {
  const kyt = opts.kyt ?? makeKytProvider();
  const ipfs = opts.ipfs ?? makeIpfsPublisher();
  const nowUnix = opts.nowUnix ?? Math.floor(Date.now() / 1000);

  // 1. screen new deposits (deposit-side KYT — the ONLY screening; binds each to its own label).
  const { approved: newApproved, rejected } = await screenDeposits(kyt, newDeposits);
  const newApprovedByCommitment = new Map(newDeposits.map((d) => [lc(d.commitment), d]));

  // 2. re-screen existing approved SENDERS for revocation → build the set of revoked LABELS.
  //    A revoked sender revokes its whole label (parent + all descendants). Change-note entries
  //    (no sender) are NOT re-screened here — they live/die purely by their inherited label.
  const revokedLabels = new Set();
  const revoked = [];
  for (const a of state.approved) {
    if (!a.sender) continue; // change note / sender-less entry: governed by its label only
    const r = await kyt.screenAddress(a.sender);
    if (r.sanctioned) {
      revokedLabels.add(labelOf(a));
      revoked.push(a);
    }
  }

  // 3. carry forward existing approved entries whose LABEL is not revoked.
  const merged = [];
  const seenCommitment = new Set();
  const liveLabels = new Set();
  const pushEntry = (entry) => {
    const c = lc(entry.commitment);
    if (seenCommitment.has(c)) return;
    seenCommitment.add(c);
    merged.push(entry);
    liveLabels.add(labelOf(entry));
  };
  for (const a of state.approved) {
    if (revokedLabels.has(labelOf(a))) continue; // drop revoked-label commitments (incl. descendants)
    pushEntry({ commitment: a.commitment, sender: a.sender ?? "", label: a.label ?? a.commitment });
  }

  // 4a. merge newly-approved deposits (screened in step 1), preserving their label binding.
  for (const a of newApproved) {
    const src = newApprovedByCommitment.get(lc(a.commitment));
    const label = src?.label ?? a.commitment;
    if (revokedLabels.has(lc(label))) continue;
    pushEntry({ commitment: a.commitment, sender: a.sender, label });
  }

  // 4b. merge CHANGE notes by LABEL INHERITANCE — NO screenAddress. A change note only enters if
  //     its inherited (parent) LABEL is currently live (an already-approved, non-revoked label).
  //     This is the proof-authorized inheritance: the parent's withdraw proof already proved
  //     parent ∈ ASP, so its descendants inherit approval without any new KYT call.
  const changeNotesRejected = [];
  for (const cn of changeNotes) {
    const label = lc(cn.label ?? cn.parentCommitment ?? "");
    if (!label || revokedLabels.has(label) || !liveLabels.has(label)) {
      changeNotesRejected.push(cn); // unknown / revoked / not-yet-approved parent label → not listed
      continue;
    }
    pushEntry({
      commitment: cn.commitment,
      sender: "", // change notes have NO plaintext sender (never re-screened)
      label,
      ...(cn.parentCommitment ? { parentCommitment: cn.parentCommitment } : {}),
    });
  }

  // 5. build ASP tree + set artifact (leaves = commitments; updatedAtUnix feeds ASP_ROOT_TTL_SECS).
  const { artifact, root, depth, labels, labelByCommitment } = await makeAspSetArtifact(
    merged.map((a) => ({ commitment: a.commitment, label: a.label })),
    nowUnix,
  );

  // 6. publish full set to IPFS
  const { cid, source } = await ipfs.publish(artifact, "eunoma-asp-set");
  artifact.ipfsCid = cid;

  return {
    approved: merged,
    revoked,
    revokedLabels: [...revokedLabels],
    rejectedNew: rejected,
    changeNotesRejected,
    root,
    depth,
    rootHex: artifact.rootHex,
    labels,
    labelByCommitment,
    updatedAtUnix: nowUnix,
    cid,
    ipfsSource: source,
    artifact,
  };
}

// aptos CLI args to record the new ASP root on-chain via the low-priv asp-recorder delegate.
// cid is utf8-encoded to hex (Move takes vector<u8>).
export function aspRecordCliArgs({ bridgeAddr, rootHex, cid }) {
  const cidHex = "0x" + Buffer.from(cid, "utf8").toString("hex");
  const root = rootHex.startsWith("0x") ? rootHex : `0x${rootHex}`;
  return [
    "move", "run",
    "--function-id", `${bridgeAddr}::eunoma_bridge::record_asp_root_via_delegate`,
    "--args", `hex:${root}`, `hex:${cidHex}`,
    "--assume-yes",
  ];
}
