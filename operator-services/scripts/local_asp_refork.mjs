// ASP re-fork epoch orchestrator. One epoch:
//   1. screen NEW deposits' senders via Chainalysis (deposit-side, real execution)
//   2. re-screen EXISTING approved senders (revocation: newly-sanctioned → drop)
//   3. rebuild the ASP LeanIMT from the merged approved set (re-fork, NOT in-place delete)
//   4. publish the full PUBLIC set to IPFS → cid
//   5. (caller) record root via the asp-recorder delegate on-chain (see aspRecordCliArgs)
//
// Off-chain REST screening → 0 Aptos gas; only the on-chain root record costs gas (1 tx/epoch).
import { screenDeposits, makeKytProvider } from "./kyt_provider.mjs";
import { makeAspSetArtifact } from "./local_build_asp_tree.mjs";
import { makeIpfsPublisher } from "./ipfs_publisher.mjs";

const lc = (s) => String(s).toLowerCase();

// state: { approved: [{commitment, sender}] } ; newDeposits: [{commitment, sender}]
// opts: { kyt, ipfs, nowUnix } (kyt/ipfs injectable for tests)
export async function runAspReforkEpoch({ state = { approved: [] }, newDeposits = [], opts = {} }) {
  const kyt = opts.kyt ?? makeKytProvider();
  const ipfs = opts.ipfs ?? makeIpfsPublisher();
  const nowUnix = opts.nowUnix ?? Math.floor(Date.now() / 1000);

  // 1. screen new deposits
  const { approved: newApproved, rejected } = await screenDeposits(kyt, newDeposits);

  // 2. re-screen existing approved for revocation
  const stillApproved = [];
  const revoked = [];
  for (const a of state.approved) {
    const r = await kyt.screenAddress(a.sender);
    if (r.sanctioned) revoked.push(a);
    else stillApproved.push(a);
  }

  // 3. merge (dedup by commitment, preserve insertion order)
  const seen = new Set(stillApproved.map((a) => lc(a.commitment)));
  const merged = [...stillApproved];
  for (const a of newApproved) {
    if (!seen.has(lc(a.commitment))) { merged.push(a); seen.add(lc(a.commitment)); }
  }

  // 4. build ASP tree + set artifact
  const { artifact, root, depth } = await makeAspSetArtifact(merged.map((a) => a.commitment), nowUnix);

  // 5. publish full set to IPFS
  const { cid, source } = await ipfs.publish(artifact, "eunoma-asp-set");
  artifact.ipfsCid = cid;

  return {
    approved: merged,
    revoked,
    rejectedNew: rejected,
    root,
    depth,
    rootHex: artifact.rootHex,
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
