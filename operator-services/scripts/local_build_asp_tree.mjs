// ASP tree builder — V4 0xbow stable-LABEL model (2026-06-01).
//
// The APPROVAL/REVOCATION unit is the deposit-scoped LABEL (0xbow's ASP-leaf = label):
//   label = hash_2(hash_3(label_scope0, label_scope1, label_scope2), label_nonce)
// fixed once per deposit. Every descendant (incl. partial-withdraw CHANGE notes) of a deposit
// shares the SAME label → a still-approved label is re-listed every epoch (honest users never age
// out) and revocation = OMIT the label so all its commitments drop together (descendants die,
// with no off-chain edge graph / transitive walk).
//
// CIRCUIT REALITY (the frozen withdraw VK): the stable label is folded into the SECRET SLOT at
// deposit time — secret_bound = hash_2(secret_raw, label) — so the COMMITMENT itself is
// label-derived, and the withdraw circuit proves `asp_incl.leaf <== cmt.out` (the COMMITMENT, not
// a raw label; withdrawal_proof.circom:116). Therefore the ASP LeanIMT LEAVES stay COMMITMENTS
// (byte-identical to what the circuit recomputes), and the LABEL is the grouping key that decides
// WHICH commitments are listed. Listing a label ⇒ list its commitments; omitting a label ⇒ drop
// its commitments. This realizes 0xbow's "ASP-leaf = label" semantics over a commitment-leaf tree.
//
// Produces the on-chain root/depth + the PUBLIC full-set artifact published to IPFS. Re-fork model:
// callers rebuild from the current approved label-set each epoch (excluding revoked labels) → new
// root → record via the asp-recorder delegate.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const circuitsScripts = resolve(here, "..", "..", "circuits", "scripts");
const { LeanIMTTree } = await import(`file://${resolve(circuitsScripts, "leanimt_tree.mjs")}`);
const { leBytesToBig, hexToLE32, le32ToHex, bigToLE32 } = await import(`file://${resolve(circuitsScripts, "poseidon_merkle.mjs")}`);

export const ASP_SET_SCHEME = "eunoma_asp_set_v1";

const toBig = (c) => (typeof c === "bigint" ? c : leBytesToBig(hexToLE32(c)));
const toHex = (c) => (typeof c === "bigint" ? le32ToHex(bigToLE32(c)) : String(c).toLowerCase());

// Normalize an approved entry to { commitmentBig, commitmentHex, labelHex }.
//   - A bare commitment (hex/bigint, legacy/no-label) is accepted: label defaults to the commitment
//     hex itself (degenerate 1-commitment "label" — preserves pre-label callers + tests).
//   - An object { commitment, label } binds the commitment to its deposit-scoped label so the
//     parent + every descendant change note share ONE label.
function normalizeEntry(entry) {
  if (entry && typeof entry === "object" && !Array.isArray(entry) && typeof entry !== "bigint") {
    const commitment = entry.commitment ?? entry.commitmentHex;
    if (commitment === undefined || commitment === null) {
      throw new Error("asp entry object missing { commitment }");
    }
    const commitmentHex = toHex(commitment);
    const labelHex = entry.label !== undefined && entry.label !== null ? toHex(entry.label) : commitmentHex;
    return { commitmentBig: toBig(commitment), commitmentHex, labelHex };
  }
  const commitmentHex = toHex(entry);
  return { commitmentBig: toBig(entry), commitmentHex, labelHex: commitmentHex };
}

// approved: array of commitment hex/bigint OR { commitment, label } entries. Order = insertion
// order (append-only within an epoch; revoked LABELS are omitted from the input on the next fork,
// which drops all of that label's commitments).
export async function buildAspTree(approved) {
  const tree = new LeanIMTTree();
  const labelByCommitment = {};
  const labelSet = new Set();
  for (const entry of approved) {
    const { commitmentBig, commitmentHex, labelHex } = normalizeEntry(entry);
    tree.append(commitmentBig, { commitmentHex });
    labelByCommitment[commitmentHex] = labelHex;
    labelSet.add(labelHex);
  }
  const root = await tree.root();
  const depth = await tree.depth();
  return { tree, root, depth, labelByCommitment, labels: [...labelSet] };
}

// Path for a specific commitment (for the withdraw witness ASP-inclusion side). The leaf is the
// COMMITMENT (circuit proves inclusion of cmt.out), unchanged by the label model.
export async function aspPathFor(tree, commitment) {
  return tree.pathForCommitment(toBig(commitment));
}

// The PUBLIC full-set artifact pinned to IPFS (commitments + labels only — no secrets; the
// LeanIMTTree forbidden-field gate enforces public-only). `updatedAtUnix` is the wall-clock record
// time the on-chain ASP_ROOT_TTL_SECS window is measured against (RF2 time-window, replacing the
// count-K window). `labels` is the approved deposit-scoped label set; `labelByCommitment` maps each
// listed commitment to its deposit-scoped label (so the next fork can OMIT a revoked label's
// commitments). `commitments` stays a FLAT, leaf-ordered hex array (the withdraw witness builder
// findIndex + the coordinator /v2/asp-set serve it verbatim).
export async function makeAspSetArtifact(approved, updatedAtUnix) {
  const { tree, root, depth, labelByCommitment, labels } = await buildAspTree(approved);
  const commitments = approved.map((e) => normalizeEntry(e).commitmentHex);
  const artifact = {
    scheme: ASP_SET_SCHEME,
    version: 1,
    treeDepth: depth,
    leafCount: commitments.length,
    rootHex: le32ToHex(bigToLE32(root)),
    commitments,
    labels,
    labelByCommitment,
    updatedAtUnix: updatedAtUnix ?? null,
  };
  return { artifact, root, depth, tree, labelByCommitment, labels };
}
