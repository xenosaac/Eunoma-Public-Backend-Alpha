// ASP tree builder — builds the dynamic-depth LeanIMT over the curation-APPROVED commitments
// (label≡commitment: ASP leaf = the existing commitment). Produces the on-chain root/depth + the
// PUBLIC full-set artifact published to IPFS. Re-fork model: callers rebuild from the current
// approved set each epoch (excluding revoked) → new root → record via asp-recorder delegate.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const circuitsScripts = resolve(here, "..", "..", "circuits", "scripts");
const { LeanIMTTree } = await import(`file://${resolve(circuitsScripts, "leanimt_tree.mjs")}`);
const { leBytesToBig, hexToLE32, le32ToHex, bigToLE32 } = await import(`file://${resolve(circuitsScripts, "poseidon_merkle.mjs")}`);

export const ASP_SET_SCHEME = "eunoma_asp_set_v1";

const toBig = (c) => (typeof c === "bigint" ? c : leBytesToBig(hexToLE32(c)));
const toHex = (c) => (typeof c === "bigint" ? le32ToHex(bigToLE32(c)) : String(c).toLowerCase());

// approvedCommitments: array of commitment hex strings (or bigints), order = insertion order
// (append-only within an epoch; revoked ones are simply omitted from the input on the next fork).
export async function buildAspTree(approvedCommitments) {
  const tree = new LeanIMTTree();
  for (const c of approvedCommitments) {
    const big = toBig(c);
    tree.append(big, { commitmentHex: toHex(c) });
  }
  const root = await tree.root();
  const depth = await tree.depth();
  return { tree, root, depth };
}

// Path for a specific commitment (for the withdraw witness ASP-inclusion side).
export async function aspPathFor(tree, commitment) {
  return tree.pathForCommitment(toBig(commitment));
}

// The PUBLIC full-set artifact pinned to IPFS (commitments only — no secrets; LeanIMTTree's
// forbidden-field gate enforces public-only).
export async function makeAspSetArtifact(approvedCommitments, updatedAtUnix) {
  const { tree, root, depth } = await buildAspTree(approvedCommitments);
  const artifact = {
    scheme: ASP_SET_SCHEME,
    version: 1,
    treeDepth: depth,
    leafCount: approvedCommitments.length,
    rootHex: le32ToHex(bigToLE32(root)),
    commitments: approvedCommitments.map(toHex),
    updatedAtUnix: updatedAtUnix ?? null,
  };
  return { artifact, root, depth, tree };
}
