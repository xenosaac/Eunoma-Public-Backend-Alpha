// Ambient module declarations for JS-only deps (no upstream types).

declare module "circomlibjs" {
  export function buildPoseidon(): Promise<any>;
  // Other exports we don't use here; kept open.
  const _default: any;
  export default _default;
}

declare module "snarkjs" {
  export const groth16: {
    verify(vk: any, publicSignals: string[], proof: any): Promise<boolean>;
    fullProve(input: any, wasmPath: string, zkeyPath: string): Promise<any>;
    prove(zkeyPath: string, witness: any): Promise<any>;
  };
}
