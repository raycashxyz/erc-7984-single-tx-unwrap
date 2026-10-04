/** The slice of snarkjs (which ships no types) this repo uses. */
declare module "snarkjs" {
  export const groth16: {
    fullProve: (
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string,
    ) => Promise<{ proof: unknown; publicSignals: string[] }>;
    exportSolidityCallData: (proof: unknown, publicSignals: readonly string[]) => Promise<string>;
  };
  export const wtns: {
    calculate: (input: Record<string, unknown>, wasmFile: string, wtnsFile: string) => Promise<void>;
  };
}
