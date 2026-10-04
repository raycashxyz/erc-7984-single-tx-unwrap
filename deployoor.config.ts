import { defineConfig } from "deployoor";

export default defineConfig({
  out: "./src/deployers",
  deploymentsPath: "./deployments",
  include:
    /^(SingleTxUnwrapWrapper|StandardERC7984Wrapper|UnwrapHonkVerifier|UnwrapGroth16Verifier|CircomUnwrapVerifier|UnwrapAndSwap|MockERC20|MockSwapPool|MockUnwrapProofVerifier|KmsUserDecryptionHarness|VerifierGasProbe)$/,
  redeploymentStrategy: "on-change",
});
