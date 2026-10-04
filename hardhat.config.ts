// Hardhat only compiles; tests run on tevm (see test/setup/environment.ts). `@deployoor/hardhat`
// regenerates the typed deployers in src/deployers after every compile.
import "@deployoor/hardhat";
import type { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  solidity: {
    version: "0.8.27",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "cancun",
    },
  },
};

export default config;
