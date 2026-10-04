/**
 * Composability: unwrap confidential USDC and swap it for WETH on an AMM in one transaction
 * (`contracts/examples/UnwrapAndSwap.sol`). The two-step unwrap cannot do this — its USDC only
 * arrives in a second transaction, after the public decryption — so the swap would have to be a
 * third transaction against a price that may have moved.
 */
import {
  describe, expect, it,
} from "vitest";
import { parseUnits } from "viem";
import { proveNoir } from "../src/prove";
import { getOrDeployMockERC20 } from "../src/deployers/MockERC20";
import { getOrDeployMockSwapPool } from "../src/deployers/MockSwapPool";
import { getOrDeployUnwrapAndSwap } from "../src/deployers/UnwrapAndSwap";
import { expectRevert } from "./setup/assertions";
import { fheTxOpts, txOpts } from "./setup/environment";
import {
  canProveNoir, deployerOptions, setupWrapper,
} from "./setup/wrapper";
import type { ProofSystem } from "./setup/wrapper";

const USDC = (amount: string): bigint => parseUnits(amount, 6);
const WETH = (amount: string): bigint => parseUnits(amount, 18);

/** The pool's quote for `amountIn`, as `MockSwapPool` computes it (x · y = k, 0.3% fee). */
const quote = (amountIn: bigint, reserveIn: bigint, reserveOut: bigint): bigint =>
  (amountIn * 997n * reserveOut) / (reserveIn * 1000n + amountIn * 997n);

const setupSwap = async ({ system = "mock" }: { system?: ProofSystem } = {}) => {
  const wrapperSetup = await setupWrapper({ system });
  const { env, usdc, sendAndWait } = wrapperSetup;
  const opts = deployerOptions(env);
  const { contract: weth } = await getOrDeployMockERC20({ ...opts, args: ["Wrapped Ether", "WETH", 18] });
  const { contract: pool } = await getOrDeployMockSwapPool({ ...opts, args: [usdc.address, weth.address] });
  const { contract: router } = await getOrDeployUnwrapAndSwap({ ...opts, args: [] });
  const reserves = { usdc: USDC("4000000"), weth: WETH("1000") };
  await sendAndWait(usdc.write.mint([pool.address, reserves.usdc], txOpts(env.deployer.account)));
  await sendAndWait(weth.write.mint([pool.address, reserves.weth], txOpts(env.deployer.account)));
  return {
    ...wrapperSetup,
    weth,
    pool,
    router,
    reserves,
  };
};

describe("unwrap and swap in one transaction", () => {
  it("unwraps confidential USDC and swaps it for WETH", async () => {
    const {
      env: { alice }, wrapper, usdc, weth, pool, router, reserves, fund, decryptBalance, userDecryption, proveOnMock, sendAndWait,
    } = await setupSwap();
    await fund(alice, USDC("1000"));
    await sendAndWait(wrapper.write.setOperator([router.address, 2 ** 40], txOpts(alice.account)));
    const prepared = await userDecryption({ holder: alice.account.address, balance: USDC("1000"), amount: USDC("400") });
    await proveOnMock(prepared);
    const expectedOut = quote(USDC("400"), reserves.usdc, reserves.weth);
    expect(await decryptBalance(alice)).toBe(USDC("1000"));
    expect(await weth.read.balanceOf([alice.account.address])).toBe(0n);

    await sendAndWait(router.write.unwrapAndSwap([
      wrapper.address,
      USDC("400"),
      prepared.signed,
      "0x",
      pool.address,
      weth.address,
      expectedOut,
    ], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(USDC("600"));
    expect(await weth.read.balanceOf([alice.account.address])).toBe(expectedOut);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(0n);
    expect(await usdc.read.balanceOf([router.address])).toBe(0n);
  });

  it("rolls the unwrap back when the swap misses its minimum output", async () => {
    const {
      env: { alice }, wrapper, weth, pool, router, reserves, fund, decryptBalance, balanceHandle, userDecryption, proveOnMock, sendAndWait,
    } = await setupSwap();
    await fund(alice, USDC("1000"));
    await sendAndWait(wrapper.write.setOperator([router.address, 2 ** 40], txOpts(alice.account)));
    const prepared = await userDecryption({ holder: alice.account.address, balance: USDC("1000"), amount: USDC("400") });
    await proveOnMock(prepared);
    const handleBefore = await balanceHandle(alice.account.address);
    const tooMuch = quote(USDC("400"), reserves.usdc, reserves.weth) + 1n;

    await expectRevert(
      router.write.unwrapAndSwap([
        wrapper.address,
        USDC("400"),
        prepared.signed,
        "0x",
        pool.address,
        weth.address,
        tooMuch,
      ], txOpts(alice.account)),
      pool.abi,
      "InsufficientOutput",
    );

    expect(await balanceHandle(alice.account.address)).toBe(handleBefore);
    expect(await decryptBalance(alice)).toBe(USDC("1000"));
  });

  it("only unwraps the caller's own balance", async () => {
    const {
      env: { alice, bob }, wrapper, weth, pool, router, fund, userDecryption, proveOnMock, sendAndWait,
    } = await setupSwap();
    await fund(alice, USDC("1000"));
    await sendAndWait(wrapper.write.setOperator([router.address, 2 ** 40], txOpts(alice.account)));
    const prepared = await userDecryption({ holder: alice.account.address, balance: USDC("1000"), amount: USDC("400") });
    await proveOnMock(prepared);

    // Bob replays Alice's decryption: the router unwraps msg.sender (Bob), whose handle it isn't.
    await expectRevert(
      router.write.unwrapAndSwap([
        wrapper.address,
        USDC("400"),
        prepared.signed,
        "0x",
        pool.address,
        weth.address,
        0n,
      ], txOpts(bob.account)),
      wrapper.abi,
      "ERC7984UnauthorizedSpender",
    );
  });
});

describe.runIf(canProveNoir())("unwrap and swap with a real UltraHonk proof", () => {
  it("unwraps confidential USDC and swaps it for WETH", async () => {
    const {
      env: { alice }, wrapper, weth, pool, router, reserves, fund, decryptBalance, userDecryption, sendAndWait,
    } = await setupSwap({ system: "noir" });
    await fund(alice, USDC("1000"));
    await sendAndWait(wrapper.write.setOperator([router.address, 2 ** 40], txOpts(alice.account)));
    const prepared = await userDecryption({ holder: alice.account.address, balance: USDC("1000"), amount: USDC("400") });
    const { proof } = proveNoir(prepared.witness);
    const expectedOut = quote(USDC("400"), reserves.usdc, reserves.weth);
    expect(await weth.read.balanceOf([alice.account.address])).toBe(0n);

    await sendAndWait(router.write.unwrapAndSwap([
      wrapper.address,
      USDC("400"),
      prepared.signed,
      proof,
      pool.address,
      weth.address,
      expectedOut,
    ], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(USDC("600"));
    expect(await weth.read.balanceOf([alice.account.address])).toBe(expectedOut);
  });
});
