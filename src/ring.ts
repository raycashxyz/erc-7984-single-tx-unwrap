/**
 * The Galois ring GR(2^128, 4) = Z_{2^128}[X] / (X^4 + X + 1): the ring Zama's threshold KMS
 * Shamir-shares a decryption over (`threshold-fhe`'s `ResiduePolyF4<Z128>`). Party p is evaluated
 * at the element whose coefficients are p's bits.
 */
import { bytesToHex, hexToBytes, numberToHex } from "viem";

export type Gr = readonly [bigint, bigint, bigint, bigint];

type Coef = 0 | 1 | 2 | 3;

const MASK128 = (1n << 128n) - 1n;
const wrap = (v: bigint): bigint => v & MASK128; // two's complement, so negatives wrap too
const gr = (f: (i: Coef) => bigint): Gr => [f(0), f(1), f(2), f(3)];

export const ZERO: Gr = [0n, 0n, 0n, 0n];
export const ONE: Gr = [1n, 0n, 0n, 0n];
/** Bytes of one serialized element: four little-endian u128 coefficients. */
export const ELEMENT_BYTES = 64;

export const add = (a: Gr, b: Gr): Gr => gr((i) => wrap(a[i] + b[i]));
export const sub = (a: Gr, b: Gr): Gr => gr((i) => wrap(a[i] - b[i]));

/** Schoolbook product, then X^4 = -X - 1, X^5 = -X^2 - X, X^6 = -X^3 - X^2. */
export const mul = (a: Gr, b: Gr): Gr => {
  const [a0, a1, a2, a3] = a;
  const [b0, b1, b2, b3] = b;
  const p4 = a1 * b3 + a2 * b2 + a3 * b1;
  const p5 = a2 * b3 + a3 * b2;
  const p6 = a3 * b3;
  return [
    wrap(a0 * b0 - p4),
    wrap(a0 * b1 + a1 * b0 - p4 - p5),
    wrap(a0 * b2 + a1 * b1 + a2 * b0 - p5 - p6),
    wrap(a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 - p6),
  ];
};

export const partyPoint = (party: number): Gr => gr((i) => BigInt((party >> i) & 1));

/**
 * Inverse of a unit: the inverse mod 2 lives in GF(16) (15 candidates), then Newton
 * y ← y (2 − a y) doubles the precision 1 → 2 → … → 128 bits.
 */
export const inverse = (a: Gr): Gr => {
  const mod2 = (g: Gr): Gr => gr((i) => g[i] & 1n);
  const seed = Array.from({ length: 15 }, (_, i) => partyPoint(i + 1))
    .find((y) => mod2(mul(a, y)).every((c, i) => c === ONE[i]));
  if (seed === undefined) throw new Error("not a unit of GR(2^128, 4)");
  const two: Gr = [2n, 0n, 0n, 0n];
  return Array.from({ length: 7 }).reduce<Gr>((y) => mul(y, sub(two, mul(a, y))), seed);
};

/** Horner evaluation of Σ coefs[k] · x^k. */
export const evaluate = (coefs: readonly Gr[], x: Gr): Gr =>
  coefs.reduceRight<Gr>((acc, c) => add(mul(acc, x), c), ZERO);

/**
 * Lagrange interpolation: the coefficients (constant first) of the degree-(n−1) polynomial through
 * n points. Distinct party points differ by units, so every denominator is invertible.
 */
export const interpolate = (points: readonly Gr[], values: readonly Gr[]): Gr[] => {
  // poly · (X − root)
  const timesLinear = (poly: readonly Gr[], root: Gr): Gr[] =>
    Array.from({ length: poly.length + 1 }, (_, k) => sub(poly[k - 1] ?? ZERO, mul(poly[k] ?? ZERO, root)));
  return points.reduce<Gr[]>((acc, xi, i) => {
    const others = points.filter((_, j) => j !== i);
    const numerator = others.reduce<Gr[]>((p, xj) => timesLinear(p, xj), [ONE]);
    const denominator = others.reduce<Gr>((d, xj) => mul(d, sub(xi, xj)), ONE);
    const scale = mul(values[i] ?? ZERO, inverse(denominator));
    return acc.map((c, k) => add(c, mul(numerator[k] ?? ZERO, scale)));
  }, points.map(() => ZERO));
};

const le128 = (v: bigint): number[] => Array.from(hexToBytes(numberToHex(v, { size: 16 })).reverse());
const fromLe128 = (bytes: Uint8Array): bigint => BigInt(bytesToHex(Uint8Array.from(bytes).reverse()));

export const toBytes = (g: Gr): Uint8Array => Uint8Array.from(g.flatMap(le128));
export const fromBytes = (bytes: Uint8Array): Gr => gr((i) => fromLe128(bytes.slice(16 * i, 16 * i + 16)));

/** The elements of a byte string of 64-byte serialized elements. */
export const elementsOf = (bytes: Uint8Array): Gr[] =>
  Array.from({ length: bytes.length / ELEMENT_BYTES }, (_, j) =>
    fromBytes(bytes.slice(ELEMENT_BYTES * j, ELEMENT_BYTES * (j + 1))));
