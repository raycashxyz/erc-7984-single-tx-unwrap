pragma circom 2.2.0;

// One-transaction ERC-7984 unwrap: Groth16 version of `../noir/src/main.nr`.
//
// A Zama KMS node signs each user-decryption share before encrypting it:
//
//   digest_i = SHA-256("USER_DEC" ‖ bincode(SigncryptionPayload{share_i, link}) ‖ user ‖ H(enc_key))
//
// The contract `ecrecover`s each node from (digest_i, signature_i) and passes the digests in as
// public inputs, next to the link, user and amount it computes from its own state. This circuit
// proves, with the shares private:
//
//  1. each digest_i is the SHA-256 of a well-formed message around share_i, for 2t + 1 = 9 nodes;
//  2. all shares lie on one degree-4 polynomial over GR(2^128, 4) (prover supplies coefficients);
//  3. the decoded constant term (a euint64) is >= amount.
//
// Public inputs, in order: link[2] ‖ user ‖ amount ‖ parties[9] ‖ digests[9][2] — the same 31 values,
// in the same order, as the Noir circuit (`KmsUserDecryption.publicInputs`).

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Multiplies a GR(2^128, 4) element by a party point x (0/1 coefficients) in Z[X]/(X^4 + X + 1),
// without reducing mod 2^128: X^4 = -X - 1, X^5 = -X^2 - X, X^6 = -X^3 - X^2.
template GrMulPoint() {
    signal input a[4];
    signal input x[4];
    signal output out[4];

    signal prod[4][4];
    var p[7] = [0, 0, 0, 0, 0, 0, 0];
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 4; j++) {
            prod[i][j] <== a[i] * x[j];
            p[i + j] += prod[i][j];
        }
    }
    out[0] <== p[0] - p[4];
    out[1] <== p[1] - p[4] - p[5];
    out[2] <== p[2] - p[5] - p[6];
    out[3] <== p[3] - p[6];
}

// TFHE's from_expanded_msg for 4 message+carry bits on a 128-bit torus, Δ = 2^123: raw >= 2^128 −
// 2^123 (top five bits set) is negative noise around 0 → 0; otherwise ((raw + 2^122) >> 123) mod 16,
// i.e. (top5 + bit122) mod 16. Also range-checks raw to 128 bits.
template DecodeBlock() {
    signal input raw;
    signal output out;

    component bits = Num2Bits(128);
    bits.in <== raw;
    var top5 = 0;
    for (var k = 0; k < 5; k++) {
        top5 += bits.out[123 + k] * (1 << k);
    }
    component rounded = Num2Bits(6); // top5 + bit122 is at most 32
    rounded.in <== top5 + bits.out[122];
    component negative = IsEqual();
    negative.in[0] <== top5;
    negative.in[1] <== 31;
    out <== (1 - negative.out) * (rounded.out[0] + 2 * rounded.out[1] + 4 * rounded.out[2] + 8 * rounded.out[3]);
}

template Unwrap() {
    var SHARES = 9; // 2t + 1 for the n = 13, t = 4 KMS
    var DEGREE = 4; // t
    var SHARE_BYTES = 256; // 4 ring elements × 4 little-endian u128 coefficients
    var MESSAGE_BITS = 3008; // 376 bytes
    var TWO_128 = 2 ** 128;
    var QUOTIENT_BIAS = 2 ** 148; // 2^20 · 2^128

    // "USER_DEC" ‖ len(TypedPlaintext.bytes) = 264 ‖ len(Vec) = 4 elements (u64 LE each)
    var PREFIX[24] = [0x55, 0x53, 0x45, 0x52, 0x5f, 0x44, 0x45, 0x43, 0x08, 0x01, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0];
    // fhe_type = Uint64 (i32 LE) ‖ len(link) = 32 (u64 LE)
    var MIDDLE[12] = [5, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0];

    signal input link[2];
    signal input user;
    signal input amount;
    signal input parties[SHARES];
    signal input digests[SHARES][2];

    signal input encKeyHash[2];
    signal input shares[SHARES][SHARE_BYTES];
    signal input poly[DEGREE + 1][4][4];

    // link ‖ user ‖ H(enc_key) — identical in all nine messages; the decompositions also
    // range-check them.
    component linkBits[2];
    component encBits[2];
    for (var h = 0; h < 2; h++) {
        linkBits[h] = Num2Bits(128);
        linkBits[h].in <== link[h];
        encBits[h] = Num2Bits(128);
        encBits[h].in <== encKeyHash[h];
    }
    component userBits = Num2Bits(160);
    userBits.in <== user;
    component amountBits = Num2Bits(64);
    amountBits.in <== amount;

    // The constant term is range-checked by DecodeBlock.
    component polyBits[DEGREE][4][4];
    for (var k = 1; k <= DEGREE; k++) {
        for (var j = 0; j < 4; j++) {
            for (var a = 0; a < 4; a++) {
                polyBits[k - 1][j][a] = Num2Bits(128);
                polyBits[k - 1][j][a].in <== poly[k][j][a];
            }
        }
    }

    component shareBits[SHARES][SHARE_BYTES];
    component sha[SHARES];
    component point[SHARES];
    component mul[SHARES][4][DEGREE];
    signal eval[SHARES][4][DEGREE + 1][4];
    signal quotient[SHARES][4][4];
    component quotientBits[SHARES][4][4];

    for (var s = 0; s < SHARES; s++) {
        // --- 1. digest of the signed message -----------------------------------------------
        sha[s] = Sha256(MESSAGE_BITS);
        for (var b = 0; b < 24; b++) {
            for (var t = 0; t < 8; t++) {
                sha[s].in[8 * b + t] <== (PREFIX[b] >> (7 - t)) & 1;
            }
        }
        for (var b = 0; b < SHARE_BYTES; b++) {
            shareBits[s][b] = Num2Bits(8);
            shareBits[s][b].in <== shares[s][b];
            for (var t = 0; t < 8; t++) {
                sha[s].in[8 * (24 + b) + t] <== shareBits[s][b].out[7 - t];
            }
        }
        for (var b = 0; b < 12; b++) {
            for (var t = 0; t < 8; t++) {
                sha[s].in[8 * (280 + b) + t] <== (MIDDLE[b] >> (7 - t)) & 1;
            }
        }
        for (var i = 0; i < 128; i++) {
            sha[s].in[8 * 292 + i] <== linkBits[0].out[127 - i];
            sha[s].in[8 * 308 + i] <== linkBits[1].out[127 - i];
            sha[s].in[8 * 344 + i] <== encBits[0].out[127 - i];
            sha[s].in[8 * 360 + i] <== encBits[1].out[127 - i];
        }
        for (var i = 0; i < 160; i++) {
            sha[s].in[8 * 324 + i] <== userBits.out[159 - i];
        }
        var hi = 0;
        var lo = 0;
        for (var i = 0; i < 128; i++) {
            hi += sha[s].out[i] * 2 ** (127 - i);
            lo += sha[s].out[128 + i] * 2 ** (127 - i);
        }
        digests[s][0] === hi;
        digests[s][1] === lo;

        // --- 2. the share lies on the polynomial -------------------------------------------
        // Party p's evaluation point has p's bits as coefficients (party ids are < 16).
        point[s] = Num2Bits(4);
        point[s].in <== parties[s];
        for (var j = 0; j < 4; j++) {
            // Horner without reduction: each step grows coefficients by at most 12×, so
            // |eval| < 22621 · 2^128 < 2^143.
            for (var a = 0; a < 4; a++) {
                eval[s][j][0][a] <== poly[DEGREE][j][a];
            }
            for (var step = 1; step <= DEGREE; step++) {
                mul[s][j][step - 1] = GrMulPoint();
                mul[s][j][step - 1].a <== eval[s][j][step - 1];
                mul[s][j][step - 1].x <== point[s].out;
                for (var a = 0; a < 4; a++) {
                    eval[s][j][step][a] <== mul[s][j][step - 1].out[a] + poly[DEGREE - step][j][a];
                }
            }
            for (var a = 0; a < 4; a++) {
                var coefficient = 0; // little-endian u128 in the share
                for (var m = 0; m < 16; m++) {
                    coefficient += shares[s][16 * (4 * j + a) + m] * 256 ** m;
                }
                // eval − share = (q − 2^20) · 2^128 with q < 2^21: only exact multiples of 2^128
                // land in that range, since |eval − share| < 2^144.
                quotient[s][j][a] <-- (eval[s][j][DEGREE][a] - coefficient + QUOTIENT_BIAS) / TWO_128;
                quotient[s][j][a] * TWO_128 === eval[s][j][DEGREE][a] - coefficient + QUOTIENT_BIAS;
                quotientBits[s][j][a] = Num2Bits(21);
                quotientBits[s][j][a].in <== quotient[s][j][a];
            }
        }
    }

    // --- 3. the constant term decodes to >= amount ----------------------------------------
    component decode[16];
    var balance = 0;
    for (var j = 0; j < 4; j++) {
        for (var a = 0; a < 4; a++) {
            decode[4 * j + a] = DecodeBlock();
            decode[4 * j + a].raw <== poly[0][j][a];
            balance += decode[4 * j + a].out * 16 ** (4 * j + a);
        }
    }
    component covers = Num2Bits(64);
    covers.in <== balance - amount;
}

component main {public [link, user, amount, parties, digests]} = Unwrap();
