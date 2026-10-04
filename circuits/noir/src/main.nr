//! UltraHonk (Barretenberg) circuit for the one-transaction unwrap.
//!
//! A Zama KMS node signs each user-decryption share before encrypting it:
//!
//!   digest_i = SHA-256("USER_DEC" ‖ bincode(SigncryptionPayload{share_i, link}) ‖ user ‖ H(enc_key))
//!
//! `SingleTxUnwrapWrapper` `ecrecover`s each node from (digest_i, signature_i) and passes the
//! digests in as public inputs, next to the link, user and amount it computes from its own state.
//! This circuit proves, with the shares private:
//!
//!  1. each digest_i is the SHA-256 of a well-formed message around share_i, for 2t + 1 = 9 parties;
//!  2. all shares lie on one degree-4 polynomial over GR(2^128, 4) (prover supplies coefficients);
//!  3. the decoded constant term (a euint64) is >= amount.
//!
//! H(enc_key) stays private: each signed digest already commits to it.

use std::hash::sha256_compression;

global SHARES: u32 = 9; // 2t + 1 for the n = 13, t = 4 KMS
global DEGREE: u32 = 4; // t
global ELEMENTS: u32 = 4; // ring elements per euint64 share (16 four-bit blocks, packing factor 2)
global COEFS: u32 = 4; // GR(2^128, 4) coefficients per element
global SHARE_BYTES: u32 = 256; // ELEMENTS × COEFS little-endian u128s
global MESSAGE_WORDS: u32 = 112; // the 376-byte signed message, padded to 7 SHA-256 blocks

global TWO_122: Field = 0x4000000000000000000000000000000;
global TWO_123: Field = 0x8000000000000000000000000000000;
global TWO_128: Field = 0x100000000000000000000000000000000;
global QUOTIENT_BIAS: Field = 0x10000000000000000000000000000000000000; // 2^20 · 2^128

global SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// The signed message as big-endian words:
// "USER_DEC" ‖ len(TypedPlaintext.bytes) = 264 ‖ len(Vec) = 4 elements (u64 LE each) ‖
global MESSAGE_PREFIX: [u32; 6] = [0x55534552, 0x5f444543, 0x08010000, 0, 0x04000000, 0];
// share (64 words) ‖ fhe_type = Uint64 (i32 LE) ‖ len(link) = 32 (u64 LE) ‖
global MESSAGE_MIDDLE: [u32; 3] = [0x05000000, 0x20000000, 0];
// link (8 words) ‖ user (5) ‖ H(enc_key) (8) ‖ SHA-256 padding for 376 bytes (3008 bits).
global PADDING: [u32; 18] = [0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbc0];

fn main(
    link: pub [Field; 2],
    user: pub Field,
    amount: pub u64,
    parties: pub [u8; SHARES],
    digests: pub [[Field; 2]; SHARES],
    enc_key_hash: [u32; 8],
    shares: [[u8; SHARE_BYTES]; SHARES],
    poly: [[[Field; COEFS]; ELEMENTS]; DEGREE + 1],
) {
    // Identical in all nine messages: link ‖ user ‖ H(enc_key).
    let tail = be_words::<4>(link[0])
        .concat(be_words::<4>(link[1]))
        .concat(be_words::<5>(user))
        .concat(enc_key_hash);
    // The constant term is range-checked by `decode_block`.
    for k in 1..DEGREE + 1 {
        for j in 0..ELEMENTS {
            for a in 0..COEFS {
                poly[k][j][a].assert_max_bit_size::<128>();
            }
        }
    }
    for i in 0..SHARES {
        let digest = sha256(MESSAGE_PREFIX
            .concat(share_words(shares[i]))
            .concat(MESSAGE_MIDDLE)
            .concat(tail)
            .concat(PADDING));
        assert(digests[i][0] == u128_be(digest, 0));
        assert(digests[i][1] == u128_be(digest, 4));
        assert_on_polynomial(poly, party_point(parties[i]), shares[i]);
    }

    let balance = decode_u64(poly[0]);
    (balance - amount as Field).assert_max_bit_size::<64>(); // balance >= amount
}

fn sha256(words: [u32; MESSAGE_WORDS]) -> [u32; 8] {
    let mut state = SHA256_IV;
    for b in 0..MESSAGE_WORDS / 16 {
        let mut block = [0; 16];
        for w in 0..16 {
            block[w] = words[16 * b + w];
        }
        state = sha256_compression(block, state);
    }
    state
}

/// A share's 64 big-endian message words. The bytes are range-checked, so each packed word is
/// below 2^32 by construction; the hint only hands it over typed as u32.
fn share_words(share: [u8; SHARE_BYTES]) -> [u32; SHARE_BYTES / 4] {
    let mut words = [0; SHARE_BYTES / 4];
    for w in 0..SHARE_BYTES / 4 {
        let packed = share[4 * w] as Field * 0x1000000
            + share[4 * w + 1] as Field * 0x10000
            + share[4 * w + 2] as Field * 0x100
            + share[4 * w + 3] as Field;
        // Safety: constrained equal to `packed` below.
        let word = unsafe { field_to_u32(packed) };
        assert(word as Field == packed);
        words[w] = word;
    }
    words
}

/// The N big-endian 32-bit words of `value`, which must be below 2^(32·N) (N <= 7).
fn be_words<let N: u32>(value: Field) -> [u32; N] {
    // Safety: the words are u32-range-checked and recombined into `value` below.
    let words: [u32; N] = unsafe { split_be_words(value) };
    assert(words.fold(0, |acc: Field, w| acc * 0x100000000 + w as Field) == value);
    words
}

/// Four digest words from `from`, big-endian, as one 128-bit field element.
fn u128_be(digest: [u32; 8], from: u32) -> Field {
    let mut v: Field = 0;
    for w in 0..4 {
        v = v * 0x100000000 + digest[from + w] as Field;
    }
    v
}

/// Little-endian u128 at `16 · index` in a share.
fn u128_le(share: [u8; SHARE_BYTES], index: u32) -> Field {
    let mut v: Field = 0;
    for m in 0..16 {
        v = v * 256 + share[index * 16 + 15 - m] as Field;
    }
    v
}

type Gr = [Field; COEFS];

/// Multiplies in Z[X]/(X^4 + X + 1) without reducing mod 2^128 (magnitudes stay far below the
/// field size): X^4 = -X - 1, X^5 = -X^2 - X, X^6 = -X^3 - X^2.
fn gr_mul(a: Gr, b: Gr) -> Gr {
    let mut p = [0; 7];
    for i in 0..COEFS {
        for j in 0..COEFS {
            p[i + j] += a[i] * b[j];
        }
    }
    [p[0] - p[4], p[1] - p[4] - p[5], p[2] - p[5] - p[6], p[3] - p[6]]
}

/// Party `p`'s evaluation point: the coefficients are p's bits (party ids are < 16).
fn party_point(party: u8) -> Gr {
    let bits: [bool; 4] = (party as Field).to_le_bits();
    bits.map(|bit| bit as Field)
}

/// Every coefficient of `share` equals the polynomial at `x`, mod 2^128.
fn assert_on_polynomial(poly: [[Gr; ELEMENTS]; DEGREE + 1], x: Gr, share: [u8; SHARE_BYTES]) {
    for j in 0..ELEMENTS {
        // Horner without reduction: x has 0/1 coefficients, so each step grows the coefficients by
        // at most 12×, and |eval| < 22621 · 2^128 < 2^143.
        let mut eval = poly[DEGREE][j];
        for k in 1..DEGREE + 1 {
            let term = gr_mul(eval, x);
            for a in 0..COEFS {
                eval[a] = term[a] + poly[DEGREE - k][j][a];
            }
        }
        for a in 0..COEFS {
            // eval − share = (q − 2^20) · 2^128 with q < 2^21: dividing by 2^128 in the field
            // lands in that range only for exact multiples, since |eval − share| < 2^144.
            let q = (eval[a] - u128_le(share, j * COEFS + a) + QUOTIENT_BIAS) / TWO_128;
            q.assert_max_bit_size::<21>();
        }
    }
}

/// The euint64 in the constant term: 16 four-bit blocks, little-endian across elements and
/// coefficients.
fn decode_u64(secret: [Gr; ELEMENTS]) -> Field {
    let mut balance: Field = 0;
    for b in 0..ELEMENTS * COEFS {
        let block = ELEMENTS * COEFS - 1 - b;
        balance = balance * 16 + decode_block(secret[block / COEFS][block % COEFS]);
    }
    balance
}

/// TFHE's from_expanded_msg for 4 message+carry bits on a 128-bit torus, Δ = 2^123:
/// raw >= 2^128 − 2^123 (top five bits all set) is negative noise around 0 → 0; otherwise
/// ((raw + 2^122) >> 123) mod 16. With raw = low + b122·2^122 + top5·2^123, that shift is
/// top5 + b122. The split also range-checks raw to 128 bits.
fn decode_block(raw: Field) -> Field {
    // Safety: the split is range-checked and recombined into `raw` below.
    let (low, b122, top5) = unsafe { split_torus(raw) };
    low.assert_max_bit_size::<122>();
    assert(b122 * (1 - b122) == 0);
    top5.assert_max_bit_size::<5>();
    assert(raw == low + b122 * TWO_122 + top5 * TWO_123);

    let rounded = top5 + b122; // in [0, 32]
    // Safety: rounded = 16·h + r is range-checked below.
    let (h, r) = unsafe { div16(rounded) };
    assert(h * (h - 1) * (h - 2) == 0);
    r.assert_max_bit_size::<4>();
    assert(rounded == h * 16 + r);
    if top5 == 31 {
        0
    } else {
        r
    }
}

unconstrained fn field_to_u32(v: Field) -> u32 {
    v as u32
}

unconstrained fn split_be_words<let N: u32>(value: Field) -> [u32; N] {
    let bytes: [u8; 32] = value.to_be_bytes();
    let mut words = [0; N];
    for k in 0..N {
        let at = 32 - 4 * (N - k);
        words[k] = ((bytes[at] as u32) << 24)
            | ((bytes[at + 1] as u32) << 16)
            | ((bytes[at + 2] as u32) << 8)
            | (bytes[at + 3] as u32);
    }
    words
}

unconstrained fn split_torus(raw: Field) -> (Field, Field, Field) {
    let bits: [bool; 128] = raw.to_le_bits();
    let mut low: Field = 0;
    for m in 0..122 {
        low = low * 2 + bits[121 - m] as Field;
    }
    let mut top5: Field = 0;
    for m in 0..5 {
        top5 = top5 * 2 + bits[127 - m] as Field;
    }
    (low, bits[122] as Field, top5)
}

unconstrained fn div16(v: Field) -> (Field, Field) {
    let bits: [bool; 6] = v.to_le_bits();
    let r = bits[0] as Field + bits[1] as Field * 2 + bits[2] as Field * 4 + bits[3] as Field * 8;
    (bits[4] as Field + bits[5] as Field * 2, r)
}

#[test]
fn decode_block_rounds_and_maps_negative_noise_to_zero() {
    assert(decode_block(5) == 0);
    assert(decode_block(TWO_128 - 6) == 0);
    assert(decode_block(7 * TWO_123 + 77) == 7);
    assert(decode_block(7 * TWO_123 + TWO_122) == 8); // rounds up
    assert(decode_block(15 * TWO_123 + TWO_122) == 0); // 16 wraps to 0
}

#[test]
fn gr_mul_reduces_by_x4_plus_x_plus_1() {
    let x = [0, 1, 0, 0];
    let x3 = gr_mul(gr_mul(x, x), x);
    assert(gr_mul(x3, x) == [-1, -1, 0, 0]);
}

#[test]
fn sha256_matches_the_known_digest_of_a_376_byte_message() {
    let digest = sha256([0x61616161; 94].concat(PADDING));
    assert((digest[0], digest[7]) == (0x5682d6b3, 0x1d080181));
}

#[test]
fn be_words_splits_and_recombines_a_160_bit_value() {
    let words = be_words::<5>(0xddaff95c5bad81dfd176d57a0df6a2ac7594193b);
    assert(words == [0xddaff95c, 0x5bad81df, 0xd176d57a, 0x0df6a2ac, 0x7594193b]);
}

#[test(should_fail)]
fn be_words_rejects_a_value_wider_than_its_words() {
    let _ = be_words::<4>(TWO_128);
}
