//! Obfuscates UniFlow's own compiled-in rule/model assets so they are not
//! plaintext `strings`-recoverable from the built binary.
//!
//! # What this is, and what it deliberately is not
//!
//! The binary must decrypt these assets itself, at runtime, using only
//! material shipped inside that same binary — there is no server, no
//! hardware key store, no out-of-band secret. Under that constraint, a
//! sufficiently motivated reverse engineer can always recover the key or
//! the plaintext (run the binary under a debugger and dump memory right
//! after decryption, or statically emulate the handful of arithmetic
//! operations below, which is not a black box). **This module raises the
//! bar against casual extraction — `strings`/`grep` scraping, naive
//! byte-for-byte diffing between two builds' rule packs, and automated
//! signature-based scanners — it does not, and cannot, provide
//! cryptographic confidentiality against a determined attacker holding the
//! compiled binary.** Anyone deciding whether this is sufficient for their
//! threat model should read this paragraph twice.
//!
//! # Design choices, and why
//!
//! - **No S-box.** A substitution-permutation cipher (AES, DES) needs a
//!   lookup table, which is exactly the kind of static byte pattern
//!   signature-based crypto-constant scanners (`findcrypt`, `binwalk`,
//!   CyberChef's auto-detect) search a binary for — finding one all but
//!   announces "there is a cipher here, and here is its table." This
//!   module is instead an ARX (Add–Rotate/shift–XOR) construction: a
//!   counter-mode keystream generator built purely from wrapping
//!   multiplication, xor, and shifts, with no table at all.
//! - **No published constants.** It would defeat the point above to build
//!   an ARX mixer and then key it with SplitMix64's golden-ratio
//!   multiplier, FNV's prime/offset, or MurmurHash3's finalizer constants —
//!   those are just as fingerprintable via a constants database as an
//!   S-box is. Every constant below was picked arbitrarily for this module
//!   and does not correspond to any published cipher, hash, or PRNG.
//! - **No single recognizable key blob.** The effective key is the mix of
//!   three independently-declared constants (see `master_key`), not one
//!   32-byte array that stands out under a diff between two binary builds.
//! - **No separate integrity checksum.** The ciphertext carries no magic
//!   header of its own to validate against — that would hand a brute-force
//!   attempt an easy "did I guess right" oracle. Correctness is instead
//!   verified implicitly by whatever the caller does with the recovered
//!   bytes (parsing them as YAML/JSON/bincode already fails loudly on
//!   wrong output).
//! - **Per-asset keystream.** Every embedded asset is transformed under a
//!   `label` (its own logical name) that is mixed into the keystream seed,
//!   so two different assets never share a keystream — reusing one would
//!   let an attacker XOR two ciphertexts together to cancel the keystream
//!   entirely (the classic "two-time pad" break), independent of how good
//!   the mixer itself is.

/// Three independent, unremarkable-looking constants. Only their *mix*
/// (see `master_key`) is ever used as the effective key — never one of
/// these values alone — so no single contiguous byte range in the binary
/// is "the key."
const KEY_PART_A: u64 = 0xA17C_5E93_B02D_4471;
const KEY_PART_B: u64 = 0x5B8E_21F0_6C93_AA17;
const KEY_PART_C: u64 = 0x3F46_C902_18AD_7E5B;

/// Multipliers for `mix`. Arbitrary, odd (required for the multiplication
/// to mix every output bit), and unrelated to any published cipher/hash/PRNG
/// constant.
const MIX_MULTIPLIER_1: u64 = 0xD1B5_4A32_9C6F_0E77;
const MIX_MULTIPLIER_2: u64 = 0x8A43_F219_5E70_C9AB;

/// Seed and multiplier for `label_seed`'s rolling hash. This hash is not
/// itself secret or security-load-bearing — its only job is to decorrelate
/// otherwise-identical keystreams across different embedded assets — so
/// its own values need no particular cryptographic property beyond being
/// unrelated to the key constants above.
const LABEL_HASH_SEED: u64 = 0x6C51_9E84_D3AF_2C07;
const LABEL_HASH_MULTIPLIER: u64 = 0x2F1B_8D45_9AC3_7061;

/// A small ARX finalizer: three xor-shift/multiply rounds, the same shape
/// common 64-bit integer hash finalizers use, but with this module's own
/// constants rather than a published one.
fn mix(mut x: u64) -> u64 {
    x ^= x >> 31;
    x = x.wrapping_mul(MIX_MULTIPLIER_1);
    x ^= x >> 27;
    x = x.wrapping_mul(MIX_MULTIPLIER_2);
    x ^= x >> 33;
    x
}

fn master_key() -> u64 {
    mix(KEY_PART_A) ^ mix(KEY_PART_B).rotate_left(23) ^ KEY_PART_C
}

/// A non-cryptographic rolling hash of `label`, used only to give each
/// distinct asset its own keystream (see the module doc comment).
fn label_seed(label: &str) -> u64 {
    let mut state = LABEL_HASH_SEED;
    for byte in label.as_bytes() {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(LABEL_HASH_MULTIPLIER);
    }
    state
}

/// Applies (or, identically, removes — XOR is its own inverse) a keyed
/// keystream to `data`, unique per `label`. The same call is used both to
/// produce the embedded ciphertext (in a build script, at compile time)
/// and to recover the original bytes (in the running program, at first
/// use) — `transform(label, transform(label, data)) == data` for any
/// `label`/`data`. See the module doc comment for exactly what this is,
/// and is not, intended to defend against.
pub fn transform(label: &str, data: &[u8]) -> Vec<u8> {
    let mut state = mix(master_key() ^ label_seed(label));
    let mut counter: u64 = 0;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        state = mix(state.wrapping_add(counter));
        counter = counter.wrapping_add(1);
        let keystream_block = state.to_le_bytes();
        for (byte, key) in chunk.iter().zip(keystream_block.iter()) {
            out.push(byte ^ key);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_is_its_own_inverse() {
        let plaintext = b"rule: sink-taint-flow\nid: EXAMPLE-001\n".to_vec();
        let ciphertext = transform("example.yml", &plaintext);
        assert_ne!(ciphertext, plaintext, "must not be a no-op");
        let recovered = transform("example.yml", &ciphertext);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn empty_input_round_trips() {
        let ciphertext = transform("empty.yml", &[]);
        assert!(ciphertext.is_empty());
        assert_eq!(transform("empty.yml", &ciphertext), Vec::<u8>::new());
    }

    #[test]
    fn input_not_a_multiple_of_the_block_size_round_trips() {
        for len in 0..40 {
            let plaintext = (0..len).map(|i| i as u8).collect::<Vec<_>>();
            let ciphertext = transform("odd-length", &plaintext);
            assert_eq!(ciphertext.len(), plaintext.len());
            assert_eq!(transform("odd-length", &ciphertext), plaintext);
        }
    }

    #[test]
    fn different_labels_produce_different_keystreams_for_the_same_plaintext() {
        let plaintext = vec![0u8; 64];
        let a = transform("asset-a.yml", &plaintext);
        let b = transform("asset-b.yml", &plaintext);
        assert_ne!(a, b, "two different assets must never share a keystream (two-time-pad risk)");
    }

    #[test]
    fn transform_is_deterministic_across_calls() {
        // Required for reproducible builds: a build script calling this
        // twice for the same asset must embed byte-identical ciphertext.
        let plaintext = b"deterministic".to_vec();
        assert_eq!(transform("same-label", &plaintext), transform("same-label", &plaintext));
    }

    #[test]
    fn output_is_not_trivially_patterned() {
        // A weak/broken mixer (e.g. one that accidentally always emits the
        // same keystream block) would show up as long repeated runs even
        // over all-zero input. Not a cryptographic claim — just a sanity
        // check that the keystream actually varies block to block.
        let plaintext = vec![0u8; 256];
        let ciphertext = transform("pattern-check", &plaintext);
        let first_block = &ciphertext[0..8];
        let all_blocks_identical = ciphertext.chunks(8).all(|block| block == first_block);
        assert!(!all_blocks_identical, "keystream must vary across blocks");
    }
}
