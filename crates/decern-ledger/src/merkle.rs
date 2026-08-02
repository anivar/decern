// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! RFC 9162 (Certificate Transparency 2.0) Merkle tree — the compact-proof layer over
//! the linear hash chain. The chain already proves a record's *bytes* and its *position*
//! relative to its neighbours; a Merkle tree over the per-record hashes adds two things the
//! chain cannot give compactly:
//!
//!   * an **inclusion proof** — record `i` is in a log of `n` records whose root is `R`,
//!     verifiable in O(log n) without shipping the whole tail; and
//!   * a **consistency proof** — the log of size `m` (an earlier, externally-ANCHORED root)
//!     is an exact prefix of the log of size `n`, in O(log n). This is what closes the
//!     equivocation/truncation gap the tail-only `decern-evidence-bundle/1` documents as open:
//!     a signed tree head over `n` that is consistent with an anchored root over `m` cannot
//!     have rewritten or dropped anything below `m`.
//!
//! The hashing is RFC 9162 §2.1.1 verbatim, including the leaf/interior **domain
//! separation** (`0x00` for a leaf, `0x01` for an interior node) that gives second-preimage
//! resistance. `k` is always the largest power of two STRICTLY less than `n`. The generator
//! functions ([`tree_hash`], [`inclusion_proof`], [`consistency_proof`]) mirror the RFC's
//! MTH / PATH / PROOF recursions; the verifiers ([`verify_inclusion`], [`verify_consistency`])
//! mirror §2.1.3.1–2 exactly, so a third party can re-derive them from the RFC alone.
//!
//! These run on the audit/export path (evidence-bundle production and offline
//! verification), never the decision hot path, so the straightforward recursive
//! generators are used for auditability over micro-optimisation.

use sha2::{Digest, Sha256};

/// RFC 9162 leaf hash: `HASH(0x00 || data)`. The `data` here is a record's chain hash
/// (the 32 bytes `chain_hash` already commits `entry_bytes || prev` to), so the Merkle
/// tree is a commitment over the exact per-record hashes the chain computes.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// RFC 9162 interior node hash: `HASH(0x01 || left || right)`.
pub fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two STRICTLY less than `n` (`n >= 2`). RFC 9162's split point `k`.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// RFC 9162 Merkle Tree Hash (MTH) over the leaf-data list `d`:
///   MTH({})      = HASH()                 (SHA-256 of the empty string)
///   MTH({d0})    = HASH(0x00 || d0)
///   MTH(D[0:n])  = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest 2^x < n
pub fn tree_hash(d: &[Vec<u8>]) -> [u8; 32] {
    match d.len() {
        0 => Sha256::new().finalize().into(),
        1 => hash_leaf(&d[0]),
        n => {
            let k = split(n);
            hash_children(&tree_hash(&d[..k]), &tree_hash(&d[k..]))
        }
    }
}

/// RFC 9162 inclusion proof PATH(m, D[0:n]): the audit path for the leaf at index `m` in a
/// tree of `d.len()` leaves — the sibling hashes needed to recompute the root from the leaf.
///   PATH(0, {d0}) = {}
///   PATH(m, D_n)  = PATH(m, D[0:k]) : MTH(D[k:n])     for m < k
///                 = PATH(m-k, D[k:n]) : MTH(D[0:k])   for m >= k
pub fn inclusion_proof(d: &[Vec<u8>], m: usize) -> Option<Vec<[u8; 32]>> {
    if m >= d.len() {
        return None;
    }
    fn path(d: &[Vec<u8>], m: usize) -> Vec<[u8; 32]> {
        let n = d.len();
        if n == 1 {
            return Vec::new();
        }
        let k = split(n);
        if m < k {
            let mut p = path(&d[..k], m);
            p.push(tree_hash(&d[k..]));
            p
        } else {
            let mut p = path(&d[k..], m - k);
            p.push(tree_hash(&d[..k]));
            p
        }
    }
    Some(path(d, m))
}

/// RFC 9162 consistency proof PROOF(m, D[0:n]) = SUBPROOF(m, D_n, true): the hashes that
/// prove the tree of the first `m` leaves is a prefix of the tree of all `d.len()` leaves.
/// `m` must satisfy `1 <= m <= d.len()`.
pub fn consistency_proof(d: &[Vec<u8>], m: usize) -> Option<Vec<[u8; 32]>> {
    if m == 0 || m > d.len() {
        return None;
    }
    // SUBPROOF(m, D_n, b):
    //   D_m, true  -> {}
    //   D_m, false -> {MTH(D_m)}
    //   m <= k     -> SUBPROOF(m, D[0:k], b)      : MTH(D[k:n])
    //   m > k      -> SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k])
    fn subproof(d: &[Vec<u8>], m: usize, b: bool) -> Vec<[u8; 32]> {
        let n = d.len();
        if m == n {
            return if b { Vec::new() } else { vec![tree_hash(d)] };
        }
        let k = split(n);
        if m <= k {
            let mut p = subproof(&d[..k], m, b);
            p.push(tree_hash(&d[k..]));
            p
        } else {
            let mut p = subproof(&d[k..], m - k, false);
            p.push(tree_hash(&d[..k]));
            p
        }
    }
    Some(subproof(d, m, true))
}

/// RFC 9162 §2.1.3.1 inclusion-proof verification. Recompute the root from `leaf_hash`
/// (the RFC leaf hash of the record, i.e. [`hash_leaf`] of its chain hash) at `leaf_index`
/// in a tree of `tree_size` leaves, following `path`, and compare to `root`.
pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8; 32],
    root: &[u8; 32],
    path: &[[u8; 32]],
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_hash;
    for p in path {
        if sn == 0 {
            return false;
        }
        if (fn_ & 1) == 1 || fn_ == sn {
            r = hash_children(p, &r);
            if (fn_ & 1) == 0 {
                while (fn_ & 1) == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = hash_children(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.3.2 consistency-proof verification: `path` proves the tree of `first`
/// leaves (root `first_root`) is a prefix of the tree of `second` leaves (root
/// `second_root`). `1 <= first <= second`.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &[u8; 32],
    second_root: &[u8; 32],
    path: &[[u8; 32]],
) -> bool {
    if first == 0 || first > second {
        return false;
    }
    // A prefix of equal size needs no proof (the roots must simply be equal).
    if first == second {
        return path.is_empty() && first_root == second_root;
    }
    // Reconstruct the working path: if `first` is an exact power of two, the first node is
    // the (implicit) first_root and is prepended rather than shipped.
    let mut work: Vec<[u8; 32]> = Vec::with_capacity(path.len() + 1);
    if first.is_power_of_two() {
        work.push(*first_root);
    }
    work.extend_from_slice(path);
    if work.is_empty() {
        return false;
    }

    let mut fn_ = first - 1;
    let mut sn = second - 1;
    while (fn_ & 1) == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    let mut fr = work[0];
    let mut sr = work[0];
    for c in &work[1..] {
        if sn == 0 {
            return false;
        }
        if (fn_ & 1) == 1 || fn_ == sn {
            fr = hash_children(c, &fr);
            sr = hash_children(c, &sr);
            if (fn_ & 1) == 0 {
                while (fn_ & 1) == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = hash_children(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *first_root && sr == *second_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        // Deterministic distinct leaf data (no clock/random): leaf i = [i as u8; 4].
        (0..n).map(|i| vec![i as u8; 4]).collect()
    }

    #[test]
    fn mth_structural_base_cases() {
        // Empty tree = SHA-256 of the empty string.
        assert_eq!(tree_hash(&[]), <[u8; 32]>::from(Sha256::new().finalize()));
        // Single leaf = HASH(0x00 || d0).
        let d = leaves(1);
        assert_eq!(tree_hash(&d), hash_leaf(&d[0]));
        // Two leaves = HASH(0x01 || leaf0 || leaf1).
        let d = leaves(2);
        assert_eq!(
            tree_hash(&d),
            hash_children(&hash_leaf(&d[0]), &hash_leaf(&d[1]))
        );
        // Three leaves: k = 2 -> node(node(l0,l1), l2).
        let d = leaves(3);
        let left = hash_children(&hash_leaf(&d[0]), &hash_leaf(&d[1]));
        assert_eq!(tree_hash(&d), hash_children(&left, &hash_leaf(&d[2])));
    }

    #[test]
    fn split_point_is_largest_power_of_two_below_n() {
        assert_eq!(split(2), 1);
        assert_eq!(split(3), 2);
        assert_eq!(split(4), 2);
        assert_eq!(split(5), 4);
        assert_eq!(split(7), 4);
        assert_eq!(split(8), 4);
        assert_eq!(split(9), 8);
    }

    #[test]
    fn inclusion_proof_round_trips_for_every_leaf_and_size() {
        for n in 1..=33usize {
            let d = leaves(n);
            let root = tree_hash(&d);
            for m in 0..n {
                let path = inclusion_proof(&d, m).expect("valid index");
                let lh = hash_leaf(&d[m]);
                assert!(
                    verify_inclusion(m as u64, n as u64, &lh, &root, &path),
                    "inclusion must verify for n={n} m={m}"
                );
            }
            assert!(inclusion_proof(&d, n).is_none(), "OOB index rejected");
        }
    }

    #[test]
    fn inclusion_proof_rejects_tampering() {
        let d = leaves(11);
        let root = tree_hash(&d);
        let path = inclusion_proof(&d, 6).unwrap();
        let lh = hash_leaf(&d[6]);
        assert!(verify_inclusion(6, 11, &lh, &root, &path));
        // Wrong leaf.
        let wrong_leaf = hash_leaf(&d[5]);
        assert!(!verify_inclusion(6, 11, &wrong_leaf, &root, &path));
        // Wrong index.
        assert!(!verify_inclusion(7, 11, &lh, &root, &path));
        // Wrong root.
        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        assert!(!verify_inclusion(6, 11, &lh, &bad_root, &path));
        // Tampered sibling.
        let mut bad_path = path.clone();
        bad_path[0][0] ^= 0xFF;
        assert!(!verify_inclusion(6, 11, &lh, &root, &bad_path));
    }

    #[test]
    fn consistency_proof_round_trips_for_every_prefix_and_size() {
        for n in 1..=33usize {
            let d = leaves(n);
            let second_root = tree_hash(&d);
            for first in 1..=n {
                let first_root = tree_hash(&d[..first]);
                let path = consistency_proof(&d, first).expect("valid first");
                assert!(
                    verify_consistency(first as u64, n as u64, &first_root, &second_root, &path),
                    "consistency must verify for first={first} second={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_a_divergent_or_truncated_log() {
        let d = leaves(9);
        let second_root = tree_hash(&d);
        let first = 5usize;
        let first_root = tree_hash(&d[..first]);
        let path = consistency_proof(&d, first).unwrap();
        assert!(verify_consistency(5, 9, &first_root, &second_root, &path));

        // A different earlier root (equivocation) does not reconcile.
        let mut forged_first = first_root;
        forged_first[0] ^= 0xFF;
        assert!(!verify_consistency(
            5,
            9,
            &forged_first,
            &second_root,
            &path
        ));

        // A rewritten head (truncation/divergence) does not reconcile.
        let mut forged_second = second_root;
        forged_second[0] ^= 0xFF;
        assert!(!verify_consistency(
            5,
            9,
            &first_root,
            &forged_second,
            &path
        ));

        // A tampered proof node fails.
        let mut bad = path.clone();
        if let Some(x) = bad.first_mut() {
            x[0] ^= 0xFF;
        }
        assert!(!verify_consistency(5, 9, &first_root, &second_root, &bad));
    }

    #[test]
    fn consistency_equal_size_needs_no_path_but_equal_roots() {
        let d = leaves(6);
        let root = tree_hash(&d);
        assert!(verify_consistency(6, 6, &root, &root, &[]));
        let mut other = root;
        other[0] ^= 0xFF;
        assert!(!verify_consistency(6, 6, &root, &other, &[]));
    }
}
