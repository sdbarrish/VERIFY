//! Merkle trees with RFC 9162 shape and leaf/node domain separation.
//!
//! An inclusion proof shows a transaction is in a block. It does not show the
//! block is complete (white paper §6.3); completeness comes from reconciling
//! expected events and physical inventory.

use crate::crypto::{hash, Hash};

pub fn leaf_hash(data: &[u8]) -> Hash {
    hash("VERIFY/merkle/leaf", data)
}

fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l);
    b[32..].copy_from_slice(r);
    hash("VERIFY/merkle/node", &b)
}

fn split(n: usize) -> usize {
    // largest power of two strictly less than n (n >= 2)
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => hash("VERIFY/merkle/empty", &[]),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

pub fn inclusion_proof(index: usize, leaves: &[Hash]) -> Vec<Hash> {
    assert!(index < leaves.len());
    let n = leaves.len();
    if n == 1 {
        return vec![];
    }
    let k = split(n);
    if index < k {
        let mut p = inclusion_proof(index, &leaves[..k]);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(index - k, &leaves[k..]);
        p.push(root(&leaves[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.2 verification.
pub fn verify_inclusion(
    index: usize,
    tree_size: usize,
    leaf: &Hash,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let (mut fnn, mut sn) = (index, tree_size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            r = node_hash(p, &r);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_verify_for_all_sizes() {
        for n in 1..=17usize {
            let leaves: Vec<Hash> = (0..n).map(|i| leaf_hash(&[i as u8])).collect();
            let r = root(&leaves);
            for i in 0..n {
                let p = inclusion_proof(i, &leaves);
                assert!(verify_inclusion(i, n, &leaves[i], &p, &r), "n={n} i={i}");
                assert!(!verify_inclusion(i, n, &leaf_hash(b"forged"), &p, &r));
            }
        }
    }
}
