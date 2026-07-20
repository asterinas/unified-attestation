//! Shrubs accumulator: a space-efficient Merkle-like tree where only "root" nodes are
//! stored rather than every internal node. Insertion and Merkle path lookup are structural:
//! they depend on leaf ordering and total leaf count, not on hash values.
//!
//! Key properties:
//! - The root list after each batch is the public commitment (sent in PublicContext).
//! - `find_shrubs_path` returns (siblings, direction_tags) for a given leaf; `None` if the
//!   leaf is itself a root boundary node.
//! - `affected_indices` computes which old attesters need path recalculation after insert.

use ark_bls12_381::Fr as BlsScalar;
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
use rayon::prelude::*;

/// Internal node representing a sub-tree root span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Root {
    level: u32,
    left: usize,   // 1-based
    right: usize,  // 1-based
}

/// Find the shrubs root that "owns" a given 1-based leaf index.
fn find_owner_root(index: usize, total: usize) -> Root {
    assert!(index >= 1 && index <= total);

    let mut level = 0u32;
    let mut block_size = 1usize;

    while block_size <= total {
        let layer_count = total / block_size;

        if layer_count == 0 {
            break;
        }

        let root_block = if layer_count % 2 == 1 {
            layer_count
        } else {
            layer_count - 1
        };

        let left = (root_block - 1) * block_size + 1;
        let right = root_block * block_size;

        if index >= left && index <= right {
            return Root { level, left, right };
        }

        if block_size > total / 2 {
            break;
        }

        block_size *= 2;
        level += 1;
    }

    unreachable!("every node should belong to a shrubs root");
}

/// Returns 1-based old attester indices whose shrubs owner root changes after insertion.
pub fn affected_indices(old_total: usize, inserted: usize) -> Vec<usize> {
    assert!(old_total > 0);

    if inserted == 0 {
        return Vec::new();
    }

    let new_total = old_total + inserted;
    let mut affected = Vec::new();

    for index in 1..=old_total {
        let old_root = find_owner_root(index, old_total);
        let new_root = find_owner_root(index, new_total);

        if old_root != new_root {
            affected.push(index);
        }
    }

    affected
}

/// Decompose an integer into the set of powers-of-two that sum to it.
/// E.g. `6 → [1, 2]` (2¹ + 2²). Used by `insert_shrubs_tree` to determine
/// which levels of the tree need root insertion.
pub fn exponents_of_two(mut x: usize) -> Vec<isize> {
    let mut exps = Vec::with_capacity(x.count_ones() as usize);
    while x != 0 {
        let tz = x.trailing_zeros();
        exps.push(tz as isize);
        x &= x - 1;
    }
    exps
}

/// Recursively insert a batch of leaves into an existing shrubs tree.
///
/// `t_root` is mutated in place. `k` tracks the current level offset,
/// `exps` is the exponents-of-two decomposition of the old leaf count,
/// `ll` indexes into `exps` to decide when to insert a root node from the
/// previous level. The recursion bottoms out when no more pairs can be hashed.
pub fn insert_shrubs_tree(
    t_root: &mut Vec<BlsScalar>,
    vect: &[BlsScalar],
    mut k: isize,
    exps: &[isize],
    mut ll: usize,
    hasher: &Poseidon<BlsScalar>,
) {
    let should_insert_root = ll < exps.len() && k + 2 == exps[ll];

    let mut temp = Vec::with_capacity(vect.len() / 2 + if should_insert_root { 1 } else { 0 });

    if should_insert_root {
        let root_index = k + 2;
        assert!(root_index >= 0, "k + 2 must be non-negative");

        ll += 1;
        temp.push(t_root[root_index as usize]);
    }

    let results: Vec<BlsScalar> = vect
        .par_chunks_exact(2)
        .map(|chunk| {
            hasher
                .hash(&[chunk[0], chunk[1]][..])
                .expect("Poseidon hash failed")
        })
        .collect();

    temp.extend(results);

    let last_i = vect.len() - if vect.len().is_multiple_of(2) { 2 } else { 1 };

    k += 1;

    if t_root.len() > k as usize {
        t_root[k as usize] = vect[last_i];
    } else {
        t_root.push(vect[last_i]);
    }

    if !temp.is_empty() {
        insert_shrubs_tree(t_root, &temp, k, exps, ll, hasher)
    }
}

/// Build a shrubs tree from scratch for the initial batch of leaves.
/// Pairs are hashed in parallel via rayon; odd leaves are pushed as roots.
/// The resulting `root` list is the public commitment inserted into PublicContext.
pub fn create_batch_devices(
    root: &mut Vec<BlsScalar>,
    leaves: &[BlsScalar],
    hasher: &Poseidon<BlsScalar>,
) {
    let len = leaves.len();

    if len == 0 {
        return;
    }

    let temp: Vec<BlsScalar> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];

            hasher.hash(&[a, b][..]).unwrap()
        })
        .collect();

    let last_i = if len.is_multiple_of(2) {
        len - 2
    } else {
        len - 1
    };

    root.push(leaves[last_i]);

    if !temp.is_empty() {
        create_batch_devices(root, &temp, hasher);
    }
}

/// Calculate the Merkle proof path and direction tags for a leaf at `value`.
///
/// Returns `(sibling_values, direction_tags)` where `direction_tags[i] = true` means
/// the sibling was on the right (leaf was left child). Returns `None` when the leaf
/// itself is a shrubs root boundary node — such leaves have no path and cannot
/// participate in the circuit for this batch.
pub fn find_shrubs_path(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    j: usize,
    value: usize,
    hasher: &Poseidon<BlsScalar>,
) -> Option<(Vec<BlsScalar>, Vec<bool>)> {
    if leaves.len() >= 2 && root[0] == leaves[value] {
        return None;
    }

    if leaves.is_empty() || value >= leaves.len() {
        return None;
    }

    let mut path = Vec::<BlsScalar>::new();
    let mut index = Vec::<bool>::new();

    let sibling_index = if value % 2 == 1 {
        index.push(false);
        value.checked_sub(1)?
    } else {
        index.push(true);
        value.checked_add(1)?
    };

    let sibling = leaves.get(sibling_index)?;
    path.push(*sibling);

    let temp: Vec<BlsScalar> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];

            hasher.hash(&[a, b][..]).unwrap()
        })
        .collect();

    if temp.len() >= 2 {
        let val = value / 2;
        let next_j = j + 1;

        if val >= temp.len() || next_j >= root.len() {
            return None;
        }

        if temp[val] == root[next_j] {
            return Some((path, index));
        }

        let (mut sub_path, mut sub_index) = find_shrubs_path(root, &temp, next_j, val, hasher)?;

        path.append(&mut sub_path);
        index.append(&mut sub_index);

        return Some((path, index));
    }

    Some((path, index))
}

fn largest_power_two_leq(n: usize) -> usize {
    assert!(n > 0);

    let mut p = 1usize;

    while p <= n / 2 {
        p <<= 1;
    }

    p
}

/// Binary-search a leaf value in the sorted shrubs leaf list. Returns the owning
/// subtree's leaf slice and the local index of the target within that slice.
/// `None` when the leaf is not present.
pub fn find_interval_index(
    arr: &[BlsScalar],
    target: &BlsScalar,
) -> Option<(Vec<BlsScalar>, usize)> {
    if arr.is_empty() {
        return None;
    }

    let target_index = arr.iter().position(|x| x == target)?;

    let mut start = 0usize;
    let mut remaining = arr.len();

    while remaining > 0 {
        let interval_len = largest_power_two_leq(remaining);
        let end = start + interval_len;

        if target_index >= start && target_index < end {
            if interval_len == 1 {
                return None;
            }

            let interval = arr[start..end].to_vec();

            let index_in_interval: usize = target_index - start;

            return Some((interval, index_in_interval));
        }

        start = end;
        remaining -= interval_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::affected_indices;

    #[test]
    fn affected_indices_returns_none_without_insertions() {
        assert_eq!(affected_indices(4, 0), Vec::<usize>::new());
    }

    #[test]
    fn affected_indices_returns_one_based_old_indices() {
        assert_eq!(affected_indices(4, 8), vec![1, 2, 3, 4]);
    }

    #[test]
    fn affected_indices_tracks_only_roots_that_change() {
        assert_eq!(affected_indices(2, 1), vec![1]);
        assert_eq!(affected_indices(3, 1), Vec::<usize>::new());
        assert_eq!(affected_indices(5, 2), vec![1, 2, 5]);
    }
}
