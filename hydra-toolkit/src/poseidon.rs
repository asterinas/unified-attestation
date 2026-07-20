//! Poseidon hash over BLS12-381 Fr. Used by the shrubs accumulator and the authorization
//! commitment `H(H(H(pk, ar), time), period)`.

use ark_bls12_381::Fr as BlsScalar;
use ark_ff::PrimeField;
use arkworks_native_gadgets::poseidon::{Poseidon, PoseidonParameters, sbox::PoseidonSbox};
use arkworks_utils::{
    Curve, bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params,
};

/// Build a Poseidon hasher with standard BLS12-381 parameters. `exp=5, width=3` is the
/// default for the 2-to-1 compression used in shrubs and authorization commitment.
pub fn poseidon_setup(curve: Curve, exp: i8, width: u8) -> Poseidon<BlsScalar> {
    let para = setup_params(curve, exp, width);
    Poseidon::<BlsScalar>::new(para)
}

fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
    let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    }
}
