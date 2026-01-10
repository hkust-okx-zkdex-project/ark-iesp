use ark_bn254::{Bn254, Fr};
use ark_isep::prover::prove;
use ark_isep::public_parameters::PublicParameters;
use ark_isep::statement::Statement;
use ark_isep::verifier::verify;
use ark_isep::witness::Witness;
use ark_std::{test_rng, UniformRand};
use std::collections::BTreeMap;
use std::ops::Range;

fn generate_inputs(
    num_tx: usize,
    pow_seg: usize,
    pow_shared: usize,
) -> (PublicParameters<Bn254>, Witness<Bn254>, Statement<Bn254>) {
    let rng = &mut test_rng();
    let mappings = (0..num_tx)
        .map(|i| (i << pow_seg, i << pow_shared))
        .collect::<BTreeMap<_, _>>();
    let num_left_values = (1 << pow_seg) * num_tx;
    let num_right_values = (1 << pow_shared) * num_tx;
    let curr_time = std::time::Instant::now();
    let pp = PublicParameters::<Bn254>::builder()
        .size_left_values(num_left_values)
        .size_right_values(num_right_values)
        .position_mappings(&mappings)
        .build(rng)
        .unwrap();
    log::info!("setup time: {:?} ms", curr_time.elapsed().as_millis());

    let left_witness_values = (0..num_left_values)
        .map(|_| Fr::rand(rng))
        .collect::<Vec<_>>();
    let mut right_witness_values = (0..num_right_values)
        .map(|_| Fr::rand(rng))
        .collect::<Vec<_>>();
    mappings.iter().for_each(|(k, v)| {
        right_witness_values[*v] = left_witness_values[*k];
    });

    let witness = Witness::new(&pp, &left_witness_values, &right_witness_values).unwrap();
    let statement = witness.generate_statement(&pp).unwrap();

    (pp, witness, statement)
}

const NUM_ITER: usize = 5;
const SHARED_POW_RANGE: Range<usize> = 0..15;
const NUM_TX: usize = 1024;
const POW_SEG: usize = 6;

fn main() {
    env_logger::init();
    for pow_shared in SHARED_POW_RANGE {
        let poly_degree_shared_exp = 10 + pow_shared;
        log::info!(
            "Num TX: {}, Log Seg: {}, Log Shared: {}, Poly Degree (to be Linked): 2^{} - 1, Poly Degree (Fixed): 2^16 - 1",
            NUM_TX,
            POW_SEG,
            pow_shared,
            poly_degree_shared_exp
        );
        let (pp, witness, statement) = generate_inputs(NUM_TX, POW_SEG, pow_shared);
        for _ in 0..NUM_ITER {
            let curr_time = std::time::Instant::now();
            let proof = prove(&pp, &witness, &statement).unwrap();
            log::info!("prove time: {:?} ms", curr_time.elapsed().as_millis());
            let curr_time = std::time::Instant::now();
            verify(&pp, &statement, &proof).unwrap();
            log::info!("verify time: {:?} ms", curr_time.elapsed().as_millis());
        }
    }
}
