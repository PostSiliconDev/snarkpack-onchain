use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::One;
use ark_groth16::{prepare_verifying_key, Groth16};
use snarkpack_onchain::*;

mod constraints;
use crate::constraints::Benchmark;
use rand_core::SeedableRng;

#[test]
fn groth16_aggregation() {
    let num_constraints = 1000;
    let nproofs = 8;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64);
    let params = {
        let c = Benchmark::<Fr>::new(num_constraints);
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(c, &mut rng).unwrap()
    };
    // prepare the verification key
    let pvk = prepare_verifying_key(&params.vk);
    // prepare the SRS needed for snarkpack - specialize after to the right
    // number of proofs
    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    // create all the proofs
    let proofs = (0..nproofs)
        .map(|_| {
            let c = Benchmark::new(num_constraints);
            Groth16::<Bls12_381>::create_random_proof_with_reduction(c, &params, &mut rng)
                .expect("proof creation failed")
        })
        .collect::<Vec<_>>();
    // verify we can at least verify one
    let inputs: Vec<_> = [Fr::one(); 2].to_vec();
    let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>();
    let r = Groth16::<Bls12_381>::verify_proof(&pvk, &proofs[1], &inputs).unwrap();
    assert!(r);

    let aggregate_proof =
        aggregate_proofs_with_public_inputs(&prover_srs, &pvk, &proofs, &all_inputs)
            .expect("error in aggregation");

    verify_aggregate_proof(&ver_srs, &pvk, &all_inputs, &aggregate_proof, &mut rng)
        .expect("error in verification");
}
