//! Evm circuit benchmarks

use ark_std::{end_timer, start_timer};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        Expression, ProvingKey, SingleVerifier,
    },
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Challenge255, PoseidonRead, PoseidonWrite},
};
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};
use rand_core::OsRng;
use zkevm_circuits::evm_circuit::{witness::Block, EvmCircuit};

#[derive(Debug, Default)]
pub struct TestCircuit<F> {
    block: Block<F>,
}

const DEGREE_OF_EVM_CIRCUIT: u32 = 18;
const DEGREE: usize = 18;
const K: u32 = 25u32;

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = EvmCircuit<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = [(); 4].map(|_| meta.advice_column());
        let rw_table = [(); 11].map(|_| meta.advice_column());
        let bytecode_table = [(); 5].map(|_| meta.advice_column());
        let block_table = [(); 3].map(|_| meta.advice_column());
        // Use constant expression to mock constant instance column for a more
        // reasonable benchmark.
        let power_of_randomness = [(); 31].map(|_| Expression::Constant(F::one()));

        EvmCircuit::configure(
            meta,
            power_of_randomness,
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_block(&mut layouter, &self.block)?;
        Ok(())
    }
}

fn setup_sample_circuit() -> (
    Params<G1Affine>,
    ParamsVerifier<Bn256>,
    ProvingKey<G1Affine>,
    Vec<Vec<Vec<Fr>>>,
    Vec<Vec<Vec<Fr>>>,
    Vec<u8>,
    Vec<u8>,
) {
    let circuit = TestCircuit::<Fr>::default();

    // Bench setup generation
    let setup_message = format!("Setup generation with degree = {}", DEGREE_OF_EVM_CIRCUIT);
    let start1 = start_timer!(|| setup_message);
    let general_params: Params<G1Affine> =
        Params::<G1Affine>::unsafe_setup::<Bn256>(DEGREE_OF_EVM_CIRCUIT);
    end_timer!(start1);

    let vk = keygen_vk(&general_params, &circuit).unwrap();
    let pk = keygen_pk(&general_params, vk, &circuit).unwrap();

    let instances: &[&[&[_]]] = &[&[]];
    let circuit = &[circuit];

    macro_rules! evm_proof {
        ($name:ident) => {
            let $name = {
                // Prove
                let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

                // Bench proof generation time
                let proof_message =
                    format!("EVM Proof generation with {} degree", DEGREE_OF_EVM_CIRCUIT);
                let start2 = start_timer!(|| proof_message);
                create_proof(
                    &general_params,
                    &pk,
                    circuit,
                    instances,
                    OsRng,
                    &mut transcript,
                )
                .unwrap();
                let proof = transcript.finalize();
                end_timer!(start2);
                proof
            };
        };
    }

    evm_proof!(proof1);
    evm_proof!(proof2);

    // Verify
    let verifier_params: ParamsVerifier<Bn256> = general_params.verifier(DEGREE * 2).unwrap();
    let mut verifier_transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof1[..]);
    let strategy = SingleVerifier::new(&verifier_params);

    // Bench verification time
    let start3 = start_timer!(|| "EVM Proof verification");
    verify_proof(
        &verifier_params,
        pk.get_vk(),
        strategy,
        instances,
        &mut verifier_transcript,
    )
    .unwrap();
    end_timer!(start3);

    let instances = instances
        .iter()
        .map(|l1| {
            l1.iter()
                .map(|l2| l2.iter().map(|c: &Fr| *c).collect::<Vec<Fr>>())
                .collect::<Vec<Vec<Fr>>>()
        })
        .collect::<Vec<Vec<Vec<Fr>>>>();

    (
        general_params,
        verifier_params,
        pk,
        instances.clone(),
        instances,
        proof1,
        proof2,
    )
}

#[cfg(test)]
mod evm_circ_benches {
    use crate::verify_circuit::{
        calc_verify_circuit_instances, Halo2VerifierCircuit, SingleProofWitness,
    };

    use super::*;
    use halo2_proofs::dev::MockProver;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_mock_evm_circuit_prover_halo2ecc() {
        let nproofs = 1;

        let (
            _target_circuit_params,
            target_circuit_verifier_params,
            target_circuit_pk,
            instances1,
            _,
            proof1,
            _,
        ) = setup_sample_circuit();

        let target_circuit_instance = instances1.clone();
        let target_circuit_proof = proof1.clone();
        let verify_circuit = Halo2VerifierCircuit {
            params: &target_circuit_verifier_params,
            vk: target_circuit_pk.get_vk(),
            nproofs,
            proofs: vec![SingleProofWitness {
                instances: &target_circuit_instance,
                transcript: &target_circuit_proof,
            }],
        };

        let instances = calc_verify_circuit_instances(
            &target_circuit_verifier_params,
            &target_circuit_pk.get_vk(),
            &vec![instances1],
            &vec![proof1],
        );

        let prover = match MockProver::run(K, &verify_circuit, vec![instances]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
