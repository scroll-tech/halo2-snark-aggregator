//! Evm circuit benchmarks

use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
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

#[cfg(test)]
mod evm_circ_benches {
    use std::env::var;
    use std::path::Path;

    use crate::verify_circuit::{
        calc_verify_circuit_instances, Halo2VerifierCircuit, SingleProofWitness,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_ecc_circuit_lib::five::integer_chip::LIMBS;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    };
    use halo2_proofs::{
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255, PoseidonRead, PoseidonWrite},
    };
    use rand::rngs::OsRng;

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

    fn setup_verify_circuit(
        target_circuit_verifier_params: &ParamsVerifier<Bn256>,
        target_circuit_pk: &ProvingKey<G1Affine>,
        nproofs: usize,
        instances: Vec<Vec<Vec<Vec<Fr>>>>,
        proofs: Vec<Vec<u8>>,
    ) -> (Params<G1Affine>, VerifyingKey<G1Affine>) {
        let verify_circuit = Halo2VerifierCircuit {
            params: &target_circuit_verifier_params,
            vk: target_circuit_pk.get_vk(),
            nproofs,
            proofs: instances
                .iter()
                .zip(proofs.iter())
                .map(|(i, t)| SingleProofWitness {
                    instances: i,
                    transcript: t,
                })
                .collect(),
        };

        let params_path = format!("HALO2_PARAMS_{}", K);

        let path = var(params_path);
        let path = match &path {
            Ok(path) => {
                let path = Path::new(path);
                Some(path)
            }
            _ => None,
        };

        println!("params path: {:?}", path);
        let verify_circuit_params = if path.is_some() && Path::exists(&path.unwrap()) {
            println!("read params from {:?}", path.unwrap());
            let mut fd = std::fs::File::open(&path.unwrap()).unwrap();
            Params::<G1Affine>::read(&mut fd).unwrap()
        } else {
            let params = Params::<G1Affine>::unsafe_setup::<Bn256>(K);

            if let Some(path) = path {
                println!("write params to {:?}", path);

                let mut fd = std::fs::File::create(path).unwrap();

                params.write(&mut fd).unwrap();
            };

            params
        };

        let verify_circuit_vk =
            keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");

        (verify_circuit_params, verify_circuit_vk)
    }

    fn create_aggregate_proof(
        nproofs: usize,
        target_circuit_verifier_params: &ParamsVerifier<Bn256>,
        target_circuit_pk: &ProvingKey<G1Affine>,
        verify_circuit_params: &Params<G1Affine>,
        verify_circuit_vk: VerifyingKey<G1Affine>,
        instances: &Vec<Vec<Vec<Vec<Fr>>>>,
        proofs: &Vec<Vec<u8>>,
    ) -> (ProvingKey<G1Affine>, Vec<Vec<Vec<Fr>>>, Vec<u8>) {
        let verify_circuit = Halo2VerifierCircuit {
            params: &target_circuit_verifier_params,
            vk: target_circuit_pk.get_vk(),
            nproofs,
            proofs: instances
                .iter()
                .zip(proofs.iter())
                .map(|(i, t)| SingleProofWitness {
                    instances: &i,
                    transcript: &t,
                })
                .collect(),
        };

        let verify_circuit_pk =
            keygen_pk(&verify_circuit_params, verify_circuit_vk, &verify_circuit)
                .expect("keygen_pk should not fail");

        let instances = calc_verify_circuit_instances(
            &target_circuit_verifier_params,
            &target_circuit_pk.get_vk(),
            instances.clone(),
            proofs.clone(),
        );
        let instances: &[&[&[Fr]]] = &[&[&instances[..]]];

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &verify_circuit_params,
            &verify_circuit_pk,
            &[verify_circuit],
            instances,
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();

        (
            verify_circuit_pk,
            instances
                .iter()
                .map(|l1| {
                    l1.iter()
                        .map(|l2| l2.iter().map(|c: &Fr| *c).collect::<Vec<Fr>>())
                        .collect::<Vec<Vec<Fr>>>()
                })
                .collect::<Vec<Vec<Vec<Fr>>>>(),
            proof,
        )
    }

    fn verify_check(
        verify_circuit_params: &Params<G1Affine>,
        verify_circuit_vk: &VerifyingKey<G1Affine>,
        verify_circuit_instance: &Vec<Vec<Vec<Fr>>>,
        proof: &Vec<u8>,
    ) {
        let params = verify_circuit_params.verifier::<Bn256>(LIMBS * 4).unwrap();
        let strategy = SingleVerifier::new(&params);

        let verify_circuit_instance1: Vec<Vec<&[Fr]>> = verify_circuit_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[Fr]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        verify_proof(
            &params,
            &verify_circuit_vk,
            strategy,
            &verify_circuit_instance2[..],
            &mut transcript,
        )
        .expect("verify aggregate proof fail")
    }

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
            vec![instances1],
            vec![proof1],
        );

        let prover = match MockProver::run(K, &verify_circuit, vec![instances]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_evm_circuit_prover_halo2ecc() {
        let nproofs = 1;

        let proof_message = format!("Setup zkevm circuit");
        let start = start_timer!(|| proof_message);
        let (
            _target_circuit_params,
            target_circuit_verifier_params,
            target_circuit_pk,
            instances1,
            instances2,
            proof1,
            proof2,
        ) = setup_sample_circuit();
        end_timer!(start);

        let proof_message = format!("Setup verify circuit");
        let start = start_timer!(|| proof_message);
        let (verify_circuit_param, verify_circuit_vk) = setup_verify_circuit(
            &target_circuit_verifier_params,
            &target_circuit_pk,
            nproofs,
            vec![instances1.clone()],
            vec![proof1.clone()],
        );
        end_timer!(start);

        let proof_message = format!("Aggregate proof");
        let start = start_timer!(|| proof_message);
        let (verify_circuit_pk, verify_circuit_instances, proof) = create_aggregate_proof(
            nproofs,
            &target_circuit_verifier_params,
            &target_circuit_pk,
            &verify_circuit_param,
            verify_circuit_vk,
            &vec![instances1],
            &vec![proof1],
        );
        end_timer!(start);

        let proof_message = format!("Check aggregate proof");
        let start = start_timer!(|| proof_message);
        verify_check(
            &verify_circuit_param,
            verify_circuit_pk.get_vk(),
            &verify_circuit_instances,
            &proof,
        );
        end_timer!(start);
    }
}
