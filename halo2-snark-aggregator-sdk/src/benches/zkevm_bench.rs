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
    use std::path::{Path, PathBuf};

    use crate::{
        write_verify_circuit_final_pair, write_verify_circuit_instance, write_verify_circuit_proof,
        write_verify_circuit_solidity,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    };
    use halo2_proofs::{
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Challenge255, PoseidonRead, PoseidonWrite},
    };
    use halo2_snark_aggregator_circuit::sample_circuit::TargetCircuit;
    use halo2_snark_aggregator_circuit::verify_circuit::{CreateProof, Setup, VerifyCheck};
    use halo2_snark_aggregator_solidity::SolidityGenerate;
    use rand::rngs::OsRng;

    impl TargetCircuit<G1Affine, Bn256> for TestCircuit<Fr> {
        const TARGET_CIRCUIT_K: u32 = DEGREE_OF_EVM_CIRCUIT;
        const PUBLIC_INPUT_SIZE: usize = (Self::TARGET_CIRCUIT_K * 2) as usize;

        type Circuit = TestCircuit<Fr>;

        fn instance_builder() -> (Self::Circuit, Vec<Vec<Fr>>) {
            (Self::Circuit::default(), vec![vec![]])
        }
    }

    fn setup_sample_circuit() -> (
        Params<G1Affine>,
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
            pk,
            instances.clone(),
            instances,
            proof1,
            proof2,
        )
    }

    fn setup_verify_circuit(
        target_circuit_params: &Params<G1Affine>,
        target_circuit_vk: &VerifyingKey<G1Affine>,
        nproofs: usize,
        target_circuit_instances: Vec<Vec<Vec<Vec<Fr>>>>,
        proofs: Vec<Vec<u8>>,
    ) -> (Params<G1Affine>, VerifyingKey<G1Affine>) {
        let request = Setup {
            target_circuit_params,
            target_circuit_vk,
            target_circuit_instances,
            proofs,
            nproofs,
        };

        request.call::<Bn256, TestCircuit<Fr>, K>()
    }

    fn create_aggregate_proof(
        nproofs: usize,
        target_circuit_params: &Params<G1Affine>,
        target_circuit_vk: &VerifyingKey<G1Affine>,
        verify_circuit_params: &Params<G1Affine>,
        verify_circuit_vk: VerifyingKey<G1Affine>,
        instances: Vec<Vec<Vec<Vec<Fr>>>>,
        proofs: Vec<Vec<u8>>,
    ) -> (
        ProvingKey<G1Affine>,
        (
            pairing_bn256::bn256::G1Affine,
            pairing_bn256::bn256::G1Affine,
            Vec<Fr>,
        ),
        Vec<Fr>,
        Vec<u8>,
    ) {
        let request = CreateProof {
            target_circuit_params,
            target_circuit_vk,
            verify_circuit_params,
            verify_circuit_vk,
            template_instances: instances.clone(),
            template_proofs: proofs.clone(),
            instances: instances,
            proofs,
            nproofs,
        };

        request.call::<Bn256, TestCircuit<Fr>>()
    }

    fn verify_check(
        verify_params: &Params<G1Affine>,
        verify_vk: &VerifyingKey<G1Affine>,
        verify_instance: Vec<Vec<Vec<Fr>>>,
        proof: Vec<u8>,
        nproofs: usize,
    ) {
        let request = VerifyCheck::<G1Affine> {
            verify_params,
            verify_vk,
            verify_instance,
            proof,
            nproofs,
        };

        request.call::<Bn256, TestCircuit<Fr>>().unwrap();
    }

    fn solidity_generage(
        target_params: &Params<G1Affine>,
        verify_params: &Params<G1Affine>,
        verify_vk: &VerifyingKey<G1Affine>,
        verify_circuit_instance: Vec<Vec<Vec<Fr>>>,
        proof: Vec<u8>,
        nproofs: usize,
        template_folder: PathBuf,
    ) -> String {
        let request = SolidityGenerate::<G1Affine> {
            target_params,
            verify_params,
            verify_vk,
            verify_circuit_instance,
            proof,
            nproofs,
        };

        request.call::<Bn256, TestCircuit<Fr>>(template_folder)
    }

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_evm_circuit_prover_halo2ecc() {
        let nproofs = 1;
        let template_dir = Path::new("../halo2-snark-aggregator-solidity/templates");
        let output_dir = &std::env::current_dir().unwrap();
        println!("template_dir: {:?}", template_dir.canonicalize());
        println!("output_dir: {:?}", output_dir.canonicalize());

        let proof_message = format!("Setup zkevm circuit");
        let start = start_timer!(|| proof_message);
        let (target_circuit_params, target_circuit_pk, instances1, _instances2, proof1, _proof2) =
            setup_sample_circuit();
        end_timer!(start);

        let proof_message = format!("Setup verify circuit");
        let start = start_timer!(|| proof_message);
        let (verify_circuit_param, verify_circuit_vk) = setup_verify_circuit(
            &target_circuit_params,
            target_circuit_pk.get_vk(),
            nproofs,
            vec![instances1.clone()],
            vec![proof1.clone()],
        );
        end_timer!(start);

        let proof_message = format!("Aggregate proof");
        let start = start_timer!(|| proof_message);
        let (verify_circuit_pk, final_pair, instance, proof) = create_aggregate_proof(
            nproofs,
            &target_circuit_params,
            target_circuit_pk.get_vk(),
            &verify_circuit_param,
            verify_circuit_vk,
            vec![instances1],
            vec![proof1],
        );
        end_timer!(start);

        let proof_message = format!("Check aggregate proof");
        let start = start_timer!(|| proof_message);
        verify_check(
            &verify_circuit_param,
            verify_circuit_pk.get_vk(),
            vec![vec![instance.clone()]],
            proof.clone(),
            nproofs,
        );
        end_timer!(start);

        let proof_message = format!("Generate solidity contract");
        let start = start_timer!(|| proof_message);
        let sol = solidity_generage(
            &target_circuit_params,
            &verify_circuit_param,
            verify_circuit_pk.get_vk(),
            vec![vec![instance.clone()]],
            proof.clone(),
            nproofs,
            template_dir.to_path_buf(),
        );
        end_timer!(start);

        {
            let folder = output_dir;
            write_verify_circuit_instance(&mut folder.clone(), &instance);
            write_verify_circuit_proof(&mut folder.clone(), &proof);
            write_verify_circuit_final_pair(&mut folder.clone(), &final_pair);
            write_verify_circuit_solidity(&mut folder.clone(), &Vec::<u8>::from(sol.as_bytes()));
        }
    }
}
