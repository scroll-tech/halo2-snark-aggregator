use super::chips::{ecc_chip::EccChip, encode_chip::PoseidonEncode, scalar_chip::ScalarChip};
use halo2_ecc_circuit_lib::{
    chips::native_ecc_chip::NativeEccChip,
    five::{
        base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig},
        integer_chip::FiveColumnIntegerChip,
        range_gate::FiveColumnRangeGate,
    },
    gates::{base_gate::Context, range_gate::RangeGateConfig},
};
use halo2_proofs::{
    arithmetic::{BaseExt, Field},
    plonk::keygen_pk,
    transcript::Challenge255,
};
use halo2_proofs::{
    arithmetic::{CurveAffine, MultiMillerLoop},
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, VerifyingKey},
    poly::commitment::{Params, ParamsVerifier},
};
use halo2_proofs::{
    plonk::{create_proof, keygen_vk},
    transcript::Blake2bWrite,
};
use halo2_snark_aggregator_api::systems::halo2::verify::verify_aggregation_proofs_in_chip;
use halo2_snark_aggregator_api::systems::halo2::{
    transcript::PoseidonTranscriptRead, verify::ProofData,
};
use rand_core::OsRng;
use serde_json::json;
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

const COMMON_RANGE_BITS: usize = 17usize;

#[derive(Clone)]
struct Halo2VerifierCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Clone)]
struct SingleProofWitness<'a, E: MultiMillerLoop> {
    instances: &'a Vec<Vec<Vec<E::Scalar>>>,
    transcript: &'a Vec<u8>,
}

#[derive(Clone)]
struct Halo2VerifierCircuit<'a, E: MultiMillerLoop> {
    params: &'a ParamsVerifier<E>,
    vk: &'a VerifyingKey<E::G1Affine>,
    proofs: Vec<SingleProofWitness<'a, E>>,
    nproofs: usize,
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C>> Circuit<C::ScalarExt>
    for Halo2VerifierCircuit<'a, E>
{
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            params: self.params,
            vk: self.vk,
            proofs: (0..self.nproofs).map(|_| self.proofs[0].clone()).collect(),
            nproofs: self.nproofs,
        }
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::configure(meta);
        let range_gate_config =
            FiveColumnRangeGate::<'_, C::Base, C::ScalarExt, COMMON_RANGE_BITS>::configure(
                meta,
                &base_gate_config,
            );
        Self::Config {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
        let range_gate = FiveColumnRangeGate::<'_, C::Base, C::ScalarExt, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_chip = FiveColumnIntegerChip::new(&range_gate);
        let ecc_chip = NativeEccChip::new(&integer_chip);
        range_gate
            .init_table(&mut layouter, &integer_chip.helper.integer_modulus)
            .unwrap();

        let nchip = &ScalarChip::new(&base_gate);
        let schip = nchip;
        let pchip = &EccChip::new(&ecc_chip);

        layouter.assign_region(
            || "base",
            |region| {
                let base_offset = 0usize;
                let mut aux = Context::new(region, base_offset);
                let ctx = &mut aux;

                let mut proof_data_list: Vec<
                    ProofData<
                        E,
                        _,
                        PoseidonTranscriptRead<_, C, _, PoseidonEncode<_>, 9usize, 8usize>,
                    >,
                > = vec![];

                for i in 0..self.nproofs {
                    let transcript =
                        PoseidonTranscriptRead::<_, C, _, PoseidonEncode<_>, 9usize, 8usize>::new(
                            &self.proofs[i].transcript[..],
                            ctx,
                            schip,
                            8usize,
                            33usize,
                        )
                        .unwrap();

                    proof_data_list.push(ProofData {
                        instances: &self.proofs[i].instances,
                        transcript,
                        key: format!("p{}", i),
                        _phantom: PhantomData,
                    })
                }

                let empty_vec = vec![];
                let mut transcript =
                    PoseidonTranscriptRead::<_, C, _, PoseidonEncode<_>, 9usize, 8usize>::new(
                        &empty_vec[..],
                        ctx,
                        schip,
                        8usize,
                        33usize,
                    )
                    .unwrap();
                verify_aggregation_proofs_in_chip(
                    ctx,
                    nchip,
                    schip,
                    pchip,
                    &self.vk,
                    &self.params,
                    proof_data_list,
                    &mut transcript,
                )
                .unwrap();

                Ok(())
            },
        )?;

        Ok(())
    }
}

fn verify_circuit_builder<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
    params: &'a ParamsVerifier<E>,
    vk: &'a VerifyingKey<E::G1Affine>,
    instances: &'a Vec<Vec<Vec<Vec<E::Scalar>>>>,
    transcript: &'a Vec<Vec<u8>>,
    nproofs: usize,
) -> Halo2VerifierCircuit<'a, E> {
    Halo2VerifierCircuit {
        params,
        vk,
        nproofs,
        proofs: instances
            .iter()
            .zip(transcript.iter())
            .map(|(i, t)| SingleProofWitness {
                instances: i,
                transcript: t,
            })
            .collect(),
    }
}

fn load_sample_circuit_info<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
    folder: &mut std::path::PathBuf,
    nproofs: usize,
    setup: bool,
) -> (
    ParamsVerifier<E>,
    VerifyingKey<C>,
    Vec<Vec<Vec<Vec<E::Scalar>>>>,
    Vec<Vec<u8>>,
) {
    let sample_circuit_params = {
        folder.push("sample_circuit.params");
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        Params::<C>::read(&mut fd).unwrap()
    };

    // We should read vkey from file, but we use a workaround due to issue https://github.com/zcash/halo2/issues/449
    /*
    let sample_circuit_vk = {
        folder.push("sample_circuit.vkey");
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        VerifyingKey::<C>::read::<_, MyCircuit<C::ScalarExt>>(&mut fd, &params).unwrap()
    };
    */
    let sample_circuit_vk = {
        let sample_circuit = crate::sample_circuit::sample_circuit_builder(
            C::ScalarExt::zero(),
            C::ScalarExt::zero(),
        );

        keygen_vk(&sample_circuit_params, &sample_circuit).expect("keygen_vk should not fail")
    };

    let mut sample_circuit_transcripts = vec![];
    let mut sample_circuit_instances = vec![];

    for i in 0..nproofs {
        let index = if setup { 0usize } else { i };
        let sample_circuit_transcript = {
            folder.push(format!("sample_circuit_proof{}.data", index));
            let mut fd = std::fs::File::open(folder.as_path()).unwrap();
            folder.pop();

            let mut buf = vec![];
            fd.read_to_end(&mut buf).unwrap();
            buf
        };
        sample_circuit_transcripts.push(sample_circuit_transcript);

        let sample_circuit_instance: Vec<Vec<Vec<E::Scalar>>> = {
            folder.push(format!("sample_circuit_instance{}.data", index));
            let fd = std::fs::File::open(folder.as_path()).unwrap();
            folder.pop();

            let instances: Vec<Vec<Vec<Vec<u8>>>> = serde_json::from_reader(fd).unwrap();
            instances
                .into_iter()
                .map(|l1| {
                    l1.into_iter()
                        .map(|l2| {
                            l2.into_iter()
                                .map(|buf| {
                                    <E::Scalar as BaseExt>::read(&mut std::io::Cursor::new(buf))
                                        .unwrap()
                                })
                                .collect()
                        })
                        .collect()
                })
                .collect()
        };
        sample_circuit_instances.push(sample_circuit_instance);
    }

    let sample_circuit_verifier_params = sample_circuit_params
        .verifier::<E>(sample_circuit_vk.cs.num_instance_columns)
        .unwrap();

    (
        sample_circuit_verifier_params,
        sample_circuit_vk,
        sample_circuit_instances,
        sample_circuit_transcripts,
    )
}

const K: u32 = 22u32;

pub(crate) fn verify_circuit_setup<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
    mut folder: std::path::PathBuf,
    nproofs: usize,
) {
    let sample_circuit_info = load_sample_circuit_info::<C, E>(&mut folder, nproofs, true);
    let verify_circuit = verify_circuit_builder(
        &sample_circuit_info.0,
        &sample_circuit_info.1,
        &sample_circuit_info.2,
        &sample_circuit_info.3,
        nproofs,
    );

    println!("circuit build done");

    folder.push("verify_circuit.params");
    let verify_circuit_params = if folder.exists() {
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        Params::<C>::read(&mut fd).unwrap()
    } else {
        // TODO: Do not use this setup in production
        let verify_circuit_params = Params::<C>::unsafe_setup::<E>(K);

        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        verify_circuit_params.write(&mut fd).unwrap();
        verify_circuit_params
    };
    folder.pop();

    println!("setup params done");

    let verify_circuit_vk =
        keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");

    println!("setup vkey done");

    {
        folder.push("verify_circuit.vkey");
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        verify_circuit_vk.write(&mut fd).unwrap();
    }
}

pub(crate) fn verify_circuit_run<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
    mut folder: std::path::PathBuf,
    nproofs: usize,
) {
    let sample_circuit_info = load_sample_circuit_info::<C, E>(&mut folder, nproofs, false);
    let verify_circuit = verify_circuit_builder(
        &sample_circuit_info.0,
        &sample_circuit_info.1,
        &sample_circuit_info.2,
        &sample_circuit_info.3,
        nproofs,
    );

    let verify_circuit_params = {
        folder.push("verify_circuit.params");
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        Params::<C>::read(&mut fd).unwrap()
    };

    // issue see https://github.com/zcash/halo2/issues/449
    /*
    let verify_circuit_vk = {
        folder.push("verify_circuit_.vkey");
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        VerifyingKey::<C>::read::<_, MyCircuit<C::ScalarExt>>(&mut fd, &params).unwrap()
    };
    */
    let verify_circuit_vk =
        keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");
    let verify_circuit_pk = keygen_pk(&verify_circuit_params, verify_circuit_vk, &verify_circuit)
        .expect("keygen_pk should not fail");

    let instances: &[&[&[C::ScalarExt]]] = &[];
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

    {
        folder.push(format!("verify_circuit_proof.data"));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        fd.write_all(&proof).unwrap();
    }

    {
        folder.push(format!("verify_circuit_instance.data"));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        let instances = json!(instances
            .iter()
            .map(|l1| l1
                .iter()
                .map(|l2| l2
                    .iter()
                    .map(|c: &C::ScalarExt| {
                        let mut buf = vec![];
                        c.write(&mut buf).unwrap();
                        buf
                    })
                    .collect())
                .collect::<Vec<Vec<Vec<u8>>>>())
            .collect::<Vec<Vec<Vec<Vec<u8>>>>>());
        fd.write_all(&proof).unwrap();
        fd.write_all(instances.to_string().as_bytes()).unwrap();
    }
}
