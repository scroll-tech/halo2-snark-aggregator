use crate::sample_circuit::MyCircuit;

use super::chips::{ecc_chip::EccChip, encode_chip::PoseidonEncodeChip, scalar_chip::ScalarChip};
use halo2_ecc_circuit_lib::chips::integer_chip::IntegerChipOps;
use halo2_ecc_circuit_lib::five::integer_chip::FiveColumnIntegerChipHelper;
use halo2_ecc_circuit_lib::five::integer_chip::LIMBS;
use halo2_ecc_circuit_lib::gates::base_gate::BaseGateOps;
use halo2_ecc_circuit_lib::{
    chips::native_ecc_chip::NativeEccChip,
    five::{
        base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig},
        integer_chip::FiveColumnIntegerChip,
        range_gate::FiveColumnRangeGate,
    },
    gates::{base_gate::Context, range_gate::RangeGateConfig},
};
use halo2_proofs::circuit::floor_planner::V1;
use halo2_proofs::plonk::{Column, Instance};
use halo2_proofs::{
    arithmetic::BaseExt,
    plonk::{keygen_pk, verify_proof, SingleVerifier},
    transcript::{Blake2bRead, Challenge255},
};
use halo2_proofs::{
    arithmetic::{CurveAffine, MultiMillerLoop},
    circuit::Layouter,
    plonk::{Circuit, ConstraintSystem, Error, VerifyingKey},
    poly::commitment::{Params, ParamsVerifier},
};
use halo2_proofs::{
    plonk::{create_proof, keygen_vk},
    transcript::Blake2bWrite,
};
use halo2_snark_aggregator_api::mock::arith::{ecc::MockEccChip, field::MockFieldChip};
use halo2_snark_aggregator_api::mock::transcript_encode::PoseidonEncode;
use halo2_snark_aggregator_api::systems::halo2::verify::verify_aggregation_proofs_in_chip;
use halo2_snark_aggregator_api::systems::halo2::{
    transcript::PoseidonTranscriptRead, verify::ProofData,
};
use log::info;
use pairing_bn256::group::Curve;
use rand_core::OsRng;
use std::io::Cursor;
use std::{io::Read, marker::PhantomData};

const COMMON_RANGE_BITS: usize = 17usize;

#[derive(Clone)]
pub struct Halo2VerifierCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
    instance: Column<Instance>,
}

#[derive(Clone)]
pub struct SingleProofWitness<'a, E: MultiMillerLoop> {
    instances: &'a Vec<Vec<Vec<E::Scalar>>>,
    transcript: &'a Vec<u8>,
}

#[derive(Clone)]
pub struct Halo2VerifierCircuit<'a, E: MultiMillerLoop> {
    params: &'a ParamsVerifier<E>,
    vk: &'a VerifyingKey<E::G1Affine>,
    proofs: Vec<SingleProofWitness<'a, E>>,
    nproofs: usize,
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C>> Circuit<C::ScalarExt>
    for Halo2VerifierCircuit<'a, E>
{
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = V1;

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

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config {
            base_gate_config,
            range_gate_config,
            instance,
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

        let mut w_x = None;
        let mut w_g = None;

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
                        PoseidonTranscriptRead<_, C, _, PoseidonEncodeChip<_>, 9usize, 8usize>,
                    >,
                > = vec![];

                for i in 0..self.nproofs {
                    let transcript = PoseidonTranscriptRead::<
                        _,
                        C,
                        _,
                        PoseidonEncodeChip<_>,
                        9usize,
                        8usize,
                    >::new(
                        &self.proofs[i].transcript[..], ctx, schip, 8usize, 33usize
                    )?;

                    proof_data_list.push(ProofData {
                        instances: &self.proofs[i].instances,
                        transcript,
                        key: format!("p{}", i),
                        _phantom: PhantomData,
                    })
                }

                let empty_vec = vec![];
                let mut transcript =
                    PoseidonTranscriptRead::<_, C, _, PoseidonEncodeChip<_>, 9usize, 8usize>::new(
                        &empty_vec[..],
                        ctx,
                        schip,
                        8usize,
                        33usize,
                    )?;
                let mut res = verify_aggregation_proofs_in_chip(
                    ctx,
                    nchip,
                    schip,
                    pchip,
                    &self.vk,
                    &self.params,
                    proof_data_list,
                    &mut transcript,
                )?;

                base_gate.assert_false(ctx, &res.0.z)?;
                base_gate.assert_false(ctx, &res.1.z)?;

                integer_chip.reduce(ctx, &mut res.0.x)?;
                integer_chip.reduce(ctx, &mut res.0.y)?;
                integer_chip.reduce(ctx, &mut res.1.x)?;
                integer_chip.reduce(ctx, &mut res.1.y)?;

                w_x = Some(res.0);
                w_g = Some(res.1);

                Ok(())
            },
        )?;

        let w_x = w_x.unwrap();
        let w_g = w_g.unwrap();

        {
            let mut layouter = layouter.namespace(|| "expose");
            for i in 0..LIMBS {
                layouter.constrain_instance(w_x.x.limbs_le[i].cell, config.instance, i)?;
            }

            for i in 0..LIMBS {
                layouter.constrain_instance(w_x.y.limbs_le[i].cell, config.instance, i + LIMBS)?;
            }

            for i in 0..LIMBS {
                layouter.constrain_instance(
                    w_g.x.limbs_le[i].cell,
                    config.instance,
                    i + LIMBS * 2,
                )?;
            }

            for i in 0..LIMBS {
                layouter.constrain_instance(
                    w_g.y.limbs_le[i].cell,
                    config.instance,
                    i + LIMBS * 3,
                )?;
            }
        }
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

pub fn load_params<C: CurveAffine>(folder: &mut std::path::PathBuf, file_name: &str) -> Params<C> {
    folder.push(file_name);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();
    Params::<C>::read(&mut fd).unwrap()
}

pub fn load_transcript<C: CurveAffine>(
    folder: &mut std::path::PathBuf,
    file_name: &str,
) -> Vec<u8> {
    folder.push(file_name);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    let mut buf = vec![];
    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn load_instances<E: MultiMillerLoop>(buf: &[u8]) -> Vec<Vec<Vec<E::Scalar>>> {
    let instances: Vec<Vec<Vec<Vec<u8>>>> = serde_json::from_reader(buf).unwrap();
    instances
        .into_iter()
        .map(|l1| {
            l1.into_iter()
                .map(|l2| {
                    l2.into_iter()
                        .map(|buf| {
                            <E::Scalar as BaseExt>::read(&mut std::io::Cursor::new(buf)).unwrap()
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

const K: u32 = 22u32;

pub struct Setup {
    pub params: Vec<u8>,
    pub vk: Vec<u8>,
    pub instances: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub nproofs: usize,
}
impl Setup {
    fn new_verify_circuit_info<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
        &self,
        setup: bool,
    ) -> (
        Params<C>,
        ParamsVerifier<E>,
        VerifyingKey<C>,
        Vec<Vec<Vec<Vec<E::Scalar>>>>,
        Vec<Vec<u8>>,
    ) {
        let target_circuit_param = Params::<C>::read(Cursor::new(&self.params)).unwrap();

        let target_circuit_vk = VerifyingKey::<C>::read::<_, MyCircuit<C::ScalarExt>>(
            &mut Cursor::new(&self.vk),
            &target_circuit_param,
        )
        .unwrap();

        let target_circuit_verifier_params = target_circuit_param
            .verifier::<E>(target_circuit_vk.cs.num_instance_columns)
            .unwrap();

        let mut target_circuit_transcripts = vec![];
        let mut target_circuit_instances = vec![];

        for i in 0..self.nproofs {
            let index = if setup { 0 } else { i };
            target_circuit_transcripts.push(self.proofs[index].clone());
            let target_circuit_instance: Vec<Vec<Vec<E::Scalar>>> =
                load_instances::<E>(&self.instances[index]);
            target_circuit_instances.push(target_circuit_instance);
        }

        (
            target_circuit_param,
            target_circuit_verifier_params,
            target_circuit_vk,
            target_circuit_instances,
            target_circuit_transcripts,
        )
    }

    pub fn call<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
        &self,
    ) -> (Params<C>, VerifyingKey<C>) {
        let sample_circuit_info = self.new_verify_circuit_info::<C, E>(true);
        let verify_circuit = verify_circuit_builder(
            &sample_circuit_info.1,
            &sample_circuit_info.2,
            &sample_circuit_info.3,
            &sample_circuit_info.4,
            self.nproofs,
        );
        info!("circuit build done");

        // TODO: Do not use this setup in production
        let verify_circuit_params = Params::<C>::unsafe_setup::<E>(K);
        info!("setup params done");

        let verify_circuit_vk =
            keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");
        info!("setup vkey done");

        (verify_circuit_params, verify_circuit_vk)
    }
}

pub(crate) fn calc_verify_circuit_instances<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
    params: &ParamsVerifier<E>,
    vk: &VerifyingKey<C>,
    n_instances: Vec<Vec<Vec<Vec<E::Scalar>>>>,
    n_transcript: Vec<Vec<u8>>,
) -> Vec<C::ScalarExt> {
    let nchip = MockFieldChip::<C::ScalarExt, Error>::default();
    let schip = MockFieldChip::<C::ScalarExt, Error>::default();
    let pchip = MockEccChip::<C, Error>::default();
    let ctx = &mut ();

    let mut proof_data_list = vec![];
    for (i, instances) in n_instances.iter().enumerate() {
        let transcript = PoseidonTranscriptRead::<_, C, _, PoseidonEncode, 9usize, 8usize>::new(
            &n_transcript[i][..],
            ctx,
            &schip,
            8usize,
            33usize,
        )
        .unwrap();

        proof_data_list.push(ProofData {
            instances,
            transcript,
            key: format!("p{}", i),
            _phantom: PhantomData,
        })
    }

    let empty_vec = vec![];
    let mut transcript = PoseidonTranscriptRead::<_, C, _, PoseidonEncode, 9usize, 8usize>::new(
        &empty_vec[..],
        ctx,
        &nchip,
        8usize,
        33usize,
    )
    .unwrap();

    let (w_x, w_g) = verify_aggregation_proofs_in_chip(
        ctx,
        &nchip,
        &schip,
        &pchip,
        vk,
        params,
        proof_data_list,
        &mut transcript,
    )
    .unwrap();

    let helper = FiveColumnIntegerChipHelper::<C::Base, C::ScalarExt>::new();
    let w_x_x = helper.w_to_limb_n_le(w_x.to_affine().coordinates().unwrap().x());
    let w_x_y = helper.w_to_limb_n_le(w_x.to_affine().coordinates().unwrap().y());
    let w_g_x = helper.w_to_limb_n_le(w_g.to_affine().coordinates().unwrap().x());
    let w_g_y = helper.w_to_limb_n_le(w_g.to_affine().coordinates().unwrap().y());

    w_x_x
        .into_iter()
        .chain(w_x_y.into_iter())
        .chain(w_g_x.into_iter())
        .chain(w_g_y.into_iter())
        .collect()
}

pub struct CreateProof {
    pub target_circuit_params: Vec<u8>,
    pub target_circuit_vk: Vec<u8>,
    pub verify_circuit_params: Vec<u8>,
    pub verify_circuit_vk: Vec<u8>,
    pub template_instances: Vec<Vec<u8>>,
    pub template_proofs: Vec<Vec<u8>>,
    pub instances: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub nproofs: usize,
}

impl CreateProof {
    pub fn call<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(&self) -> (Vec<u8>, Vec<u8>) {
        let setup = Setup {
            params: self.target_circuit_params.clone(),
            vk: self.target_circuit_vk.clone(),
            instances: self.template_instances.clone(),
            proofs: self.template_proofs.clone(),
            nproofs: self.nproofs,
        };

        let now = std::time::Instant::now();
        let (target_circuit_params_verifier, target_circuit_vkey) = {
            let sample_circuit_info = setup.new_verify_circuit_info::<C, E>(false);
            (sample_circuit_info.1, sample_circuit_info.2)
        };

        let sample_circuit_info = setup.new_verify_circuit_info::<C, E>(false);
        let verify_circuit = verify_circuit_builder(
            &sample_circuit_info.1,
            &sample_circuit_info.2,
            &sample_circuit_info.3,
            &sample_circuit_info.4,
            self.nproofs,
        );

        let (instances, transcripts) = {
            let mut verify_circuit_transcripts = vec![];
            let mut verify_circuit_instances = vec![];

            for i in 0..self.nproofs {
                verify_circuit_transcripts.push(self.proofs[i].clone());
                let circuit_instance: Vec<Vec<Vec<E::Scalar>>> =
                    load_instances::<E>(&self.instances[i]);
                verify_circuit_instances.push(circuit_instance);
            }

            (verify_circuit_instances, verify_circuit_transcripts)
        };

        let instances = calc_verify_circuit_instances(
            &target_circuit_params_verifier,
            &target_circuit_vkey,
            instances,
            transcripts,
        );

        let verify_circuit_params =
            Params::<C>::read(Cursor::new(&self.verify_circuit_params)).unwrap();
        let elapsed_time = now.elapsed();
        info!(
            "Running load params took {} seconds.",
            elapsed_time.as_secs()
        );

        let verify_circuit_vk = VerifyingKey::<C>::read::<_, Halo2VerifierCircuit<'_, E>>(
            &mut Cursor::new(&self.verify_circuit_vk),
            &verify_circuit_params,
        )
        .unwrap();

        let elapsed_time = now.elapsed();
        info!("Running load vkey took {} seconds.", elapsed_time.as_secs());
        info!("build vk done");

        let verify_circuit_pk =
            keygen_pk(&verify_circuit_params, verify_circuit_vk, &verify_circuit)
                .expect("keygen_pk should not fail");

        let elapsed_time = now.elapsed();
        info!("Running keygen_pk took {} seconds.", elapsed_time.as_secs());

        let instances: &[&[&[C::ScalarExt]]] = &[&[&instances[..]]];
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

        let elapsed_time = now.elapsed();
        println!(
            "Running create proof took {} seconds.",
            elapsed_time.as_secs()
        );

        let instances = instances
            .iter()
            .map(|l1| {
                l1.iter()
                    .map(|l2| {
                        l2.iter()
                            .map(|c: &C::ScalarExt| {
                                let mut buf = vec![];
                                c.write(&mut buf).unwrap();
                                buf
                            })
                            .collect()
                    })
                    .collect::<Vec<Vec<Vec<u8>>>>()
            })
            .collect::<Vec<Vec<Vec<Vec<u8>>>>>();

        (serde_json::to_vec(&instances).unwrap(), proof)
    }
}

pub struct VerifyCheck {
    pub params: Vec<u8>,
    pub vk: Vec<u8>,
    pub instance: Vec<u8>,
    pub proof: Vec<u8>,
}

impl VerifyCheck {
    pub fn call<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(&self) -> Result<(), Error> {
        let verify_circuit_params = Params::<C>::read(Cursor::new(&self.params)).unwrap();
        let verify_circuit_vk = VerifyingKey::<C>::read::<_, Halo2VerifierCircuit<'_, E>>(
            &mut Cursor::new(&self.vk),
            &verify_circuit_params,
        )
        .unwrap();
        let verify_circuit_instance = load_instances::<E>(&self.instance);

        info!("build vk done");

        let params = verify_circuit_params.verifier::<E>(LIMBS * 4).unwrap();
        let strategy = SingleVerifier::new(&params);

        let verify_circuit_instance1: Vec<Vec<&[E::Scalar]>> = verify_circuit_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[E::Scalar]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&self.proof[..]);

        verify_proof(
            &params,
            &verify_circuit_vk,
            strategy,
            &verify_circuit_instance2[..],
            &mut transcript,
        )
    }
}
