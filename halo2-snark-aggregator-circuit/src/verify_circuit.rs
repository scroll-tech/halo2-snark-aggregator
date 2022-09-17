use crate::fs::{
    load_target_circuit_instance, load_target_circuit_params, load_target_circuit_proof,
    load_target_circuit_vk, load_verify_circuit_instance, load_verify_circuit_params,
    load_verify_circuit_proof, load_verify_circuit_vk,
};
use crate::sample_circuit::TargetCircuit;

use super::chips::{
    ecc_chip::{EccChip, FpChip},
    encode_chip::PoseidonEncodeChip,
    scalar_chip::ScalarChip,
};
use ff::PrimeField;
use halo2_ecc::gates::QuantumCell;
use halo2_ecc::{
    fields::fp::FpStrategy,
    gates::{Context, ContextParams, GateInstructions},
};
use halo2_proofs::circuit::floor_planner::V1;
use halo2_proofs::circuit::{AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{create_proof, keygen_vk, ProvingKey};
use halo2_proofs::plonk::{Column, Instance};
use halo2_proofs::{
    arithmetic::{CurveAffine, MultiMillerLoop},
    circuit::Layouter,
    plonk::{Circuit, ConstraintSystem, Error, VerifyingKey},
    poly::commitment::{Params, ParamsVerifier},
};
use halo2_proofs::{
    plonk::{keygen_pk, verify_proof, SingleVerifier},
    transcript::Challenge255,
};
use halo2_snark_aggregator_api::arith::ecc::ArithEccChip;
use halo2_snark_aggregator_api::arith::field::ArithFieldChip;
use halo2_snark_aggregator_api::mock::arith::{
    ecc::MockEccChip,
    field::{MockChipCtx, MockFieldChip},
};
use halo2_snark_aggregator_api::mock::transcript_encode::PoseidonEncode;
use halo2_snark_aggregator_api::systems::halo2::verify::{
    verify_aggregation_proofs_in_chip, CircuitProof,
};
use halo2_snark_aggregator_api::systems::halo2::{
    transcript::PoseidonTranscriptRead, verify::ProofData,
};
use halo2_snark_aggregator_api::transcript::sha::{ShaRead, ShaWrite};
use log::info;
use num_bigint::BigUint;
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};
use pairing_bn256::group::Curve;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::env::var;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::{io::Read, marker::PhantomData};

const LIMB_BITS: usize = 88;

// for tuning the circuit
#[derive(Serialize, Deserialize)]
pub struct Halo2VerifierCircuitConfigParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

#[derive(Clone)]
pub struct Halo2VerifierCircuitConfig<C: CurveAffine>
where
    C::Base: PrimeField,
{
    pub base_field_config: FpChip<C>,
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct SingleProofPair<E: MultiMillerLoop> {
    pub instances: Vec<Vec<Vec<E::Scalar>>>,
    pub transcript: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SingleProofWitness<'a, E: MultiMillerLoop> {
    pub instances: &'a Vec<Vec<Vec<E::Scalar>>>,
    pub transcript: &'a Vec<u8>,
}

#[derive(Clone)]
pub struct Halo2VerifierCircuit<'a, E: MultiMillerLoop> {
    pub(crate) name: String,
    pub(crate) params: &'a ParamsVerifier<E>,
    pub(crate) vk: &'a VerifyingKey<E::G1Affine>,
    pub(crate) proofs: Vec<SingleProofWitness<'a, E>>,
    pub(crate) nproofs: usize,
}

#[derive(Clone)]
pub struct Halo2CircuitInstance<'a, E: MultiMillerLoop> {
    pub(crate) name: String,
    pub(crate) params: &'a ParamsVerifier<E>,
    pub(crate) vk: &'a VerifyingKey<E::G1Affine>,
    pub(crate) n_instances: &'a Vec<Vec<Vec<Vec<E::Scalar>>>>,
    pub(crate) n_transcript: &'a Vec<Vec<u8>>,
}

pub struct Halo2CircuitInstances<'a, E: MultiMillerLoop, const N: usize>(
    [Halo2CircuitInstance<'a, E>; N],
);

impl<
        'a,
        C: CurveAffine,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
        const N: usize,
    > Halo2CircuitInstances<'a, E, N>
{
    pub fn calc_verify_circuit_final_pair(&self) -> (C, C, Vec<<C as CurveAffine>::ScalarExt>) {
        let nchip = MockFieldChip::<C::ScalarExt, Error>::default();
        let schip = MockFieldChip::<C::ScalarExt, Error>::default();
        let pchip = MockEccChip::<C, Error>::default();
        let ctx = &mut MockChipCtx::default();

        let circuit_proofs = self
            .0
            .iter()
            .enumerate()
            .map(|(ci, instance)| {
                let mut proof_data_list = vec![];
                for (i, instances) in instance.n_instances.iter().enumerate() {
                    let transcript =
                        PoseidonTranscriptRead::<_, C, _, PoseidonEncode, 9usize, 8usize>::new(
                            &instance.n_transcript[i][..],
                            ctx,
                            &schip,
                            8usize,
                            33usize,
                        )
                        .unwrap();

                    proof_data_list.push(ProofData {
                        instances,
                        transcript,
                        key: format!("c{}p{}", ci, i),
                        _phantom: PhantomData,
                    })
                }

                CircuitProof {
                    name: instance.name.clone(),
                    vk: instance.vk,
                    params: instance.params,
                    proofs: proof_data_list,
                }
            })
            .collect();

        let empty_vec = vec![];
        let mut transcript =
            PoseidonTranscriptRead::<_, C, _, PoseidonEncode, 9usize, 8usize>::new(
                &empty_vec[..],
                ctx,
                &nchip,
                8usize,
                33usize,
            )
            .unwrap();

        let (w_x, w_g, instances, _) = verify_aggregation_proofs_in_chip(
            ctx,
            &nchip,
            &schip,
            &pchip,
            circuit_proofs,
            &mut transcript,
        )
        .unwrap();

        (w_x.to_affine(), w_g.to_affine(), instances)
    }
}

pub struct Halo2VerifierCircuits<'a, E: MultiMillerLoop, const N: usize> {
    pub circuits: [Halo2VerifierCircuit<'a, E>; N],
    pub coherent: Vec<[(usize, usize); 2]>,
}

impl<
        'a,
        C: CurveAffine,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
        const N: usize,
    > Circuit<C::ScalarExt> for Halo2VerifierCircuits<'a, E, N>
where
    C::Base: PrimeField,
{
    type Config = Halo2VerifierCircuitConfig<C>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Halo2VerifierCircuits {
            circuits: self.circuits.clone().map(|c| c.without_witnesses()),
            coherent: self.coherent.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let mut folder = std::path::PathBuf::new();
        folder.push("../halo2-snark-aggregator-circuit/src/configs");
        folder.push("verify_circuit.config");
        let params_str = std::fs::read_to_string(folder.as_path())
            .expect(format!("{} should exist", folder.to_str().unwrap()).as_str());
        let params: Halo2VerifierCircuitConfigParams =
            serde_json::from_str(params_str.as_str()).unwrap();

        assert!(
            params.limb_bits == LIMB_BITS,
            "For now we fix limb_bits = {}, otherwise change code",
            LIMB_BITS
        );
        let base_field_config = FpChip::<C>::configure(
            meta,
            params.strategy,
            params.num_advice,
            params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_ecc::utils::modulus::<C::Base>(),
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config {
            base_field_config,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Halo2VerifierCircuitConfig<C>,
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let mut layouter = layouter.namespace(|| "mult-circuit");
        let mut res = self.synthesize_proof(&config.base_field_config, &mut layouter)?;

        let base_gate = ScalarChip::new(&config.base_field_config.range.gate);
        let mut instances = None;

        // Need to trick layouter to skip first pass in get shape mode
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        layouter.assign_region(
            || "get instances",
            |region| {
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: config.base_field_config.range.gate.num_advice,
                        using_simple_floor_planner,
                        first_pass,
                    },
                );
                let ctx = &mut aux;

                // since we already ran one layouter in synthesize_proof, we can't just return with an empty region: that would tell the layouter to set the region at row 0
                // so we will set a horizontal line of cells
                if using_simple_floor_planner && first_pass {
                    for i in 0..config.base_field_config.range.gate.basic_gates.len() {
                        config.base_field_config.range.gate.assign_cell(
                            ctx,
                            QuantumCell::Witness(None),
                            config.base_field_config.range.gate.basic_gates[i].value,
                            0,
                        )?;
                    }
                    first_pass = false;
                    return Ok(());
                }

                // TODO: probably need to constrain these Fp elements to be < p
                // integer_chip.reduce(ctx, &mut res.0.x)?;
                // integer_chip.reduce(ctx, &mut res.0.y)?;
                // integer_chip.reduce(ctx, &mut res.1.x)?;
                // integer_chip.reduce(ctx, &mut res.1.y)?;

                // It uses last bit to identify y and -y, so the w_modulus must be odd.
                // assert!(integer_chip.helper.w_modulus.bit(0));

                // We now compute compressed commitments of `res` in order to constrain them to equal the public inputs of this aggregation circuit
                // See `final_pair_to_instances` for the format

                let y0_bit = config.base_field_config.range.get_last_bit(
                    ctx,
                    &res.0.y.truncation.limbs[0],
                    config.base_field_config.limb_bits,
                )?;
                let y1_bit = config.base_field_config.range.get_last_bit(
                    ctx,
                    &res.1.y.truncation.limbs[0],
                    config.base_field_config.limb_bits,
                )?;

                // Our big integers are represented with `limb_bits` sized limbs
                // We want to pack as many limbs as possible to fit into native field C::ScalarExt, allowing room for 1 extra bit
                let chunk_size = (<C::Scalar as PrimeField>::NUM_BITS as usize - 2)
                    / config.base_field_config.limb_bits;
                assert!(chunk_size > 0);
                let num_chunks = (<C::Base as PrimeField>::NUM_BITS as usize
                    + config.base_field_config.limb_bits * chunk_size
                    - 1)
                    / (config.base_field_config.limb_bits * chunk_size);

                let mut get_instance = |limbs: &Vec<AssignedCell<C::ScalarExt, C::ScalarExt>>,
                                        bit|
                 -> Result<
                    Vec<AssignedCell<C::ScalarExt, C::ScalarExt>>,
                    Error,
                > {
                    let mut instances = Vec::with_capacity(num_chunks);
                    for i in 0..num_chunks {
                        let mut a = Vec::with_capacity(chunk_size + 1);
                        let mut b = Vec::with_capacity(chunk_size + 1);
                        for j in 0..std::cmp::min(
                            chunk_size,
                            config.base_field_config.num_limbs - i * chunk_size,
                        ) {
                            a.push(QuantumCell::Existing(&limbs[i * num_chunks + j]));
                            b.push(QuantumCell::Constant(halo2_ecc::utils::biguint_to_fe(
                                &(BigUint::from(1u64) << (j * config.base_field_config.limb_bits)),
                            )));
                        }
                        if i == num_chunks - 1 {
                            a.push(QuantumCell::Existing(&bit));
                            b.push(QuantumCell::Constant(halo2_ecc::utils::biguint_to_fe(
                                &(BigUint::from(1u64)
                                    << (chunk_size * config.base_field_config.limb_bits)),
                            )));
                        }
                        let (_, _, chunk) = base_gate.0.inner_product(ctx, &a, &b)?;
                        instances.push(chunk);
                    }
                    Ok(instances)
                };

                let mut pair_instance_0 = get_instance(&res.0.x.truncation.limbs, y0_bit)?;
                let mut pair_instance_1 = get_instance(&res.1.x.truncation.limbs, y1_bit)?;

                pair_instance_0.append(&mut pair_instance_1);
                pair_instance_0.append(&mut res.2);

                let (const_rows, total_fixed, lookup_rows) =
                    config.base_field_config.finalize(ctx)?;

                println!("Finished exposing instances");
                let advice_rows = ctx.advice_rows.iter();
                let total_cells = advice_rows.clone().sum::<usize>();
                println!("total non-lookup advice cells used: {}", total_cells);
                println!(
                    "maximum rows used by an advice column: {}",
                    advice_rows.clone().max().or(Some(&0)).unwrap(),
                );
                println!(
                    "minimum rows used by an advice column: {}",
                    advice_rows.clone().min().or(Some(&usize::MAX)).unwrap(),
                );
                println!(
                    "total cells used in special lookup advice columns: {}",
                    ctx.cells_to_lookup.len()
                );
                println!(
                    "maximum rows used by a special lookup advice column: {}",
                    lookup_rows
                );
                println!("total cells used in fixed columns: {}", total_fixed);
                println!("maximum rows used by a fixed column: {}", const_rows);
                instances = Some(pair_instance_0);
                Ok(())
            },
        )?;

        Ok({
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in instances.unwrap().iter().enumerate() {
                layouter.constrain_instance(
                    assigned_instance.cell().clone(),
                    config.instance,
                    i,
                )?;
            }
        })
    }
}

impl<
        'a,
        C: CurveAffine,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
        const N: usize,
    > Halo2VerifierCircuits<'a, E, N>
where
    C::Base: PrimeField,
{
    fn synthesize_proof(
        &self,
        field_chip: &FpChip<C>,
        layouter: &mut impl Layouter<C::ScalarExt>,
    ) -> Result<
        (
            <EccChip<C> as ArithEccChip>::AssignedPoint,
            <EccChip<C> as ArithEccChip>::AssignedPoint,
            Vec<AssignedCell<C::ScalarExt, C::ScalarExt>>,
        ),
        Error,
    > {
        field_chip.load_lookup_table(layouter)?;

        let using_simple_floor_planner = true;
        let mut first_pass = true;

        let nchip = &ScalarChip::new(&field_chip.range.gate);
        let schip = nchip;
        let pchip = &EccChip::new(field_chip);

        let mut r = None;

        layouter.assign_region(
            || "proof",
            |region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: field_chip.range.gate.num_advice,
                        using_simple_floor_planner,
                        first_pass,
                    },
                );
                let ctx = &mut aux;

                let circuit_proofs = self
                    .circuits
                    .iter()
                    .enumerate()
                    .map(|(ci, instance)| {
                        let mut proof_data_list: Vec<
                            ProofData<
                                E,
                                _,
                                PoseidonTranscriptRead<
                                    _,
                                    C,
                                    _,
                                    PoseidonEncodeChip<_>,
                                    9usize,
                                    8usize,
                                >,
                            >,
                        > = vec![];

                        for i in 0..instance.nproofs {
                            let transcript = PoseidonTranscriptRead::<
                                _,
                                C,
                                _,
                                PoseidonEncodeChip<_>,
                                9usize,
                                8usize,
                            >::new(
                                &instance.proofs[i].transcript[..],
                                ctx,
                                schip,
                                8usize,
                                33usize,
                            )?;

                            proof_data_list.push(ProofData {
                                instances: &instance.proofs[i].instances,
                                transcript,
                                key: format!("c{}p{}", ci, i),
                                _phantom: PhantomData,
                            })
                        }

                        Ok(CircuitProof {
                            name: instance.name.clone(),
                            vk: instance.vk,
                            params: instance.params,
                            proofs: proof_data_list,
                        })
                    })
                    .into_iter()
                    .collect::<Result<Vec<CircuitProof<_, _, _>>, Error>>()?;

                let empty_vec = vec![];
                let mut transcript =
                    PoseidonTranscriptRead::<_, C, _, PoseidonEncodeChip<_>, 9usize, 8usize>::new(
                        &empty_vec[..],
                        ctx,
                        schip,
                        8usize,
                        33usize,
                    )?;
                let (p1, p2, v, commits) = verify_aggregation_proofs_in_chip(
                    ctx,
                    nchip,
                    schip,
                    pchip,
                    circuit_proofs,
                    &mut transcript,
                )?;
                let v = v.iter().map(|a| a.0.clone()).collect();

                for coherent in &self.coherent {
                    pchip.chip.assert_equal(
                        ctx,
                        &commits[coherent[0].0][coherent[0].1],
                        &commits[coherent[1].0][coherent[1].1],
                    )?;
                }

                r = Some((p1, p2, v));

                let (const_rows, total_fixed, lookup_rows) = field_chip.finalize(ctx)?;

                println!("Aggregate proof synthesized.");
                let advice_rows = ctx.advice_rows.iter();
                let total_cells = advice_rows.clone().sum::<usize>();
                println!("total non-lookup advice cells used: {}", total_cells);
                println!(
                    "maximum rows used by an advice column: {}",
                    advice_rows.clone().max().or(Some(&0)).unwrap(),
                );
                println!(
                    "minimum rows used by an advice column: {}",
                    advice_rows.clone().min().or(Some(&usize::MAX)).unwrap(),
                );
                println!(
                    "total cells used in special lookup advice columns: {}",
                    ctx.cells_to_lookup.len()
                );
                println!(
                    "maximum rows used by a special lookup advice column: {}",
                    lookup_rows
                );
                println!("total cells used in fixed columns: {}", total_fixed);
                println!("maximum rows used by a fixed column: {}", const_rows);

                Ok(())
            },
        )?;

        Ok(r.unwrap())
    }
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>>
    Circuit<C::ScalarExt> for Halo2VerifierCircuit<'a, E>
where
    C::Base: PrimeField,
{
    type Config = Halo2VerifierCircuitConfig<C>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            name: self.name.clone(),
            params: self.params,
            vk: self.vk,
            proofs: (0..self.nproofs).map(|_| self.proofs[0].clone()).collect(),
            nproofs: self.nproofs,
        }
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let mut folder = std::path::PathBuf::new();
        folder.push("../halo2-snark-aggregator-circuit/src/configs");
        folder.push("verify_circuit.config");
        let params_str = std::fs::read_to_string(folder.as_path())
            .expect(format!("{} should exist", folder.to_str().unwrap()).as_str());
        let params: Halo2VerifierCircuitConfigParams =
            serde_json::from_str(params_str.as_str()).unwrap();

        assert!(
            params.limb_bits == LIMB_BITS,
            "For now we fix limb_bits = {}, otherwise change code",
            LIMB_BITS
        );
        let base_field_config = FpChip::<C>::configure(
            meta,
            params.strategy,
            params.num_advice,
            params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_ecc::utils::modulus::<C::Base>(),
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config {
            base_field_config,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        Halo2VerifierCircuits {
            circuits: [self.clone()],
            coherent: vec![],
        }
        .synthesize(config, layouter)
    }
}

fn verify_circuit_builder<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C>, const N: usize>(
    circuits: [Halo2VerifierCircuit<'a, E>; N],
    coherent: Vec<[(usize, usize); 2]>,
) -> Halo2VerifierCircuits<'a, E, N> {
    Halo2VerifierCircuits { circuits, coherent }
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

pub struct Setup<C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>> {
    pub name: String,
    pub target_circuit_params: Rc<Params<C>>,
    pub target_circuit_vk: Rc<VerifyingKey<C>>,
    pub proofs: Vec<SingleProofPair<E>>,
    pub nproofs: usize,
}

impl Setup<G1Affine, Bn256> {
    pub fn new<SingleCircuit: TargetCircuit<G1Affine, Bn256>, L>(
        folder: &PathBuf,
        load_instances: L,
    ) -> Setup<G1Affine, Bn256>
    where
        L: Fn(&Vec<u8>) -> Vec<Vec<Vec<Fr>>>,
    {
        let target_circuit_instances = (0..SingleCircuit::N_PROOFS)
            .map(|index| {
                load_instances(&load_target_circuit_instance::<SingleCircuit>(
                    &mut folder.clone(),
                    index,
                ))
            })
            .collect::<Vec<_>>();

        let proofs = (0..SingleCircuit::N_PROOFS)
            .map(|index| load_target_circuit_proof::<SingleCircuit>(&mut folder.clone(), index))
            .collect::<Vec<_>>();

        let single_proof_witness = target_circuit_instances
            .into_iter()
            .zip(proofs.into_iter())
            .map(|(instances, transcript)| SingleProofPair::<Bn256> {
                instances,
                transcript,
            })
            .collect::<Vec<_>>();

        let target_circuit_params =
            load_target_circuit_params::<G1Affine, Bn256, SingleCircuit>(&mut folder.clone());
        let target_circuit_vk = load_target_circuit_vk::<G1Affine, Bn256, SingleCircuit>(
            &mut folder.clone(),
            &target_circuit_params,
        );

        Setup {
            name: format!("{:?}", folder),
            target_circuit_params: Rc::new(target_circuit_params),
            target_circuit_vk: Rc::new(target_circuit_vk),
            proofs: single_proof_witness,
            nproofs: SingleCircuit::N_PROOFS,
        }
    }
}

#[derive(Debug)]
struct SetupOutcome<C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>> {
    name: String,
    params_verifier: ParamsVerifier<E>,
    vk: Rc<VerifyingKey<C>>,
    instances: Vec<Vec<Vec<Vec<C::ScalarExt>>>>,
    proofs: Vec<Vec<u8>>,
    nproofs: usize,
}

pub struct MultiCircuitsSetup<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    const N: usize,
> {
    pub setups: [Setup<C, E>; N],
    pub coherent: Vec<[(usize, usize); 2]>,
}

fn from_0_to_n<const N: usize>() -> [usize; N] {
    let mut arr = [0; N];
    for i in 0..N {
        arr[i] = i;
    }
    arr
}

impl<C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>, const N: usize>
    MultiCircuitsSetup<C, E, N>
where
    C::Base: PrimeField,
{
    fn new_verify_circuit_info(&self, setup: bool) -> [SetupOutcome<C, E>; N] {
        from_0_to_n::<N>().map(|circuit_index| {
            let target_circuit_verifier_params = self.setups[circuit_index]
                .target_circuit_params
                .verifier::<E>(
                    self.setups[circuit_index]
                        .target_circuit_vk
                        .cs
                        .num_instance_columns,
                )
                .unwrap();

            let mut target_circuit_transcripts = vec![];
            let mut target_circuit_instances = vec![];

            for i in 0..self.setups[circuit_index].nproofs {
                let index = if setup { 0 } else { i };
                target_circuit_transcripts
                    .push(self.setups[circuit_index].proofs[index].transcript.clone());
                target_circuit_instances
                    .push(self.setups[circuit_index].proofs[index].instances.clone());
            }

            SetupOutcome::<C, E> {
                name: self.setups[circuit_index].name.clone(),
                params_verifier: target_circuit_verifier_params,
                vk: self.setups[circuit_index].target_circuit_vk.clone(),
                instances: target_circuit_instances,
                proofs: target_circuit_transcripts,
                nproofs: self.setups[circuit_index].nproofs,
            }
        })
    }

    pub fn get_params_cached(k: u32) -> Params<C> {
        let mut params_folder = std::path::PathBuf::new();
        params_folder.push("../params");
        if !params_folder.is_dir() {
            std::fs::create_dir(params_folder.as_path())
                .expect("params folder creation should not fail");
        }
        params_folder.push(format!("bn254_{}.params", k));

        let path = params_folder.as_path();

        println!("params path: {:?}", path);
        if Path::exists(path) {
            println!("read params from {:?}", path);
            let mut fd = std::fs::File::open(path).unwrap();
            Params::<C>::read(&mut fd).unwrap()
        } else {
            let params = Params::<C>::unsafe_setup::<E>(k);
            println!("write params to {:?}", path);
            let mut fd = std::fs::File::create(path).unwrap();
            params.write(&mut fd).unwrap();
            params
        }
    }

    pub fn call(&self, verify_circuit_k: u32) -> (Params<C>, VerifyingKey<C>) {
        let setup_outcome = self.new_verify_circuit_info(true);

        let verify_circuit = verify_circuit_builder(
            from_0_to_n::<N>().map(|i| Halo2VerifierCircuit {
                name: setup_outcome[i].name.clone(),
                params: &setup_outcome[i].params_verifier,
                vk: &setup_outcome[i].vk,
                proofs: setup_outcome[i]
                    .instances
                    .iter()
                    .zip(setup_outcome[i].proofs.iter())
                    .map(|(instances, transcript)| SingleProofWitness {
                        instances,
                        transcript,
                    })
                    .collect(),
                nproofs: setup_outcome[i].nproofs,
            }),
            self.coherent.clone(),
        );
        info!("circuit build done");

        // for testing purposes
        let prover = match halo2_proofs::dev::MockProver::run(
            verify_circuit_k,
            &verify_circuit,
            vec![vec![]],
        ) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));

        // TODO: Do not use this setup in production
        let verify_circuit_params = Self::get_params_cached(verify_circuit_k);
        info!("setup params done");

        let verify_circuit_vk =
            keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");
        info!("setup vkey done");

        (verify_circuit_params, verify_circuit_vk)
    }
}

pub fn final_pair_to_instances<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
>(
    pair: &(C, C, Vec<E::Scalar>),
    limb_bits: usize,
) -> Vec<C::ScalarExt>
where
    C::Base: PrimeField,
{
    // Our big integers are represented with `limb_bits` sized limbs
    // We want to pack as many limbs as possible to fit into native field C::ScalarExt, allowing room for 1 extra bit
    let chunk_size = (<C::Scalar as PrimeField>::NUM_BITS as usize - 2) / limb_bits;
    assert!(chunk_size > 0);
    let num_chunks = (<C::Base as PrimeField>::NUM_BITS as usize + limb_bits * chunk_size - 1)
        / (limb_bits * chunk_size);

    let w_to_limbs_le = |w: &C::Base| {
        let w_big = halo2_ecc::utils::fe_to_biguint(w);
        halo2_ecc::utils::decompose_biguint::<C::ScalarExt>(
            &w_big,
            num_chunks,
            chunk_size * limb_bits,
        )
    };
    let mut w_x_x = w_to_limbs_le(pair.0.coordinates().unwrap().x());
    let mut w_g_x = w_to_limbs_le(pair.1.coordinates().unwrap().x());

    let get_last_bit = |w: &C::Base| -> C::ScalarExt {
        let w_big = halo2_ecc::utils::fe_to_biguint(w);
        if w_big % 2u64 == BigUint::from(0u64) {
            C::ScalarExt::from(0)
        } else {
            halo2_ecc::utils::biguint_to_fe(&(BigUint::from(1u64) << (chunk_size * limb_bits)))
        }
    };

    if let Some(w_hi) = w_x_x.last_mut() {
        *w_hi = *w_hi + get_last_bit(pair.0.coordinates().unwrap().y());
    }
    if let Some(w_hi) = w_g_x.last_mut() {
        *w_hi = *w_hi + get_last_bit(pair.1.coordinates().unwrap().y());
    }

    w_x_x.append(&mut w_g_x);
    let mut verify_circuit_instances = w_x_x;

    pair.2.iter().for_each(|instance| {
        verify_circuit_instances.push(*instance);
    });

    verify_circuit_instances
}

// This is used for zkevm bench
pub fn calc_verify_circuit_instances<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
>(
    name: String,
    params: &ParamsVerifier<E>,
    vk: &VerifyingKey<C>,
    n_instances: &Vec<Vec<Vec<Vec<E::Scalar>>>>,
    n_transcript: &Vec<Vec<u8>>,
) -> Vec<C::ScalarExt>
where
    C::Base: PrimeField,
{
    let pair = Halo2CircuitInstances([Halo2CircuitInstance {
        name,
        params,
        vk,
        n_instances,
        n_transcript,
    }])
    .calc_verify_circuit_final_pair();
    final_pair_to_instances::<C, E>(&pair, LIMB_BITS)
}

pub struct CreateProof<C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>> {
    pub name: String,
    pub target_circuit_params: Rc<Params<C>>,
    pub target_circuit_vk: Rc<VerifyingKey<C>>,
    pub template_proofs: Vec<SingleProofPair<E>>,
    pub proofs: Vec<SingleProofPair<E>>,
    pub nproofs: usize,
}

impl CreateProof<G1Affine, Bn256> {
    pub fn new<SingleCircuit: TargetCircuit<G1Affine, Bn256>, L>(
        folder: &PathBuf,
        load_instances: L,
    ) -> CreateProof<G1Affine, Bn256>
    where
        L: Fn(&Vec<u8>) -> Vec<Vec<Vec<Fr>>>,
    {
        let instances = (0..SingleCircuit::N_PROOFS)
            .map(|index| {
                load_instances(&load_target_circuit_instance::<SingleCircuit>(
                    &mut folder.clone(),
                    index,
                ))
            })
            .collect::<Vec<_>>();

        let proofs = (0..SingleCircuit::N_PROOFS)
            .map(|index| load_target_circuit_proof::<SingleCircuit>(&mut folder.clone(), index))
            .collect::<Vec<_>>();

        let single_proof_witness = instances
            .into_iter()
            .zip(proofs.into_iter())
            .map(|(instances, transcript)| SingleProofPair::<Bn256> {
                instances,
                transcript,
            })
            .collect::<Vec<_>>();

        let target_circuit_params =
            load_target_circuit_params::<G1Affine, Bn256, SingleCircuit>(&mut folder.clone());
        let target_circuit_vk = load_target_circuit_vk::<G1Affine, Bn256, SingleCircuit>(
            &mut folder.clone(),
            &target_circuit_params,
        );

        CreateProof {
            name: format!("{:?}", folder),
            target_circuit_params: Rc::new(target_circuit_params),
            target_circuit_vk: Rc::new(target_circuit_vk),
            template_proofs: single_proof_witness.clone(),
            proofs: single_proof_witness,
            nproofs: SingleCircuit::N_PROOFS,
        }
    }
}

pub struct MultiCircuitsCreateProof<
    'a,
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    const N: usize,
> {
    pub target_circuit_proofs: [CreateProof<C, E>; N],
    pub verify_circuit_params: &'a Params<C>,
    pub verify_circuit_vk: VerifyingKey<C>,
    pub coherent: Vec<[(usize, usize); 2]>,
}

impl<C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>, const N: usize>
    MultiCircuitsCreateProof<'_, C, E, N>
where
    C::Base: PrimeField,
{
    pub fn call(
        self,
    ) -> (
        ProvingKey<C>,
        (C, C, Vec<C::ScalarExt>),
        Vec<C::ScalarExt>,
        Vec<u8>,
    ) {
        let setup = MultiCircuitsSetup {
            setups: self.target_circuit_proofs.map(|target_circuit| Setup {
                name: target_circuit.name,
                target_circuit_params: target_circuit.target_circuit_params,
                target_circuit_vk: target_circuit.target_circuit_vk,
                proofs: target_circuit.template_proofs, // template_proofs?
                nproofs: target_circuit.nproofs,
            }),
            coherent: self.coherent.clone(),
        };

        let now = std::time::Instant::now();

        let setup_outcome = setup.new_verify_circuit_info(false);
        let verify_circuit = {
            verify_circuit_builder(
                from_0_to_n::<N>().map(|i| Halo2VerifierCircuit {
                    name: setup_outcome[i].name.clone(),
                    params: &setup_outcome[i].params_verifier,
                    vk: &setup_outcome[i].vk,
                    proofs: setup_outcome[i]
                        .instances
                        .iter()
                        .zip(setup_outcome[i].proofs.iter())
                        .map(|(instances, transcript)| SingleProofWitness {
                            instances,
                            transcript,
                        })
                        .collect(),
                    nproofs: setup_outcome[i].nproofs,
                }),
                self.coherent,
            )
        };

        /*
        let (instances, transcripts) = {
            let mut verify_circuit_transcripts = vec![];
            let mut verify_circuit_instances = vec![];

            for i in 0..N {
                for j in 0..self.target_circuit_proofs[i].nproofs {
                    verify_circuit_transcripts
                        .push(self.target_circuit_proofs[i].proofs[j].transcript.clone());
                    verify_circuit_instances
                        .push(self.target_circuit_proofs[i].proofs[j].instances.clone());
                }
            }

            (verify_circuit_instances, verify_circuit_transcripts)
        };
        */

        let setup_outcome = setup.new_verify_circuit_info(false);

        let verify_circuit_final_pair = {
            Halo2CircuitInstances(from_0_to_n::<N>().map(|i| Halo2CircuitInstance {
                name: setup_outcome[i].name.clone(),
                params: &setup_outcome[i].params_verifier,
                vk: &setup_outcome[i].vk,
                n_instances: &setup_outcome[i].instances,
                n_transcript: &setup_outcome[i].proofs,
            }))
            .calc_verify_circuit_final_pair()
        };

        let verify_circuit_instances =
            final_pair_to_instances::<C, E>(&verify_circuit_final_pair, LIMB_BITS);

        let verify_circuit_pk = keygen_pk(
            &self.verify_circuit_params,
            self.verify_circuit_vk,
            &verify_circuit,
        )
        .expect("keygen_pk should not fail");

        let elapsed_time = now.elapsed();
        info!("Running keygen_pk took {} seconds.", elapsed_time.as_secs());

        let instances: &[&[&[C::ScalarExt]]] = &[&[&verify_circuit_instances[..]]];
        let mut transcript = ShaWrite::<_, _, Challenge255<_>, sha2::Sha256>::init(vec![]);
        create_proof(
            &self.verify_circuit_params,
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

        (
            verify_circuit_pk,
            verify_circuit_final_pair,
            verify_circuit_instances,
            proof,
        )
    }
}

pub struct VerifyCheck<C: CurveAffine> {
    pub verify_params: Rc<Params<C>>,
    pub verify_vk: Rc<VerifyingKey<C>>,
    pub verify_instance: Vec<Vec<Vec<C::ScalarExt>>>,
    pub verify_public_inputs_size: usize,
    pub verify_proof: Vec<u8>,
}

impl VerifyCheck<G1Affine> {
    pub fn new(folder: &PathBuf, verify_public_inputs_size: usize) -> VerifyCheck<G1Affine> {
        VerifyCheck::<G1Affine> {
            verify_params: Rc::new(load_verify_circuit_params(&mut folder.clone())),
            verify_vk: Rc::new(load_verify_circuit_vk(&mut folder.clone())),
            verify_instance: load_verify_circuit_instance(&mut folder.clone()),
            verify_proof: load_verify_circuit_proof(&mut folder.clone()),
            verify_public_inputs_size,
        }
    }
}

impl<C: CurveAffine> VerifyCheck<C> {
    pub fn call<E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>>(
        &self,
    ) -> Result<(), Error> {
        let params = self
            .verify_params
            .verifier::<E>(self.verify_public_inputs_size)
            .unwrap();
        let strategy = SingleVerifier::new(&params);

        let verify_circuit_instance1: Vec<Vec<&[E::Scalar]>> = self
            .verify_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[E::Scalar]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        let mut transcript =
            ShaRead::<_, _, Challenge255<_>, sha2::Sha256>::init(&self.verify_proof[..]);

        verify_proof(
            &params,
            &self.verify_vk,
            strategy,
            &verify_circuit_instance2[..],
            &mut transcript,
        )
    }
}
