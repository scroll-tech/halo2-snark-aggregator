use crate::fs::{
    get_params_cached, load_target_circuit_instance, load_target_circuit_proof,
    load_verify_circuit_instance, load_verify_circuit_params, load_verify_circuit_proof,
    load_verify_circuit_vk,
};
use crate::sample_circuit::TargetCircuit;

use super::chips::{
    ecc_chip::{EccChip, FpChip},
    encode_chip::PoseidonEncodeChip,
    scalar_chip::ScalarChip,
};
use ark_std::{end_timer, start_timer};
use ff::PrimeField;
use halo2_base::gates::GateInstructions;
use halo2_base::{AssignedValue, Context, ContextParams, QuantumCell};
use halo2_ecc::fields::fp::FpStrategy;
use halo2_proofs::circuit::{Cell, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::halo2curves::group::Group;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::pairing::MillerLoopResult;
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::halo2curves::CurveAffineExt;
use halo2_proofs::plonk::{create_proof, keygen_vk, Fixed, ProvingKey};
use halo2_proofs::plonk::{Column, Instance};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::Layouter,
    plonk::{Circuit, ConstraintSystem, Error, VerifyingKey},
    poly::commitment::Params,
};
use halo2_proofs::{
    plonk::{keygen_pk, verify_proof},
    transcript::Challenge255,
};
use halo2_snark_aggregator_api::arith::ecc::ArithEccChip;
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
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::path::PathBuf;
use std::rc::Rc;
use std::{io::Read, marker::PhantomData};

const LIMB_BITS: usize = 88;

// for tuning the circuit
#[derive(Serialize, Deserialize)]
pub struct Halo2VerifierCircuitConfigParams {
    pub strategy: FpStrategy,
    pub degree: usize,
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
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    pub base_field_config: FpChip<C>,
    // `constants` is a vector of fixed columns for allocating constant values
    pub constants: Vec<Column<Fixed>>,
    pub instance: Column<Instance>,
    pub max_rows: usize,
    pub num_advices: usize,
}

#[derive(Clone, Debug)]
pub struct SingleProofPair<E: Engine> {
    pub instances: Vec<Vec<Vec<E::Scalar>>>,
    pub transcript: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SingleProofWitness<'a, E: Engine> {
    pub instances: &'a Vec<Vec<Vec<E::Scalar>>>,
    pub transcript: &'a Vec<u8>,
}

#[derive(Clone)]
pub struct Halo2VerifierCircuit<'a, E: Engine> {
    pub(crate) name: String,
    pub(crate) params: &'a ParamsVerifierKZG<E>,
    pub(crate) vk: &'a VerifyingKey<E::G1Affine>,
    pub(crate) proofs: Vec<SingleProofWitness<'a, E>>,
    pub(crate) nproofs: usize,
}

#[derive(Clone)]
pub struct Halo2CircuitInstance<'a, E: Engine> {
    pub(crate) name: String,
    pub(crate) params: &'a ParamsVerifierKZG<E>,
    pub(crate) vk: &'a VerifyingKey<E::G1Affine>,
    pub(crate) n_instances: &'a Vec<Vec<Vec<Vec<E::Scalar>>>>,
    pub(crate) n_transcript: &'a Vec<Vec<u8>>,
}

pub struct Halo2CircuitInstances<'a, E: Engine, const N: usize>([Halo2CircuitInstance<'a, E>; N]);

impl<
        'a,
        C: CurveAffine,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
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
            .map(|(_ci, instance)| {
                let mut proof_data_list = vec![];
                for (i, instances) in instance.n_instances.iter().enumerate() {
                    let transcript =
                        PoseidonTranscriptRead::<_, C, _, PoseidonEncode, 9usize, 8usize>::new(
                            &instance.n_transcript[i][..],
                            ctx,
                            &schip,
                            8usize,
                            63usize,
                        )
                        .unwrap();

                    proof_data_list.push(ProofData {
                        instances,
                        transcript,
                        key: format!("{}_p{}", instance.name, i),
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
                63usize,
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

        if true {
            // check final pair
            let s_g2_prepared = <E as MultiMillerLoop>::G2Prepared::from(self.0[0].params.s_g2());
            let n_g2_prepared = <E as MultiMillerLoop>::G2Prepared::from(-self.0[0].params.g2());
            let terms = &[
                (&(w_x.to_affine()), &s_g2_prepared),
                (&w_g.to_affine(), &n_g2_prepared),
            ];
            let success = bool::from(
                <E as MultiMillerLoop>::multi_miller_loop(terms)
                    .final_exponentiation()
                    .is_identity(),
            );
            log::debug!(
                "check final pairing({}): {:?}",
                success,
                (
                    w_x.to_affine(),
                    w_g.to_affine(),
                    self.0[0].params.s_g2(),
                    -self.0[0].params.g2()
                )
            );
            debug_assert!(success);
        }
        (w_x.to_affine(), w_g.to_affine(), instances)
    }
}

pub struct Halo2VerifierCircuits<'a, E: Engine, const N: usize> {
    pub circuits: [Halo2VerifierCircuit<'a, E>; N],
    pub coherent: Vec<[(usize, usize); 2]>,
}

impl<
        'a,
        C: CurveAffineExt,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
        const N: usize,
    > Circuit<C::ScalarExt> for Halo2VerifierCircuits<'a, E, N>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
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
        let params_str = include_str!("configs/verify_circuit.config");
        let params: Halo2VerifierCircuitConfigParams = serde_json::from_str(params_str).unwrap();

        assert!(
            params.limb_bits == LIMB_BITS,
            "For now we fix limb_bits = {}, otherwise change code",
            LIMB_BITS
        );
        let base_field_config = FpChip::<C>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_base::utils::modulus::<C::Base>(),
            0,
            params.degree,
        );

        let mut constants = Vec::with_capacity(params.num_fixed);
        for _i in 0..params.num_fixed {
            let c = meta.fixed_column();
            meta.enable_equality(c);
            // meta.enable_constant(c);
            constants.push(c);
        }

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config {
            base_field_config,
            constants,
            instance,
            max_rows: 1 << params.degree,
            num_advices: params.num_advice,
        }
    }

    fn synthesize(
        &self,
        config: Halo2VerifierCircuitConfig<C>,
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let mut layouter = layouter.namespace(|| "mult-circuit");
        config.base_field_config.load_lookup_table(&mut layouter)?;

        let base_gate = ScalarChip::new(config.base_field_config.range.gate.clone());

        // Need to trick layouter to skip first pass in get shape mode
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        let instances = layouter.assign_region(
            || "get instances",
            |region| -> Result<Vec<Cell>, _> {
                if using_simple_floor_planner && first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.max_rows,
                        num_advice: vec![config.num_advices],
                        fixed_columns: config.constants.clone(),
                    },
                );
                let ctx = &mut aux;

                let mut res = self.synthesize_proof(config.base_field_config.clone(), ctx)?;
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
                    &res.0.y.truncation.limbs[0].clone(),
                    config.base_field_config.limb_bits,
                );
                let y1_bit = config.base_field_config.range.get_last_bit(
                    ctx,
                    &res.1.y.truncation.limbs[0].clone(),
                    config.base_field_config.limb_bits,
                );

                // Our big integers are represented with `limb_bits` sized limbs
                // We want to pack as many limbs as possible to fit into native field C::ScalarExt, allowing room for 1 extra bit
                let mut pair_instance_0 = get_instance::<C, E>(
                    &base_gate,
                    ctx,
                    &res.0.x.truncation.limbs,
                    &y0_bit,
                    config.base_field_config.limb_bits,
                    config.base_field_config.num_limbs,
                )?;
                let mut pair_instance_1 = get_instance::<C, E>(
                    &base_gate,
                    ctx,
                    &res.1.x.truncation.limbs,
                    &y1_bit,
                    config.base_field_config.limb_bits,
                    config.base_field_config.num_limbs,
                )?;

                pair_instance_0.append(&mut pair_instance_1);
                pair_instance_0.append(&mut res.2);

                let sizes = config.base_field_config.finalize(ctx);
                let const_rows = sizes[0];
                let total_fixed = sizes[1];
                let lookup_rows = sizes[2];

                println!("Finished exposing instances\n");
                // let advice_rows = ctx.advice_alloc.iter();
                // let total_cells = advice_rows.map(|&x|x.clone().sum::<usize>()).sum();
                // println!("total non-lookup advice cells used: {}", total_cells);
                println!("maximum rows used by an advice column: {}", ctx.max_rows,);
                // println!(
                //     "minimum rows used by an advice column: {}",
                //     advice_rows.clone().min().or(Some(&usize::MAX)).unwrap(),
                // );
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

                Ok(pair_instance_0.iter().map(|x| x.cell()).collect::<Vec<_>>())
            },
        )?;

        Ok({
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in instances.iter().enumerate() {
                layouter.constrain_instance(*assigned_instance, config.instance, i)?;
            }
        })
    }
}

fn get_instance<'a: 'c, 'c, C, E>(
    base_gate: &ScalarChip<C::ScalarExt>,
    ctx: &mut Context<'c, C::ScalarExt>,
    limbs: &[AssignedValue<'a, C::ScalarExt>],
    bit: &AssignedValue<'a, E::Scalar>,
    limb_bits: usize,
    num_limbs: usize,
) -> Result<Vec<AssignedValue<'c, C::ScalarExt>>, Error>
where
    C: CurveAffineExt,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    let chunk_size = (<C::Scalar as PrimeField>::NUM_BITS as usize - 2) / limb_bits;
    assert!(chunk_size > 0);
    let num_chunks = (<C::Base as PrimeField>::NUM_BITS as usize + limb_bits * chunk_size - 1)
        / (limb_bits * chunk_size);

    let mut instances = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks {
        let mut a = Vec::with_capacity(chunk_size + 1);
        let mut b = Vec::with_capacity(chunk_size + 1);
        for j in 0..std::cmp::min(chunk_size, num_limbs - i * chunk_size) {
            a.push(QuantumCell::Existing(&limbs[i * num_chunks + j]));
            b.push(QuantumCell::Constant(halo2_base::utils::biguint_to_fe(
                &(BigUint::from(1u64) << (j * limb_bits)),
            )));
        }
        if i == num_chunks - 1 {
            a.push(QuantumCell::Existing(&bit));
            b.push(QuantumCell::Constant(halo2_base::utils::biguint_to_fe(
                &(BigUint::from(1u64) << (chunk_size * limb_bits)),
            )));
        }
        let chunk = base_gate.0.inner_product(ctx, a, b);
        instances.push(chunk);
    }
    Ok(instances)
}

impl<
        'a,
        C: CurveAffineExt,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
        const N: usize,
    > Halo2VerifierCircuits<'a, E, N>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn synthesize_proof<'c>(
        &self,
        field_chip: FpChip<C>,
        ctx: &mut Context<'c, C::ScalarExt>,
    ) -> Result<
        (
            <EccChip<'c, C> as ArithEccChip>::AssignedPoint,
            <EccChip<'c, C> as ArithEccChip>::AssignedPoint,
            Vec<AssignedValue<'c, C::ScalarExt>>,
        ),
        Error,
    > {
        let nchip = &ScalarChip::new(field_chip.range.gate.clone());
        let schip = nchip;
        let pchip = &EccChip::new(field_chip);

        let circuit_proofs = self
            .circuits
            .iter()
            .enumerate()
            .map(|(ci, instance)| {
                let mut proof_data_list: Vec<
                    ProofData<
                        E,
                        _,
                        PoseidonTranscriptRead<_, C, _, PoseidonEncodeChip<_>, 9usize, 8usize>,
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
                        63usize,
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
        let mut transcript = PoseidonTranscriptRead::<
            _,
            C,
            _,
            PoseidonEncodeChip<_>,
            9usize,
            8usize,
        >::new(&empty_vec[..], ctx, schip, 8usize, 33usize)?;

        let (p1, p2, v, commits) = verify_aggregation_proofs_in_chip(
            ctx,
            nchip,
            schip,
            pchip,
            circuit_proofs,
            &mut transcript,
        )?;

        for coherent in &self.coherent {
            pchip.chip.assert_equal(
                ctx,
                &commits[coherent[0].0][coherent[0].1],
                &commits[coherent[1].0][coherent[1].1],
            );
        }

        println!("Aggregate proof synthesized.");

        Ok((p1, p2, v))
    }
}

impl<'a, C: CurveAffineExt, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug>
    Circuit<C::ScalarExt> for Halo2VerifierCircuit<'a, E>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
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
        let params_str = include_str!("configs/verify_circuit.config");
        let params: Halo2VerifierCircuitConfigParams = serde_json::from_str(params_str).unwrap();

        assert!(
            params.limb_bits == LIMB_BITS,
            "For now we fix limb_bits = {}, otherwise change code",
            LIMB_BITS
        );
        let base_field_config = FpChip::<C>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_base::utils::modulus::<C::Base>(),
            0,
            params.degree as usize,
        );

        let mut constants = Vec::with_capacity(params.num_fixed);
        for _i in 0..params.num_fixed {
            let c = meta.fixed_column();
            meta.enable_equality(c);
            // meta.enable_constant(c);
            constants.push(c);
        }

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config {
            base_field_config,
            constants,
            instance,
            max_rows: 1 << params.degree,
            num_advices: params.num_advice,
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

fn verify_circuit_builder<'a, C: CurveAffine, E: Engine<G1Affine = C>, const N: usize>(
    circuits: [Halo2VerifierCircuit<'a, E>; N],
    coherent: Vec<[(usize, usize); 2]>,
) -> Halo2VerifierCircuits<'a, E, N> {
    Halo2VerifierCircuits { circuits, coherent }
}

pub fn load_params<E: MultiMillerLoop + Debug>(
    folder: &mut std::path::PathBuf,
    file_name: &str,
) -> ParamsKZG<E> {
    folder.push(file_name);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();
    ParamsKZG::<E>::read(&mut fd).unwrap()
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

pub struct Setup<C: CurveAffine, E: Engine<G1Affine = C, Scalar = C::ScalarExt>> {
    pub name: String,
    pub target_circuit_params: Rc<ParamsKZG<E>>,
    pub target_circuit_vk: Rc<VerifyingKey<C>>,
    pub proofs: Vec<SingleProofPair<E>>,
    pub nproofs: usize,
}

impl Setup<G1Affine, Bn256> {
    pub fn new<SingleCircuit: TargetCircuit<Bn256>, L>(
        folder: &PathBuf,
        load_instances: L,
    ) -> Setup<G1Affine, Bn256>
    where
        L: Fn(&[u8]) -> Vec<Vec<Vec<Fr>>>,
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
            get_params_cached::<G1Affine, Bn256>(SingleCircuit::TARGET_CIRCUIT_K);
        let target_circuit_vk =
            keygen_vk(&target_circuit_params, &SingleCircuit::Circuit::default())
                .expect("keygen_vk should not fail");
        /*
        // vk read does not work..
        load_target_circuit_vk::<G1Affine, Bn256, SingleCircuit>(
            &mut folder.clone(),
            &target_circuit_params,
        );
        */

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
struct SetupOutcome<C: CurveAffine, E: Engine<G1Affine = C, Scalar = C::ScalarExt>> {
    name: String,
    params_verifier: ParamsVerifierKZG<E>,
    vk: Rc<VerifyingKey<C>>,
    instances: Vec<Vec<Vec<Vec<C::ScalarExt>>>>,
    proofs: Vec<Vec<u8>>,
    nproofs: usize,
}

pub struct MultiCircuitsSetup<
    C: CurveAffine,
    E: Engine<G1Affine = C, Scalar = C::ScalarExt>,
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

impl<
        C: CurveAffineExt,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
        const N: usize,
    > MultiCircuitsSetup<C, E, N>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn new_verify_circuit_info(&self, setup: bool) -> [SetupOutcome<C, E>; N] {
        from_0_to_n::<N>().map(|circuit_index| {
            let target_circuit_verifier_params = self.setups[circuit_index]
                .target_circuit_params
                .verifier_params();

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
                params_verifier: target_circuit_verifier_params.clone(),
                vk: self.setups[circuit_index].target_circuit_vk.clone(),
                instances: target_circuit_instances,
                proofs: target_circuit_transcripts,
                nproofs: self.setups[circuit_index].nproofs,
            }
        })
    }

    pub fn call(&self, verify_circuit_k: u32) -> (ParamsKZG<E>, VerifyingKey<C>) {
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

        // TODO: Do not use this setup in production
        let verify_circuit_params = get_params_cached::<C, E>(verify_circuit_k);
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
    pair: &(C, C, Vec<C::ScalarExt>),
    limb_bits: usize,
) -> Vec<C::ScalarExt>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    // Our big integers are represented with `limb_bits` sized limbs
    // We want to pack as many limbs as possible to fit into native field C::ScalarExt, allowing room for 1 extra bit
    let chunk_size = (<C::Scalar as PrimeField>::NUM_BITS as usize - 2) / limb_bits;
    assert!(chunk_size > 0);
    let num_chunks = (<C::Base as PrimeField>::NUM_BITS as usize + limb_bits * chunk_size - 1)
        / (limb_bits * chunk_size);

    let w_to_limbs_le = |w: &C::Base| {
        let w_big = halo2_base::utils::fe_to_biguint(w);
        halo2_base::utils::decompose_biguint::<C::ScalarExt>(
            &w_big,
            num_chunks,
            chunk_size * limb_bits,
        )
    };
    // println!("{:#?}\n{:#?}", pair.0.coordinates(), pair.1.coordinates());
    let mut w_x_x = w_to_limbs_le(pair.0.coordinates().unwrap().x());
    let mut w_g_x = w_to_limbs_le(pair.1.coordinates().unwrap().x());

    let get_last_bit = |w: &C::Base| -> C::ScalarExt {
        let w_big = halo2_base::utils::fe_to_biguint(w);
        if w_big % 2u64 == BigUint::from(0u64) {
            C::ScalarExt::from(0)
        } else {
            halo2_base::utils::biguint_to_fe(&(BigUint::from(1u64) << (chunk_size * limb_bits)))
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
    C: CurveAffineExt,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
>(
    name: String,
    params: &ParamsVerifierKZG<E>,
    vk: &VerifyingKey<C>,
    n_instances: &Vec<Vec<Vec<Vec<E::Scalar>>>>,
    n_transcript: &Vec<Vec<u8>>,
) -> Vec<C::ScalarExt>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
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

pub struct CreateProof<C: CurveAffine, E: Engine<G1Affine = C, Scalar = C::ScalarExt>> {
    pub name: String,
    pub target_circuit_params: Rc<ParamsKZG<E>>,
    pub target_circuit_vk: Rc<VerifyingKey<C>>,
    pub template_proofs: Vec<SingleProofPair<E>>,
    pub proofs: Vec<SingleProofPair<E>>,
    pub nproofs: usize,
}

impl CreateProof<G1Affine, Bn256> {
    pub fn new<SingleCircuit: TargetCircuit<Bn256>, L>(
        folder: &PathBuf,
        load_instances: L,
    ) -> CreateProof<G1Affine, Bn256>
    where
        L: Fn(&[u8]) -> Vec<Vec<Vec<Fr>>>,
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
            get_params_cached::<G1Affine, Bn256>(SingleCircuit::TARGET_CIRCUIT_K);
        let target_circuit_vk =
            keygen_vk(&target_circuit_params, &SingleCircuit::Circuit::default())
                .expect("keygen_vk should not fail");

        /*
        let target_circuit_params =
            load_target_circuit_params::<G1Affine, Bn256, SingleCircuit>(&mut folder.clone());
        let target_circuit_vk = load_target_circuit_vk::<G1Affine, Bn256, SingleCircuit>(
            &mut folder.clone(),
            &target_circuit_params,
        );
        */

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
    E: Engine<G1Affine = C, Scalar = C::ScalarExt>,
    const N: usize,
> {
    pub target_circuit_proofs: [CreateProof<C, E>; N],
    pub verify_circuit_params: &'a ParamsKZG<E>,
    // pub verify_circuit_vk: VerifyingKey<C>,
    pub coherent: Vec<[(usize, usize); 2]>,
    pub verify_public_inputs_size: usize,
}

impl<
        C: CurveAffineExt,
        E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt> + Debug,
        const N: usize,
    > MultiCircuitsCreateProof<'_, C, E, N>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
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

        let instances: &[&[&[C::ScalarExt]]] = &[&[&verify_circuit_instances[..]]];

        /*
        // for testing purposes
        let mock_prover_time = start_timer!(|| "Mock prover");
        let prover = match halo2_proofs::dev::MockProver::run(
            21,
            &verify_circuit,
            vec![verify_circuit_instances.clone()],
        ) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
        end_timer!(mock_prover_time);
        */

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(self.verify_circuit_params, &verify_circuit)
            .expect("keygen_vk should not fail");
        println!("vk done");
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let verify_circuit_pk = keygen_pk(
            self.verify_circuit_params,
            vk, //self.verify_circuit_vk,
            &verify_circuit,
        )
        .expect("keygen_pk should not fail");
        end_timer!(pk_time);

        let proof_time = start_timer!(|| "Proving time");
        let mut transcript = ShaWrite::<_, C, Challenge255<_>, sha2::Sha256>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &self.verify_circuit_params,
            &verify_circuit_pk,
            &[verify_circuit],
            instances,
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "Verify time");
        let params_verifier: ParamsVerifierKZG<E> =
            self.verify_circuit_params.verifier_params().clone();
        let strategy = SingleStrategy::new(&params_verifier);

        let mut transcript = ShaRead::<_, _, Challenge255<_>, sha2::Sha256>::init(&proof[..]);

        assert!(verify_proof::<_, VerifierGWC<_>, _, _, _>(
            &params_verifier,
            &verify_circuit_pk.get_vk(),
            strategy,
            instances,
            &mut transcript,
        )
        .is_ok());
        end_timer!(verify_time);

        (
            verify_circuit_pk,
            verify_circuit_final_pair,
            verify_circuit_instances,
            proof,
        )
    }
}

pub struct VerifyCheck<E: Engine> {
    pub verify_params: Rc<ParamsKZG<E>>,
    pub verify_vk: VerifyingKey<E::G1Affine>,
    pub verify_instance: Vec<Vec<Vec<E::Scalar>>>,
    pub verify_public_inputs_size: usize,
    pub verify_proof: Vec<u8>,
}

impl VerifyCheck<Bn256> {
    pub fn new(folder: &PathBuf, verify_public_inputs_size: usize) -> VerifyCheck<Bn256> {
        VerifyCheck::<Bn256> {
            verify_params: Rc::new(load_verify_circuit_params(&mut folder.clone())),
            verify_vk: load_verify_circuit_vk(&mut folder.clone()),
            verify_instance: load_verify_circuit_instance(&mut folder.clone()),
            verify_proof: load_verify_circuit_proof(&mut folder.clone()),
            verify_public_inputs_size,
        }
    }
}

impl<E: MultiMillerLoop + Debug> VerifyCheck<E> {
    pub fn call(&self) -> Result<(), Error> {
        let params = self.verify_params.verifier_params();
        let strategy = SingleStrategy::new(&params);

        let verify_circuit_instance1: Vec<Vec<&[E::Scalar]>> = self
            .verify_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[E::Scalar]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        let mut transcript =
            ShaRead::<_, _, Challenge255<_>, sha2::Sha256>::init(&self.verify_proof[..]);

        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            params,
            &self.verify_vk,
            strategy,
            &verify_circuit_instance2[..],
            &mut transcript,
        )
    }
}
