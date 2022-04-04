use std::marker::PhantomData;

use crate::arith::code::{FieldCode, PointCode};
use crate::field::bn_to_field;
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner};

use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof_check, Advice, Circuit, Column,
    ConstraintSystem, Error, Instance, Selector, SingleVerifier,
};
use halo2_proofs::poly::commitment::ParamsVerifier;
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_pcg::Pcg32;
// use halo2_proofs::poly::commitment::{Guard, MSM};
use crate::verify::halo2::verify::VerifierParams;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::Challenge255;
use pairing_bn256::bn256::Fr as Fp;
use pairing_bn256::bn256::{Bn256, G1Affine};

#[derive(Clone, Debug)]
pub struct FieldConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    /// This is the public input (instance) column.
    instance: Column<Instance>,

    // We need a selector to enable the multiplication gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::mul` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_mul: Selector,
}

struct FieldChip<F: FieldExt> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}

trait NumericInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Num;

    /// Loads a number into the circuit as a private input.
    fn load_private(&self, layouter: impl Layouter<F>, a: Option<F>) -> Result<Self::Num, Error>;

    /// Loads a number into the circuit as a fixed constant.
    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;

    /// Returns `c = a * b`.
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Exposes a number as a public input to the circuit.
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}

struct Number<F: FieldExt>(AssignedCell<F, F>);

impl<F: FieldExt> Chip<F> for FieldChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> FieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance);
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_mul = meta.selector();

        // Define our multiplication gate!
        meta.create_gate("mul", |meta| {
            // To implement multiplication, we need three advice cells and a selector
            // cell. We arrange them like so:
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            // Gates may refer to any relative offsets we want, but each distinct
            // offset adds a cost to the proof. The most common offsets are 0 (the
            // current row), 1 (the next row), and -1 (the previous row), for which
            // `Rotation` has specific constructors.
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint.
            //
            // The polynomial expressions returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            // has the following properties:
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs - out)]
        });

        FieldConfig {
            advice,
            instance,
            s_mul,
        }
    }
}

impl<F: FieldExt> NumericInstructions<F> for FieldChip<F> {
    type Num = Number<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Option<F>,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(
                        || "private input",
                        config.advice[0],
                        0,
                        || value.ok_or(Error::Synthesis),
                    )
                    .map(Number)
            },
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                region
                    .assign_advice_from_constant(|| "constant value", config.advice[0], 0, constant)
                    .map(Number)
            },
        )
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can assign the multiplication result, which is to be assigned
                // into the output position.
                let value = a.0.value().and_then(|a| b.0.value().map(|b| *a * *b));

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region
                    .assign_advice(
                        || "lhs * rhs",
                        config.advice[0],
                        1,
                        || value.ok_or(Error::Synthesis),
                    )
                    .map(Number)
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

#[derive(Clone, Default)]
pub struct MyCircuit<F: FieldExt> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];

        let instance = meta.instance_column();

        FieldChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::<F>::construct(config);

        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load a"), self.b)?;

        let c = field_chip.mul(layouter.namespace(|| "a*b"), a, b)?;

        field_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
    }

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
}

pub(in crate) fn build_verifier_params(
    sanity_check: bool,
) -> Result<
    (
        FieldCode<<G1Affine as CurveAffine>::ScalarExt>,
        PointCode<G1Affine>,
        ParamsVerifier<Bn256>,
        VerifierParams<
            (),
            <G1Affine as CurveAffine>::ScalarExt,
            <G1Affine as CurveAffine>::CurveExt,
            (),
        >,
    ),
    halo2_proofs::plonk::Error,
> {
    use crate::verify::halo2::verify::sanity_check_fn;

    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{PoseidonRead, PoseidonWrite};

    let fc = FieldCode::<<G1Affine as CurveAffine>::ScalarExt>::default();
    let pc = PointCode::<G1Affine>::default();
    let ctx = &mut ();

    let u = bn_to_field(&BigUint::from_bytes_be(
        b"2bf0d643e52e5e03edec5e060a6e2d57014425cbf7344f2846771ef22efffdfc",
    ));

    let circuit = MyCircuit::<Fp> {
        a: Some(Fp::from(1)),
        b: Some(Fp::from(1)),
    };

    const K: u32 = 5;
    let public_inputs_size = 1;

    let params: Params<G1Affine> =
        Params::<G1Affine>::unsafe_setup_rng::<Bn256, _>(K, Pcg32::seed_from_u64(42));

    let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

    let instance = Fp::one();

    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[&[instance]]],
        Pcg32::seed_from_u64(42),
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof = transcript.finalize();

    let instances: &[&[&[Fp]]] = &[&[&[instance]]];
    let mut transcript = PoseidonRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

    let params = VerifierParams::from_transcript::<Bn256, _, _, _, _>(
        &fc,
        &pc,
        ctx,
        u,
        instances,
        pk.get_vk(),
        &params_verifier,
        &mut transcript,
    )
    .unwrap();

    let strategy = SingleVerifier::new(&params_verifier);
    let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);

    if sanity_check {
        assert!(verify_proof_check(
            &params_verifier,
            pk.get_vk(),
            strategy,
            instances,
            &mut transcript,
            |queries| sanity_check_fn(&params, queries),
        )
        .is_ok());
    }

    Ok((fc, pc, params_verifier, params))
}
