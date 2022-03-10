use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::EvaluationQuery;

use crate::schema::ast::{CommitQuery, SchemaItem};

use crate::schema::utils::VerifySetupHelper;

use crate::{arith_in_ctx, infix2postfix};
use crate::{commit, scalar};
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct Evaluated<'a, C, S: Clone, P: Clone, Error> {
    h_commitment: SchemaItem<'a, S, P>, // calculated
    expected_h_eval: S,                 // calculated
    random_commitment: &'a P,           // from input
    random_eval: &'a S,                 // from input
    _m: PhantomData<(C, Error)>,
}

impl<'a, C, S: Clone, P: Clone, Error: Debug> Evaluated<'a, C, S, P, Error> {
    pub(in crate::verify::halo2) fn new(
        sgate: &(impl ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>),
        ctx: &'a mut C,
        expressions: Vec<S>,
        y: &'a S,
        xn: &'a S,
        random_commitment: &'a P,
        random_eval: &'a S,
        expect_commitments: Vec<&'a P>,
    ) -> Evaluated<'a, C, S, P, Error> {
        let one = &sgate.one(ctx).unwrap();
        let zero = &sgate.zero(ctx).unwrap();
        let expected_h_eval = &sgate.mult_and_add(ctx, expressions.iter(), y);
        let expected_h_eval = arith_in_ctx!([sgate, ctx] expected_h_eval / (xn - one)).unwrap();

        let h_commitment =
            expect_commitments
                .iter()
                .rev()
                .fold(scalar!(zero), |acc, commitment| {
                    let c = CommitQuery {
                        c: Some(commitment.clone()),
                        v: None,
                    };
                    scalar!(xn) * acc + commit!(c)
                });
        Evaluated {
            h_commitment,
            expected_h_eval,
            random_eval: random_eval,
            random_commitment: random_commitment,
            _m: PhantomData,
        }
    }

    pub(in crate::verify::halo2) fn queries(
        &'a self,
        x: &'a S,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        iter::empty()
            .chain(Some(EvaluationQuery::new_from_query(
                x.clone(),
                self.h_commitment.clone() + scalar!(&self.expected_h_eval),
            )))
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                self.random_commitment,
                self.random_eval,
            )))
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner};
    use halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error,
        Instance, Selector,
    };
    // use halo2_proofs::poly::commitment::{Guard, MSM};
    use crate::verify::halo2::verify::VerifierParams;
    use halo2_proofs::poly::Rotation;
    use halo2_proofs::transcript::Challenge255;
    use pairing_bn256::bn256::{Bn256, G1Affine};
    use rand_core::OsRng;

    #[derive(Clone, Debug)]
    struct FieldConfig {
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
        fn load_private(
            &self,
            layouter: impl Layouter<F>,
            a: Option<F>,
        ) -> Result<Self::Num, Error>;

        /// Loads a number into the circuit as a fixed constant.
        fn load_constant(
            &self,
            layouter: impl Layouter<F>,
            constant: F,
        ) -> Result<Self::Num, Error>;

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
                        .assign_advice_from_constant(
                            || "constant value",
                            config.advice[0],
                            0,
                            constant,
                        )
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
    struct MyCircuit<F: FieldExt> {
        a: Option<F>,
        b: Option<F>,
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

    #[test]
    fn test_queries() {
        use halo2_proofs::poly::commitment::Params;
        use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite};
        use pairing_bn256::bn256::Fr as Fp;

        let circuit = MyCircuit::<Fp> {
            a: Some(Fp::from(1)),
            b: Some(Fp::from(1)),
        };

        const K: u32 = 5;

        let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(K);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let instance = Fp::one() + Fp::one();
        create_proof(
            &params,
            &pk,
            &[circuit.clone(), circuit.clone()],
            &[&[&[instance]], &[&[instance]]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");

        let proof = transcript.finalize();

        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

        let _params =
            VerifierParams::from_transcript::<Bn256, _, _>(pk.get_vk(), &mut transcript).unwrap();
        ()
    }
}
