use super::{lookup, permutation, vanish};
use crate::arith::api::{ContextGroup, ContextRing};
use crate::arith::code::{FieldCode, PointCode};
use crate::schema::ast::{CommitQuery, MultiOpenProof, SchemaItem, ArrayOpAdd};
use crate::schema::utils::{RingUtils, VerifySetupHelper};
use crate::schema::{EvaluationProof, EvaluationQuery, SchemaGenerator};
use crate::{arith_in_ctx, infix2postfix};
use crate::{commit, scalar};
use group::Curve;
use halo2_proofs::arithmetic::{CurveAffine, Engine, Field, FieldExt, MultiMillerLoop};
use halo2_proofs::plonk::{Expression, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{read_n_points, read_n_scalars, EncodedChallenge, TranscriptRead};
use pairing_bn256::bn256::G1Affine;
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct PlonkCommonSetup {
    // pub l: u32,
    pub n: u32,
}

pub trait Evaluable<
    C,
    S,
    Error: Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
    ) -> S;
}

impl<
        C,
        S: Field,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    > Evaluable<C, S, Error, SGate> for Expression<S>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
    ) -> S {
        match self {
            Expression::Constant(scalar) => *scalar,
            Expression::Selector(selector) => {
                panic!("virtual selectors are removed during optimization")
            }
            Expression::Fixed {
                query_index,
                column_index,
                rotation,
            } => fixed(*query_index),
            Expression::Advice {
                query_index,
                column_index,
                rotation,
            } => advice(*query_index),
            Expression::Instance {
                query_index,
                column_index,
                rotation,
            } => instance(*query_index),
            Expression::Negated(a) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let zero = &sgate.zero(ctx).unwrap();
                arith_in_ctx!([sgate, ctx] zero - a).unwrap()
            }
            Expression::Sum(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] a + b).unwrap()
            }
            Expression::Product(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] a * b).unwrap()
            }
            Expression::Scaled(a, f) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] f * a).unwrap()
            }
        }
    }
}

pub struct VerifierParams<
    C,
    S: Field,
    P: Clone,
    Error: Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
> {
    //public_wit: Vec<C::ScalarExt>,
    pub gates: Vec<Vec<Expression<S>>>,
    pub common: PlonkCommonSetup,
    pub lookup_evaluated: Vec<Vec<lookup::Evaluated<C, S, P, Error>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<C, S, P, Error>>,
    pub instance_commitments: Vec<Vec<P>>,
    pub instance_evals: Vec<Vec<S>>,
    pub instance_queries: Vec<(usize, usize)>,
    pub advice_commitments: Vec<Vec<P>>,
    pub advice_evals: Vec<Vec<S>>,
    pub advice_queries: Vec<(usize, usize)>,
    pub fixed_commitments: Vec<P>,
    pub fixed_evals: Vec<S>,
    pub fixed_queries: Vec<(usize, usize)>,
    pub permutation_commitments: Vec<P>,
    pub permutation_evals: Vec<S>, // permutations common evaluation
    pub vanish_commitments: Vec<P>,
    pub random_commitment: P,
    pub random_eval: S,
    pub beta: S,
    pub gamma: S,
    pub alpha: S,
    pub theta: S,
    pub delta: S,
    pub x: S,
    pub u: S,
    pub v: S,
    pub xi: S,
    // TODO omage: S root of z^{2^n} = 1
    pub sgate: SGate,
    pub pgate: PGate,
    pub _ctx: PhantomData<C>,
    pub _error: PhantomData<Error>,
}

impl<
        'a,
        C: Clone,
        S: Field,
        P: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, Error>,
    > VerifierParams<C, S, P, Error, SGate, PGate>
{
    fn rotate_omega(&self, at: usize) -> S {
        unimplemented!("rotate omega")
    }
    pub(in crate) fn queries(
        &'a self,
        sgate: &'a SGate,
        ctx: &'a mut C,
        y: &'a S,
        w: &'a S,
        l: u32,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let zero = &sgate.zero(ctx);
        let x = &self.x;
        let x_inv = x;  //TODO
        let x_next = x; //TODO
        let xn = x; // TODO let xn = x.pow(&[params.n as u64, 0, 0, 0]);
        let xns = sgate.pow_constant_vec(ctx, x, self.common.n)?;
        let ls = sgate.get_lagrange_commits(ctx, x, xn, w, self.common.n, l)?;
        let l_0 = &(ls[0]);
        let l_last = &ls[l as usize];
        let l_blind = &sgate.add_array(ctx, ls[1..(l as usize)].iter().collect())?;

        let pcommon = permutation::CommonEvaluated {
            permutation_evals: &self.permutation_evals,
            permutation_commitments: &self.permutation_commitments,
        };

        let mut expression = vec![];

        /* All calculation relies on ctx thus FnMut for map does not work anymore */
        for k in 0..self.advice_evals.len() {
            let advice_evals = &self.advice_evals[k];
            let instance_evals = &self.instance_evals[k];
            let permutation = &self.permutation_evaluated[k];
            let lookups = &self.lookup_evaluated[k];
            for i in 0..self.gates.len() {
                for j in 0..self.gates[i].len() {
                    let poly = &self.gates[i][j];
                    expression.push(poly.ctx_evaluate(
                        sgate,
                        ctx,
                        &|n| self.fixed_evals[n].clone(),
                        &|n| advice_evals[n].clone(),
                        &|n| instance_evals[n].clone(),
                    ));
                }
            }
            let p = permutation
                .expressions(
                    //vk,
                    //&vk.cs.permutation,
                    //&permutations_common,
                    //fixed_evals,
                    //advice_evals,
                    //instance_evals,
                    sgate,
                    ctx,
                    &pcommon,
                    l_0,
                    l_last,
                    l_blind,
                    &self.delta,
                    &self.beta,
                    &self.gamma,
                    x,
                )
                .unwrap();
            expression.extend(p);
            for i in 0..lookups.len() {
                let l = lookups[i]
                    .expressions(
                        sgate,
                        ctx,
                        &self.fixed_evals.iter().map(|ele| ele).collect(),
                        &advice_evals.iter().map(|ele| ele).collect(),
                        &instance_evals.iter().map(|ele| ele).collect(),
                        l_0,
                        l_last,
                        l_blind,
                        //argument,
                        &self.theta,
                        &self.beta,
                        &self.gamma,
                    )
                    .unwrap();
                expression.extend(l);
            }
        }

        let vanish = vanish::Evaluated::new(
            sgate,
            ctx,
            expression,
            y,
            xn,
            &self.random_commitment,
            &self.random_eval,
            self.vanish_commitments.iter().map(|ele| ele).collect(),
        );

        //vanishing.verify(expressions, y, xn)

        let queries = self
            .instance_commitments
            .iter()
            .zip(self.instance_evals.iter())
            .zip(self.advice_commitments.iter())
            .zip(self.advice_evals.iter())
            .zip(self.permutation_evaluated.iter())
            .zip(self.lookup_evaluated.iter())
            .flat_map(
                |(
                    (
                        (
                            ((instance_commitments, instance_evals), advice_commitments),
                            advice_evals,
                        ),
                        permutation,
                    ),
                    lookups,
                )| {
                    iter::empty()
                        .chain(self.instance_queries.iter().enumerate().map(
                            move |(query_index, &(column, at))| {
                                EvaluationQuery::new(
                                    self.rotate_omega(at),
                                    &instance_commitments[column],
                                    &instance_evals[query_index],
                                )
                            },
                        ))
                        .chain(self.advice_queries.iter().enumerate().map(
                            move |(query_index, &(column, at))| {
                                EvaluationQuery::new(
                                    self.rotate_omega(at),
                                    &advice_commitments[column],
                                    &advice_evals[query_index],
                                )
                            },
                        ))
                        .chain(permutation.queries()) // tested
                        .chain(
                            lookups
                                .iter()
                                .flat_map(move |p| p.queries(x, x_inv, x_next))
                                .into_iter(),
                        )
                },
            )
            .chain(
                self.fixed_queries
                    .iter()
                    .enumerate()
                    .map(|(query_index, &(column, at))| {
                        EvaluationQuery::<'a, S, P>::new(
                            self.rotate_omega(at),
                            &self.fixed_commitments[column],
                            &self.fixed_evals[query_index],
                        )
                    }),
            )
            .chain(pcommon.queries(x))
            .chain(vanish.queries(x));
        unimplemented!("get point schemas not implemented")
    }
}

impl<
        'a,
        C: Clone,
        S: Field,
        P: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, Error>,
    > SchemaGenerator<'a, C, S, P, Error> for VerifierParams<C, S, P, Error, SGate, PGate>
{
    fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        unimplemented!("get point schemas not implemented")
    }
    fn batch_multi_open_proofs(&self, ctx: &mut C) -> Result<MultiOpenProof<'a, S, P>, Error> {
        let mut proofs = self.get_point_schemas(ctx)?;
        proofs.reverse();
        let (mut w_x, mut w_g) = {
            let s = &proofs[0].s;
            let w = CommitQuery {
                c: Some(proofs[0].w),
                v: None,
            };
            (
                commit!(w),
                scalar!(proofs[0].point) * commit!(w) + s.clone(),
            )
        };
        let _ = proofs[1..].iter().map(|p| {
            let s = &p.s;
            let w = CommitQuery {
                c: Some(p.w),
                v: None,
            };
            w_x = scalar!(self.u) * w_x.clone() + commit!(w);
            w_g = scalar!(self.u) * w_g.clone() + scalar!(p.point) * commit!(w) + s.clone();
        });
        Ok(MultiOpenProof { w_x, w_g })
    }
}

impl<'a>
    VerifierParams<
        (),
        <G1Affine as CurveAffine>::ScalarExt,
        <G1Affine as CurveAffine>::CurveExt,
        (),
        FieldCode<<G1Affine as CurveAffine>::ScalarExt>,
        PointCode<G1Affine>,
    >
{
    pub fn from_transcript<
        'params,
        C: MultiMillerLoop,
        E: EncodedChallenge<C::G1Affine>,
        T: TranscriptRead<C::G1Affine, E>,
    >(
        alpha: <C::G1Affine as CurveAffine>::ScalarExt,
        u: <C::G1Affine as CurveAffine>::ScalarExt,
        v: <C::G1Affine as CurveAffine>::ScalarExt,
        xi: <C::G1Affine as CurveAffine>::ScalarExt,
        instances: &[&[&[C::Scalar]]],
        vk: &VerifyingKey<C::G1Affine>,
        params: &'params ParamsVerifier<C>,
        transcript: &mut T,
    ) -> Result<
        VerifierParams<
            (),
            <C::G1Affine as CurveAffine>::ScalarExt,
            <C::G1Affine as CurveAffine>::CurveExt,
            (),
            FieldCode<<C::G1Affine as CurveAffine>::ScalarExt>,
            PointCode<C::G1Affine>,
        >,
        halo2_proofs::plonk::Error,
    > {
        use crate::verify::halo2::permutation::Evaluated;
        use crate::verify::halo2::permutation::EvaluatedSet;
        use group::Group;
        use halo2_proofs::plonk::Error;
        use halo2_proofs::transcript::ChallengeScalar;

        let from_affine = |v: Vec<Vec<C::G1Affine>>| {
            v.iter()
                .map(|v| v.iter().map(|&affine| C::G1::from(affine)).collect())
                .collect()
        };

        let fc = FieldCode::<<C::G1Affine as CurveAffine>::ScalarExt> {
            one: <C::G1Affine as CurveAffine>::ScalarExt::one(),
            zero: <C::G1Affine as CurveAffine>::ScalarExt::zero(),
            generator: <C::G1Affine as CurveAffine>::ScalarExt::one(),
        };

        let pc = PointCode::<C::G1Affine> {
            one: <C::G1Affine as CurveAffine>::CurveExt::generator(),
            zero: <C::G1Affine as CurveAffine>::CurveExt::identity(),
            generator: <C::G1Affine as CurveAffine>::CurveExt::generator(),
        };

        for instances in instances.iter() {
            if instances.len() != vk.cs.num_instance_columns {
                return Err(Error::InvalidInstances);
            }
        }

        let instance_commitments = instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|instance| {
                        if instance.len() > params.n as usize - (vk.cs.blinding_factors() + 1) {
                            return Err(Error::InstanceTooLarge);
                        }

                        Ok(params.commit_lagrange(instance.to_vec()).to_affine())
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let num_proofs = instance_commitments.len();

        // Hash verification key into transcript
        vk.hash_into(transcript)?;

        for instance_commitments in instance_commitments.iter() {
            // Hash the instance (external) commitments into the transcript
            for commitment in instance_commitments {
                transcript.common_point(*commitment)?
            }
        }

        let advice_commitments = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                // Hash the prover's advice commitments into the transcript
                read_n_points(transcript, vk.cs.num_advice_columns)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Sample theta challenge for keeping lookup columns linearly independent
        let theta: ChallengeScalar<<C as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();

        let lookups_permuted = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                // Hash each lookup permuted commitment
                vk.cs
                    .lookups
                    .iter()
                    .map(|argument| argument.read_permuted_commitments(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Sample beta challenge
        let beta: ChallengeScalar<<C as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();

        // Sample gamma challenge
        let gamma: ChallengeScalar<<C as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();

        let permutations_committed = (0..num_proofs)
            .map(|_| {
                // Hash each permutation product commitment
                vk.cs.permutation.read_product_commitments(vk, transcript)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let lookups_committed = lookups_permuted
            .into_iter()
            .map(|lookups| {
                // Hash each lookup product commitment
                lookups
                    .into_iter()
                    .map(|lookup| lookup.read_product_commitment(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let random_poly_commitment = transcript.read_point()?;

        // Sample y challenge, which keeps the gates linearly independent.
        let _y: ChallengeScalar<<C as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();

        let h_commitments = read_n_points(transcript, vk.domain.get_quotient_poly_degree())?;
        let h_commitments: Vec<<C as Engine>::G1> = h_commitments
            .iter()
            .map(|&affine| <C as Engine>::G1::from(affine))
            .collect();

        // Sample x challenge, which is used to ensure the circuit is
        // satisfied with high probability.
        let x: ChallengeScalar<<C as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();

        // TODO PUT INTO CIRCUIT
        let x_next = vk.domain.rotate_omega(*x, Rotation::next());
        let x_last = vk
            .domain
            .rotate_omega(*x, Rotation(-((vk.cs.blinding_factors() + 1) as i32)));

        let instance_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                read_n_scalars(transcript, vk.cs.instance_queries.len())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let advice_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                read_n_scalars(transcript, vk.cs.advice_queries.len())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let fixed_evals = read_n_scalars(transcript, vk.cs.fixed_queries.len())?;

        let random_eval = transcript.read_scalar()?;

        let permutations_common = vk.permutation.evaluate(transcript)?;

        let permutations_evaluated = permutations_committed
            .into_iter()
            .map(|permutation| permutation.evaluate(transcript))
            .collect::<Result<Vec<_>, _>>()?;

        let permutations_evaluated: Vec<
            crate::verify::halo2::permutation::Evaluated<
                (),
                <C::G1Affine as CurveAffine>::ScalarExt,
                <C::G1Affine as CurveAffine>::CurveExt,
                (),
            >,
        > = permutations_evaluated
            .iter()
            .zip(advice_evals.iter())
            .zip(instance_evals.iter())
            .map(
                |((permutation_evals, advice_evals), instance_evals)| Evaluated::<
                    (),
                    <C::G1Affine as CurveAffine>::ScalarExt,
                    <C::G1Affine as CurveAffine>::CurveExt,
                    (),
                > {
                    x: *x,
                    x_next: x_next,
                    x_last: x_last,
                    sets: permutation_evals
                        .sets
                        .iter()
                        .map(|eval| EvaluatedSet::<
                            <C::G1Affine as CurveAffine>::ScalarExt,
                            <C::G1Affine as CurveAffine>::CurveExt,
                        > {
                            permutation_product_commitment: <C as Engine>::G1::from(
                                eval.permutation_product_commitment,
                            ),
                            permutation_product_eval: eval.permutation_product_eval,
                            permutation_product_next_eval: eval.permutation_product_next_eval,
                            permutation_product_last_eval: eval.permutation_product_last_eval,
                            chunk_len: vk.cs.degree() - 2,
                        })
                        .collect(),
                    _m: PhantomData,
                    evals: vk
                        .cs
                        .permutation
                        .columns
                        .chunks(vk.cs.degree() - 2)
                        .map(|columns| {
                            columns
                                .iter()
                                .map(|column| match column.column_type() {
                                    halo2_proofs::plonk::Any::Advice => {
                                        advice_evals
                                            [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                    }
                                    halo2_proofs::plonk::Any::Fixed => {
                                        fixed_evals
                                            [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                    }
                                    halo2_proofs::plonk::Any::Instance => {
                                        instance_evals
                                            [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                    }
                                })
                                .collect::<Vec<<C as Engine>::Scalar>>()
                        })
                        .collect::<Vec<Vec<<C as Engine>::Scalar>>>()
                        .concat(),
                    chunk_len: vk.cs.degree() - 2,
                },
            )
            .collect();

        let lookups_evaluated = lookups_committed
            .into_iter()
            .map(|lookups| -> Result<Vec<_>, _> {
                lookups
                    .into_iter()
                    .map(|lookup| lookup.evaluate(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let lookups_evaluated: Vec<
            Vec<
                crate::verify::halo2::lookup::Evaluated<
                    (),
                    <C::G1Affine as CurveAffine>::ScalarExt,
                    <C::G1Affine as CurveAffine>::CurveExt,
                    (),
                >,
            >,
        > = lookups_evaluated
            .into_iter()
            .map(|vec| {
                vec.into_iter()
                    .zip(vk.cs.lookups.iter())
                    .map(
                        |(lookup, argument)| crate::verify::halo2::lookup::Evaluated {
                            input_expressions: argument.input_expressions.clone(),
                            table_expressions: argument.table_expressions.clone(),
                            committed: crate::verify::halo2::lookup::Committed {
                                permuted: crate::verify::halo2::lookup::PermutationCommitments {
                                    permuted_input_commitment: <C as Engine>::G1::from(
                                        lookup.committed.permuted.permuted_input_commitment,
                                    ),
                                    permuted_table_commitment: <C as Engine>::G1::from(
                                        lookup.committed.permuted.permuted_table_commitment,
                                    ),
                                },
                                product_commitment: <C as Engine>::G1::from(
                                    lookup.committed.product_commitment,
                                ),
                            },
                            product_eval: lookup.product_eval,
                            product_next_eval: lookup.product_next_eval,
                            permuted_input_eval: lookup.permuted_input_eval,
                            permuted_input_inv_eval: lookup.permuted_input_inv_eval,
                            permuted_table_eval: lookup.permuted_table_eval,
                            _m: PhantomData,
                        },
                    )
                    .collect()
            })
            .collect();

        let fixed_commitments: Vec<<C as Engine>::G1> = vk
            .fixed_commitments
            .iter()
            .map(|&affine| <C as Engine>::G1::from(affine))
            .collect();

        Ok(VerifierParams::<
            (), // Dummy Context
            <C::G1Affine as CurveAffine>::ScalarExt,
            <C::G1Affine as CurveAffine>::CurveExt,
            (), //Error
            FieldCode<<C::G1Affine as CurveAffine>::ScalarExt>,
            PointCode<C::G1Affine>,
        > {
            gates: vk.cs.gates.iter().map(|gate| gate.polys.clone()).collect(),
            common: PlonkCommonSetup {
                n: (params.n as u32),
            },
            lookup_evaluated: lookups_evaluated,
            permutation_evaluated: permutations_evaluated,
            instance_commitments: from_affine(instance_commitments),
            instance_evals,
            instance_queries: vk
                .cs
                .instance_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as usize))
                .collect(),
            advice_commitments: from_affine(advice_commitments),
            advice_evals,
            advice_queries: vk
                .cs
                .advice_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as usize))
                .collect(),
            fixed_commitments: fixed_commitments.iter().map(|&elem| elem).collect(),
            fixed_evals,
            fixed_queries: vk
                .cs
                .fixed_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as usize))
                .collect(),
            permutation_commitments: vk
                .permutation
                .commitments
                .iter()
                .map(|commit| C::G1::from(*commit))
                .collect(),
            permutation_evals: permutations_common.permutation_evals,
            vanish_commitments: h_commitments.iter().map(|&elem| elem).collect(),
            random_commitment: <C as Engine>::G1::from(random_poly_commitment),
            random_eval,
            beta: *beta,
            gamma: *gamma,
            alpha,
            theta: *theta,
            delta: <<C::G1Affine as CurveAffine>::ScalarExt as FieldExt>::DELTA,
            x: *x,
            u,
            v,
            xi,
            sgate: fc,
            pgate: pc,
            _ctx: PhantomData,
            _error: PhantomData,
        })
    }
}
