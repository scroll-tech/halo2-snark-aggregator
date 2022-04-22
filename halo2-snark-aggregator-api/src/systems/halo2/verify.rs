use super::evaluation::EvaluationQuerySchema;
use super::multiopen::MultiOpenProof;
use super::params::{PlonkCommonSetup, VerifierParams};
use super::{
    lookup::{self, PermutationCommitments},
    permutation,
};
use crate::arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip};
use crate::scalar;
use crate::transcript::read::TranscriptRead;
use group::Curve;
use group::Group;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::arithmetic::{Field, MillerLoopResult};
use halo2_proofs::{arithmetic::BaseExt, poly::Rotation};
use halo2_proofs::{
    arithmetic::{CurveAffine, MultiMillerLoop},
    plonk::{Expression, VerifyingKey},
    poly::commitment::ParamsVerifier,
};
use std::marker::PhantomData;
use std::vec;
pub struct VerifierParamsBuilder<
    'a,
    E: MultiMillerLoop,
    A: ArithEccChip<Point = E::G1Affine>,
    T: TranscriptRead<A>,
> {
    ctx: &'a mut A::Context,
    nchip: &'a A::NativeChip,
    schip: &'a A::ScalarChip,
    pchip: &'a A,
    instances: &'a [&'a [&'a [E::Scalar]]],
    vk: &'a VerifyingKey<E::G1Affine>,
    params: &'a ParamsVerifier<E>,
    transcript: &'a mut T,
    key: String,
}

// Follow the sequence of official halo2
impl<
        'a,
        E: MultiMillerLoop,
        A: ArithEccChip<
            Point = E::G1Affine,
            Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
            Native = <E::G1Affine as CurveAffine>::ScalarExt,
        >,
        T: TranscriptRead<A>,
    > VerifierParamsBuilder<'a, E, A, T>
{
    fn init_transcript(&mut self) -> Result<(), A::Error> {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", self.vk.pinned());

        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());
        let assigned_scalar = self.schip.assign_const(self.ctx, scalar)?;
        self.transcript
            .common_scalar(self.ctx, self.nchip, self.schip, &assigned_scalar)?;
        Ok(())
    }

    fn build_instance_commitment(&mut self) -> Result<Vec<Vec<A::AssignedPoint>>, A::Error> {
        for instances in self.instances.iter() {
            assert!(instances.len() == self.vk.cs.num_instance_columns)
        }

        self.instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|instance| {
                        assert!(
                            instance.len()
                                <= self.params.n as usize - (self.vk.cs.blinding_factors() + 1)
                        );
                        let p = self.params.commit_lagrange(instance.to_vec()).to_affine();
                        let p = self.pchip.assign_var(self.ctx, p)?;
                        self.transcript
                            .common_point(self.ctx, self.nchip, self.schip, self.pchip, &p)?;
                        Ok(p)
                    })
                    .collect::<Result<Vec<A::AssignedPoint>, A::Error>>()
            })
            .collect::<Result<Vec<Vec<A::AssignedPoint>>, A::Error>>()
    }

    fn load_point(&mut self) -> Result<A::AssignedPoint, A::Error> {
        self.transcript
            .read_point(self.ctx, self.nchip, self.schip, self.pchip)
    }

    fn load_n_points(&mut self, n: usize) -> Result<Vec<A::AssignedPoint>, A::Error> {
        let mut ret = vec![];
        for _ in 0..n {
            let p = self.load_point()?;
            ret.push(p);
        }
        Ok(ret)
    }

    fn load_n_m_points(
        &mut self,
        n: usize,
        m: usize,
    ) -> Result<Vec<Vec<A::AssignedPoint>>, A::Error> {
        let mut ret = vec![];
        for _ in 0..n {
            let p = self.load_n_points(m)?;
            ret.push(p);
        }
        Ok(ret)
    }

    fn load_scalar(&mut self) -> Result<A::AssignedScalar, A::Error> {
        self.transcript
            .read_scalar(self.ctx, self.nchip, self.schip)
    }

    fn load_n_scalars(&mut self, n: usize) -> Result<Vec<A::AssignedScalar>, A::Error> {
        let mut ret = vec![];
        for _ in 0..n {
            let p = self.load_scalar()?;
            ret.push(p);
        }
        Ok(ret)
    }

    fn load_n_m_scalars(
        &mut self,
        n: usize,
        m: usize,
    ) -> Result<Vec<Vec<A::AssignedScalar>>, A::Error> {
        let mut ret = vec![];
        for _ in 0..n {
            let p = self.load_n_scalars(m)?;
            ret.push(p);
        }
        Ok(ret)
    }

    fn squeeze_challenge_scalar(&mut self) -> Result<A::AssignedScalar, A::Error> {
        self.transcript
            .squeeze_challenge_scalar(self.ctx, self.nchip, self.schip)
    }

    fn rotate_omega(
        &mut self,
        x: &A::AssignedScalar,
        omega: A::Scalar,
        at: i32,
    ) -> Result<A::AssignedScalar, A::Error> {
        let (base, exp) = if at < 0 {
            (omega.invert().unwrap(), [(-at) as u64, 0, 0, 0])
        } else {
            (omega, [at as u64, 0, 0, 0])
        };
        let omega_at = base.pow_vartime(exp);
        self.schip
            .sum_with_coeff_and_constant(self.ctx, vec![(x, omega_at)], A::Scalar::zero())
    }

    fn convert_expression(
        &mut self,
        expr: Expression<A::Scalar>,
    ) -> Result<Expression<A::AssignedScalar>, A::Error> {
        Ok(match expr {
            Expression::Constant(c) => Expression::Constant(self.schip.assign_const(self.ctx, c)?),
            Expression::Selector(s) => Expression::Selector(s),
            Expression::Fixed {
                query_index,
                column_index,
                rotation,
            } => Expression::Fixed {
                query_index,
                column_index,
                rotation,
            },
            Expression::Advice {
                query_index,
                column_index,
                rotation,
            } => Expression::Advice {
                query_index,
                column_index,
                rotation,
            },
            Expression::Instance {
                query_index,
                column_index,
                rotation,
            } => Expression::Instance {
                query_index,
                column_index,
                rotation,
            },
            Expression::Negated(b) => Expression::Negated(
                Box::<Expression<A::AssignedScalar>>::new(self.convert_expression(*b)?),
            ),
            Expression::Sum(b1, b2) => Expression::Sum(
                Box::<Expression<A::AssignedScalar>>::new(self.convert_expression(*b1)?),
                Box::<Expression<A::AssignedScalar>>::new(self.convert_expression(*b2)?),
            ),
            Expression::Product(b1, b2) => Expression::Product(
                Box::<Expression<A::AssignedScalar>>::new(self.convert_expression(*b1)?),
                Box::<Expression<A::AssignedScalar>>::new(self.convert_expression(*b2)?),
            ),
            Expression::Scaled(b, f) => Expression::Scaled(
                Box::<Expression<A::AssignedScalar>>::new(self.convert_expression(*b)?),
                self.schip.assign_const(self.ctx, f)?,
            ),
        })
    }

    fn build_permutation_evaluated(
        &mut self,
        x: &<A as ArithEccChip>::AssignedScalar,
        permutations_committed: Vec<Vec<<A as ArithEccChip>::AssignedPoint>>,
        advice_evals: &Vec<Vec<<A as ArithEccChip>::AssignedScalar>>,
        instance_evals: &Vec<Vec<<A as ArithEccChip>::AssignedScalar>>,
        fixed_evals: &Vec<<A as ArithEccChip>::AssignedScalar>,
    ) -> Result<Vec<permutation::Evaluated<A>>, A::Error> {
        let permutation_evaluated_sets = permutations_committed
            .into_iter()
            .map(|permutation| {
                let mut sets = vec![];

                let mut iter = permutation.into_iter();
                while let Some(permutation_product_commitment) = iter.next() {
                    let permutation_product_eval = self.load_scalar()?;
                    let permutation_product_next_eval = self.load_scalar()?;
                    let permutation_product_last_eval = if iter.len() > 0 {
                        Some(self.load_scalar()?)
                    } else {
                        None
                    };

                    sets.push(permutation::EvaluatedSet {
                        permutation_product_commitment,
                        permutation_product_eval,
                        permutation_product_next_eval,
                        permutation_product_last_eval,
                    });
                }

                Ok(sets)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let permutation_evaluated_evals: Vec<Vec<<A as ArithEccChip>::AssignedScalar>> =
            advice_evals
                .iter()
                .zip(instance_evals.iter())
                .map(|(advice_evals, instance_evals)| {
                    self.vk
                        .cs
                        .permutation
                        .columns
                        .chunks(self.vk.cs.degree() - 2)
                        .map(|columns| {
                            columns
                                .iter()
                                .map(|column| match column.column_type() {
                                    halo2_proofs::plonk::Any::Advice => advice_evals
                                        [self.vk.cs.get_any_query_index(*column, Rotation::cur())]
                                    .clone(),
                                    halo2_proofs::plonk::Any::Fixed => fixed_evals
                                        [self.vk.cs.get_any_query_index(*column, Rotation::cur())]
                                    .clone(),
                                    halo2_proofs::plonk::Any::Instance => instance_evals
                                        [self.vk.cs.get_any_query_index(*column, Rotation::cur())]
                                    .clone(),
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                        .concat()
                })
                .collect::<Vec<_>>();

        let permutation_evaluated = permutation_evaluated_sets
            .into_iter()
            .zip(permutation_evaluated_evals.into_iter())
            .map(
                |(permutation_evaluated_set, permutation_evaluated_eval)| permutation::Evaluated {
                    x: x.clone(),
                    sets: permutation_evaluated_set,
                    evals: permutation_evaluated_eval,
                    chunk_len: self.vk.cs.degree() - 2,
                    key: self.key.clone(),
                },
            )
            .collect();

        Ok(permutation_evaluated)
    }

    fn build_lookup_evaluated(
        &mut self,
        lookups_permuted: Vec<Vec<PermutationCommitments<<A as ArithEccChip>::AssignedPoint>>>,
        lookups_committed: Vec<Vec<<A as ArithEccChip>::AssignedPoint>>,
    ) -> Result<Vec<Vec<lookup::Evaluated<A>>>, A::Error> {
        let lookup_evaluated = lookups_permuted
            .into_iter()
            .zip(lookups_committed.into_iter())
            .map(|(permuted, product_commitment)| {
                permuted
                    .into_iter()
                    .zip(product_commitment.into_iter())
                    .zip(self.vk.cs.lookups.iter())
                    .map(|((permuted, product_commitment), argument)| {
                        let product_eval = self.load_scalar()?;
                        let product_next_eval = self.load_scalar()?;
                        let permuted_input_eval = self.load_scalar()?;
                        let permuted_input_inv_eval = self.load_scalar()?;
                        let permuted_table_eval = self.load_scalar()?;
                        Ok(lookup::Evaluated {
                            input_expressions: argument
                                .input_expressions
                                .iter()
                                .map(|expr| self.convert_expression(expr.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                            table_expressions: argument
                                .table_expressions
                                .iter()
                                .map(|expr| self.convert_expression(expr.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                            committed: lookup::Committed {
                                permuted,
                                product_commitment,
                            },
                            product_eval,
                            product_next_eval,
                            permuted_input_eval,
                            permuted_input_inv_eval,
                            permuted_table_eval,
                            key: self.key.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(lookup_evaluated)
    }

    pub fn build_params(mut self) -> Result<VerifierParams<A>, A::Error> {
        self.init_transcript()?;

        let instance_commitments = self.build_instance_commitment()?;

        let num_proofs = instance_commitments.len();

        let advice_commitments = self.load_n_m_points(num_proofs, self.vk.cs.num_advice_columns)?;

        let theta = self.squeeze_challenge_scalar()?;

        let lookups_permuted = (0..num_proofs)
            .map(|_| {
                (0..self.vk.cs.lookups.len())
                    .map(|_| {
                        let permuted_input_commitment = self.load_point()?;
                        let permuted_table_commitment = self.load_point()?;

                        Ok(PermutationCommitments {
                            permuted_input_commitment,
                            permuted_table_commitment,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<Vec<_>>, _>>()?;

        let beta = self.squeeze_challenge_scalar()?;
        let gamma = self.squeeze_challenge_scalar()?;

        let permutations_committed = self.load_n_m_points(
            num_proofs,
            self.vk
                .cs
                .permutation
                .columns
                .chunks(self.vk.cs.degree() - 2)
                .len(),
        )?;

        let lookups_committed = lookups_permuted
            .iter()
            .map(|lookups| {
                // Hash each lookup product commitment
                lookups
                    .into_iter()
                    .map(|_| self.load_point())
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let random_commitment = self.load_point()?;

        let y = self.squeeze_challenge_scalar()?;
        let h_commitments = self.load_n_points(self.vk.domain.get_quotient_poly_degree())?;
        let l = self.vk.cs.blinding_factors() as u32 + 1;
        let n = self.params.n as u32;
        let omega = self.vk.domain.get_omega();

        let x = self.squeeze_challenge_scalar()?;
        let x_next = self.rotate_omega(&x, omega, 1)?;
        let x_last = self.rotate_omega(&x, omega, -(l as i32))?;
        let x_inv = self.rotate_omega(&x, omega, -1)?;
        let xn = self.schip.pow_constant(self.ctx, &x, n)?;

        let instance_evals =
            self.load_n_m_scalars(num_proofs, self.vk.cs.instance_queries.len())?;
        let advice_evals = self.load_n_m_scalars(num_proofs, self.vk.cs.advice_queries.len())?;
        let fixed_evals = self.load_n_scalars(self.vk.cs.fixed_queries.len())?;

        let random_eval = self.load_scalar()?;

        let permutation_evals = self.load_n_scalars(self.vk.permutation.commitments.len())?;
        let permutation_evaluated = self.build_permutation_evaluated(
            &x,
            permutations_committed,
            &advice_evals,
            &instance_evals,
            &fixed_evals,
        )?;

        let lookup_evaluated = self.build_lookup_evaluated(lookups_permuted, lookups_committed)?;

        let fixed_commitments = self
            .vk
            .fixed_commitments
            .iter()
            .map(|&affine| self.pchip.assign_var(self.ctx, affine))
            .collect::<Result<Vec<_>, _>>()?;

        let v = self.squeeze_challenge_scalar()?;
        let u = self.squeeze_challenge_scalar()?;

        let mut w = vec![];
        while let Ok(p) = self.load_point() {
            w.push(p);
        }

        Ok(VerifierParams {
            key: self.key.clone(),
            gates: self
                .vk
                .cs
                .gates
                .iter()
                .map(|gate| {
                    gate.polys
                        .iter()
                        .map(|expr| self.convert_expression(expr.clone()))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()?,
            common: PlonkCommonSetup { l, n },
            lookup_evaluated,
            permutation_evaluated,
            instance_commitments,
            instance_evals,
            instance_queries: self
                .vk
                .cs
                .instance_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            advice_commitments,
            advice_evals,
            advice_queries: self
                .vk
                .cs
                .advice_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            fixed_commitments,
            fixed_evals,
            fixed_queries: self
                .vk
                .cs
                .fixed_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            permutation_commitments: self
                .vk
                .permutation
                .commitments
                .iter()
                .map(|commit| self.pchip.assign_var(self.ctx, *commit))
                .collect::<Result<Vec<_>, _>>()?,
            permutation_evals,
            vanish_commitments: h_commitments,
            random_commitment,
            random_eval,
            beta,
            gamma,
            theta,
            delta: self.schip.assign_const(
                self.ctx,
                <<E::G1Affine as CurveAffine>::ScalarExt as FieldExt>::DELTA,
            )?,
            x,
            x_next,
            x_last,
            x_inv,
            xn,
            y,
            u,
            v,
            omega: self
                .schip
                .assign_const(self.ctx, self.vk.domain.get_omega())?,
            w,
            zero: self
                .schip
                .assign_const(self.ctx, <E::G1Affine as CurveAffine>::ScalarExt::zero())?,
            one: self
                .schip
                .assign_const(self.ctx, <E::G1Affine as CurveAffine>::ScalarExt::one())?,
            n: self.schip.assign_const(
                self.ctx,
                <E::G1Affine as CurveAffine>::ScalarExt::from(n as u64),
            )?,
        })
    }
}

pub fn verify_single_proof_no_eval<
    E: MultiMillerLoop,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
    T: TranscriptRead<A>,
>(
    ctx: &mut A::Context,
    nchip: &A::NativeChip,
    schip: &A::ScalarChip,
    pchip: &A,
    instances: &[&[&[E::Scalar]]],
    vk: &VerifyingKey<E::G1Affine>,
    params: &ParamsVerifier<E>,
    transcript: &mut T,
    key: String,
) -> Result<MultiOpenProof<A>, A::Error> {
    let params_builder = VerifierParamsBuilder {
        ctx,
        nchip,
        schip,
        pchip,
        instances,
        vk,
        params,
        transcript,
        key,
    };

    let chip_params = params_builder.build_params()?;
    chip_params.batch_multi_open_proofs(ctx, schip)
}

fn evaluate_multiopen_proof<
    E: MultiMillerLoop,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
    T: TranscriptRead<A>,
>(
    ctx: &mut A::Context,
    schip: &A::ScalarChip,
    pchip: &A,
    proof: MultiOpenProof<A>,
    params: &ParamsVerifier<E>,
) -> Result<(E::G1Affine, E::G1Affine), A::Error> {
    let one = schip.assign_one(ctx)?;

    let (left_s, left_e) = proof.w_x.eval::<_, A>(ctx, schip, pchip, &one)?;
    let (right_s, right_e) = proof.w_g.eval::<_, A>(ctx, schip, pchip, &one)?;

    let generator = pchip.assign_one(ctx)?;
    let left = match left_e {
        None => left_s,
        Some(eval) => {
            let s = pchip.scalar_mul(ctx, &eval, &generator)?;
            pchip.add(ctx, &left_s, &s)?
        }
    };
    let right = match right_e {
        None => right_s,
        Some(eval) => {
            let s = pchip.scalar_mul(ctx, &eval, &generator)?;
            pchip.sub(ctx, &right_s, &s)?
        }
    };

    let left = pchip.to_value(&left)?;
    let right = pchip.to_value(&right)?;

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    let success = bool::from(
        E::multi_miller_loop(&[(&left, &s_g2_prepared), (&right, &n_g2_prepared)])
            .final_exponentiation()
            .is_identity(),
    );
    assert!(success);

    Ok((left, right))
}

pub fn verify_single_proof_in_chip<
    E: MultiMillerLoop,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
    T: TranscriptRead<A>,
>(
    ctx: &mut A::Context,
    nchip: &A::NativeChip,
    schip: &A::ScalarChip,
    pchip: &A,
    instances: &[&[&[E::Scalar]]],
    vk: &VerifyingKey<E::G1Affine>,
    params: &ParamsVerifier<E>,
    transcript: &mut T,
) -> Result<(E::G1Affine, E::G1Affine), A::Error> {
    let proof = verify_single_proof_no_eval(
        ctx, nchip, schip, pchip, instances, vk, params, transcript, "".to_owned(),
    )?;
    evaluate_multiopen_proof::<E, A, T>(ctx, schip, pchip, proof, params)
}

pub struct ProofData<
    'a,
    E: MultiMillerLoop,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
    T: TranscriptRead<A>,
> {
    pub instances: &'a Vec<Vec<Vec<E::Scalar>>>,
    pub transcript: T,
    pub key: String,
    pub _phantom: PhantomData<A>,
}

pub fn verify_aggregation_proofs_in_chip<
    E: MultiMillerLoop,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
    T: TranscriptRead<A>,
>(
    ctx: &mut A::Context,
    nchip: &A::NativeChip,
    schip: &A::ScalarChip,
    pchip: &A,
    vk: &VerifyingKey<E::G1Affine>,
    params: &ParamsVerifier<E>,
    mut proofs: Vec<ProofData<E, A, T>>,
    transcript: &mut T,
) -> Result<(E::G1Affine, E::G1Affine), A::Error> {
    let multiopen_proofs: Vec<MultiOpenProof<A>> = proofs
        .iter_mut()
        .map(|proof| {
            let instances1: Vec<Vec<&[E::Scalar]>> = proof
                .instances
                .iter()
                .map(|x| x.iter().map(|y| &y[..]).collect())
                .collect();
            let instances2: Vec<&[&[E::Scalar]]> = instances1.iter().map(|x| &x[..]).collect();

            verify_single_proof_no_eval(
                ctx,
                nchip,
                schip,
                pchip,
                &instances2[..],
                vk,
                params,
                &mut proof.transcript,
                proof.key.clone(),
            )
        })
        .collect::<Result<_, A::Error>>()?;

    for proof in proofs.iter_mut() {
        let scalar = proof
            .transcript
            .squeeze_challenge_scalar(ctx, nchip, schip)?;
        transcript.common_scalar(ctx, nchip, schip, &scalar)?;
    }

    let aggregation_challenge = transcript.squeeze_challenge_scalar(ctx, nchip, schip)?;

    let mut acc: Option<MultiOpenProof<A>> = None;
    for proof in multiopen_proofs.into_iter() {
        acc = match acc {
            None => Some(proof),
            Some(acc) => Some(MultiOpenProof {
                w_x: acc.w_x * scalar!(aggregation_challenge) + proof.w_x,
                w_g: acc.w_g * scalar!(aggregation_challenge) + proof.w_g,
            }),
        }
    }
    let aggregated_proof = acc.unwrap();

    evaluate_multiopen_proof::<E, A, T>(ctx, schip, pchip, aggregated_proof, params)
}
