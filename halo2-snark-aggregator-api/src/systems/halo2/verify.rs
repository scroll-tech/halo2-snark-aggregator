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
use group::prime::PrimeCurveAffine;
use halo2_proofs::arithmetic::{Field, FieldExt};
use halo2_proofs::halo2curves::pairing::MultiMillerLoop;
use halo2_proofs::poly::kzg::commitment::ParamsVerifierKZG;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::CurveAffine,
    plonk::{Expression, VerifyingKey},
    poly::commitment::Params,
};
use std::fmt::Debug;
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
    assigned_instances: Vec<Vec<A::AssignedPoint>>,
    vk: &'a VerifyingKey<E::G1Affine>,
    params: &'a ParamsVerifierKZG<E>,
    transcript: &'a mut T,
    key: String,
}

// Follow the sequence of official halo2
impl<
        'a,
        E: MultiMillerLoop + Debug,
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

    fn squeeze_instance_commitment(&mut self) -> Result<(), A::Error> {
        let _: Vec<Vec<Result<(), A::Error>>> = self
            .assigned_instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|p| {
                        self.transcript
                            .common_point(self.ctx, self.nchip, self.schip, self.pchip, &p)?;

                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok(())
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
            Expression::Fixed(fixed_query) => Expression::Fixed(fixed_query),
            Expression::Advice(advice_query) => Expression::Advice(advice_query),
            Expression::Instance(instance_query) => Expression::Instance(instance_query),
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
                        .cs()
                        .permutation
                        .columns
                        .chunks(self.vk.cs().degree() - 2)
                        .map(|columns| {
                            columns
                                .iter()
                                .map(|column| match column.column_type() {
                                    halo2_proofs::plonk::Any::Advice => advice_evals[self
                                        .vk
                                        .cs()
                                        .get_any_query_index(*column, Rotation::cur())]
                                    .clone(),
                                    halo2_proofs::plonk::Any::Fixed => fixed_evals[self
                                        .vk
                                        .cs()
                                        .get_any_query_index(*column, Rotation::cur())]
                                    .clone(),
                                    halo2_proofs::plonk::Any::Instance => instance_evals[self
                                        .vk
                                        .cs()
                                        .get_any_query_index(*column, Rotation::cur())]
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
            .enumerate()
            .map(
                |(i, (permutation_evaluated_set, permutation_evaluated_eval))| {
                    permutation::Evaluated {
                        x: x.clone(),
                        blinding_factors: self.vk.cs().blinding_factors(),
                        sets: permutation_evaluated_set,
                        evals: permutation_evaluated_eval,
                        chunk_len: self.vk.cs().degree() - 2,
                        key: format!("{}_{}", self.key.clone(), i),
                    }
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
            .enumerate()
            .map(|(i, (permuted, product_commitment))| {
                permuted
                    .into_iter()
                    .zip(product_commitment.into_iter())
                    .zip(self.vk.cs().lookups.iter())
                    .enumerate()
                    .map(|(j, ((permuted, product_commitment), argument))| {
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
                            key: format!("{}_{}_{}", self.key.clone(), i, j),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(lookup_evaluated)
    }

    pub fn build_params(mut self) -> Result<VerifierParams<A>, A::Error> {
        self.init_transcript()?;

        self.squeeze_instance_commitment()?;
        let instance_commitments = &self.assigned_instances;

        let num_proofs = instance_commitments.len();

        let advice_commitments =
            self.load_n_m_points(num_proofs, self.vk.cs().num_advice_columns)?;

        let theta = self.squeeze_challenge_scalar()?;

        let lookups_permuted = (0..num_proofs)
            .map(|_| {
                (0..self.vk.cs().lookups.len())
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
                .cs()
                .permutation
                .columns
                .chunks(self.vk.cs().degree() - 2)
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
        let h_commitments = self.load_n_points(self.vk.domain_ref().get_quotient_poly_degree())?;
        let l = self.vk.cs().blinding_factors() as u32 + 1;
        let n = self.params.n() as u32;
        let omega = self.vk.domain_ref().get_omega();

        let x = self.squeeze_challenge_scalar()?;

        let instance_evals =
            self.load_n_m_scalars(num_proofs, self.vk.cs().instance_queries.len())?;
        let advice_evals = self.load_n_m_scalars(num_proofs, self.vk.cs().advice_queries.len())?;
        let fixed_evals = self.load_n_scalars(self.vk.cs().fixed_queries.len())?;

        let random_eval = self.load_scalar()?;

        let permutation_evals = self.load_n_scalars(self.vk.permutation().commitments.len())?;
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
            .fixed_commitments()
            .iter()
            .map(|&affine| self.pchip.assign_const(self.ctx, affine))
            .collect::<Result<Vec<_>, _>>()?;

        let v = self.squeeze_challenge_scalar()?;
        let u = self.squeeze_challenge_scalar()?;

        let mut w = vec![];
        while let Ok(p) = self.load_point() {
            w.push(p);
        }

        let x_next = self.rotate_omega(&x, omega, 1)?;
        let x_last = self.rotate_omega(&x, omega, -(l as i32))?;
        let x_inv = self.rotate_omega(&x, omega, -1)?;
        let xn = self.schip.pow_constant(self.ctx, &x, n)?;

        Ok(VerifierParams {
            key: self.key.clone(),
            gates: self
                .vk
                .cs()
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
            instance_commitments: self.assigned_instances,
            instance_evals,
            instance_queries: self
                .vk
                .cs()
                .instance_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            advice_commitments,
            advice_evals,
            advice_queries: self
                .vk
                .cs()
                .advice_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            fixed_commitments,
            fixed_evals,
            fixed_queries: self
                .vk
                .cs()
                .fixed_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            permutation_commitments: self
                .vk
                .permutation()
                .commitments
                .iter()
                .map(|commit| self.pchip.assign_const(self.ctx, *commit))
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
                .assign_const(self.ctx, self.vk.domain_ref().get_omega())?,
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

pub fn assign_instance_commitment<
    E: MultiMillerLoop + Debug,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
>(
    ctx: &mut A::Context,
    schip: &A::ScalarChip,
    pchip: &A,
    instances: &[&[&[E::Scalar]]],
    vk: &VerifyingKey<E::G1Affine>,
    params: &ParamsVerifierKZG<E>,
) -> Result<(Vec<A::AssignedScalar>, Vec<Vec<A::AssignedPoint>>), A::Error> {
    let mut plain_assigned_instances = vec![];

    for instances in instances.iter() {
        assert!(instances.len() == vk.cs().num_instance_columns)
    }

    let instances = instances
        .iter()
        .map(|instance| {
            instance
                .iter()
                .map(|instance| {
                    assert!(
                        instance.len() <= params.n() as usize - (vk.cs().blinding_factors() + 1)
                    );

                    let mut assigned_scalars = vec![];
                    for instance in instance.iter() {
                        let s = schip.assign_var(ctx, instance.clone())?;
                        assigned_scalars.push(s.clone());
                        plain_assigned_instances.push(s);
                    }
                    Ok(assigned_scalars)
                })
                .collect::<Result<Vec<_>, A::Error>>()
        })
        .collect::<Result<Vec<Vec<_>>, A::Error>>()?;

    let commitments = instances
        .iter()
        .map(|instance| {
            instance
                .iter()
                .map(|instance| {
                    let mut acc = None;

                    for (i, instance) in instance.iter().enumerate() {
                        let ls = pchip.scalar_mul_constant(
                            ctx,
                            &instance,
                            params.g_lagrange_ref()[i].clone(),
                        )?;

                        match acc {
                            None => acc = Some(ls),
                            Some(acc_) => {
                                let acc_ = pchip.add(ctx, &acc_, &ls)?;
                                acc = Some(acc_);
                            }
                        }
                    }

                    let c = match acc {
                        None => pchip.assign_const(ctx, E::G1Affine::identity()),
                        Some(acc) => pchip.normalize(ctx, &acc),
                    }?;

                    Ok(c)
                })
                .collect::<Result<Vec<_>, A::Error>>()
        })
        .collect::<Result<Vec<Vec<_>>, A::Error>>()?;

    Ok((plain_assigned_instances, commitments))
}

pub fn verify_single_proof_no_eval<
    E: MultiMillerLoop + Debug,
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
    assigned_instances: Vec<Vec<A::AssignedPoint>>,
    vk: &VerifyingKey<E::G1Affine>,
    params: &ParamsVerifierKZG<E>,
    transcript: &mut T,
    key: String,
) -> Result<(MultiOpenProof<A>, Vec<<A as ArithEccChip>::AssignedPoint>), A::Error> {
    let params_builder = VerifierParamsBuilder {
        ctx,
        nchip,
        schip,
        pchip,
        assigned_instances,
        vk,
        params,
        transcript,
        key,
    };

    let chip_params = params_builder.build_params()?;
    let advice_commitments = chip_params.advice_commitments.clone();
    Ok((
        chip_params.batch_multi_open_proofs(ctx, schip)?,
        advice_commitments[0].clone(),
    ))
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
    //params: &ParamsVerifier<E>,  only for debugging purpose
) -> Result<(A::AssignedPoint, A::AssignedPoint), A::Error> {
    let one = schip.assign_one(ctx)?;

    // do not print ctx anymore! our ctx contains constants_to_assign and lookup_cells, very long
    // println!("debug context before evaluate multiopen proof: {}", ctx);

    // println!("w_x.eval");
    let (left_s, left_e) = proof.w_x.eval::<_, A>(ctx, schip, pchip, &one)?;
    // println!("w_g.eval");
    let (right_s, right_e) = proof.w_g.eval::<_, A>(ctx, schip, pchip, &one)?;
    // println!("right_s: {:#?}", right_s);
    // println!("right_e: {:#?}", right_e);

    let left = match left_e {
        None => left_s,
        Some(eval) => {
            let s = pchip.scalar_mul_constant(ctx, &eval, E::G1Affine::generator())?;
            pchip.add(ctx, &left_s, &s)?
        }
    };
    let right = match right_e {
        None => right_s,
        Some(eval) => {
            let s = pchip.scalar_mul_constant(ctx, &eval, E::G1Affine::generator())?;
            pchip.sub(ctx, &right_s, &s)?
        }
    };

    /* FIXME: only for debugging purpose

    let left_v = pchip.to_value(&left)?;
    let right_v = pchip.to_value(&right)?;

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    let success = bool::from(
        E::multi_miller_loop(&[(&left_v, &s_g2_prepared), (&right_v, &n_g2_prepared)])
            .final_exponentiation()
            .is_identity(),
    );
    assert!(success);

    */
    // println!("debug context after evaluate multiopen proof: {}", ctx);

    Ok((left, right))
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

pub struct CircuitProof<
    'a,
    E: MultiMillerLoop,
    A: ArithEccChip<
        Point = E::G1Affine,
        Scalar = <E::G1Affine as CurveAffine>::ScalarExt,
        Native = <E::G1Affine as CurveAffine>::ScalarExt,
    >,
    T: TranscriptRead<A>,
> {
    pub name: String,
    pub vk: &'a VerifyingKey<E::G1Affine>,
    pub params: &'a ParamsVerifierKZG<E>,
    pub proofs: Vec<ProofData<'a, E, A, T>>,
}

pub fn verify_single_proof_in_chip<
    E: MultiMillerLoop + Debug,
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
    circuit: &mut CircuitProof<E, A, T>,
    transcript: &mut T,
) -> Result<
    (
        A::AssignedPoint,       // w_x
        A::AssignedPoint,       // w_g
        Vec<A::AssignedScalar>, // plain assigned instance
        Vec<A::AssignedPoint>,  // advice commitments
    ),
    A::Error,
> {
    let instances1: Vec<Vec<&[E::Scalar]>> = circuit.proofs[0]
        .instances
        .iter()
        .map(|x| x.iter().map(|y| &y[..]).collect())
        .collect();
    let instances2: Vec<&[&[E::Scalar]]> = instances1.iter().map(|x| &x[..]).collect();
    let (plain_assigned_instances, assigned_instances_commitment) = assign_instance_commitment(
        ctx,
        schip,
        pchip,
        &instances2[..],
        circuit.vk,
        circuit.params,
    )?;

    let (proof, advice_commitments) = verify_single_proof_no_eval(
        ctx,
        nchip,
        schip,
        pchip,
        assigned_instances_commitment,
        circuit.vk,
        circuit.params,
        transcript,
        "".to_owned(),
    )?;

    println!("get single proof {}", circuit.name);
    let (w_x, w_g) =
        evaluate_multiopen_proof::<E, A, T>(ctx, schip, pchip, proof /*, circuit.params*/)?;
    println!("fin eval multiopen pf");
    Ok((w_x, w_g, plain_assigned_instances, advice_commitments))
}

pub fn verify_aggregation_proofs_in_chip<
    E: MultiMillerLoop + Debug,
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
    mut circuits: Vec<CircuitProof<E, A, T>>,
    transcript: &mut T,
) -> Result<
    (
        A::AssignedPoint,           // w_x
        A::AssignedPoint,           // w_g
        Vec<A::AssignedScalar>,     // plain assigned instance
        Vec<Vec<A::AssignedPoint>>, // advice commitments
    ),
    A::Error,
> {
    let mut plain_assigned_instances = vec![];

    let multiopen_proofs: Vec<Vec<(MultiOpenProof<A>, Vec<A::AssignedPoint>)>> = circuits
        //let multiopen_proofs: Vec<Vec<MultiOpenProof<A>>> = circuits
        .iter_mut()
        .map(|circuit_proof| {
            let r = circuit_proof
                .proofs
                .iter_mut()
                .map(|proof| {
                    let instances1: Vec<Vec<&[E::Scalar]>> = proof
                        .instances
                        .iter()
                        .map(|x| x.iter().map(|y| &y[..]).collect())
                        .collect();
                    let instances2: Vec<&[&[E::Scalar]]> =
                        instances1.iter().map(|x| &x[..]).collect();

                    let (assigned_instances, assigned_instance_commitments) =
                        assign_instance_commitment(
                            ctx,
                            schip,
                            pchip,
                            &instances2[..],
                            circuit_proof.vk,
                            circuit_proof.params,
                        )?;

                    for assigned_instance in assigned_instances {
                        plain_assigned_instances.push(assigned_instance)
                    }

                    let (p, c) = verify_single_proof_no_eval(
                        ctx,
                        nchip,
                        schip,
                        pchip,
                        assigned_instance_commitments,
                        circuit_proof.vk,
                        circuit_proof.params,
                        &mut proof.transcript,
                        proof.key.clone(),
                    )?;

                    println!("get proof {} {}", circuit_proof.name, p);

                    Ok((p, c))
                })
                .collect::<Result<Vec<(MultiOpenProof<A>, Vec<A::AssignedPoint>)>, A::Error>>();

            /* update aggregation challenge */
            for p in circuit_proof.proofs.iter_mut() {
                let scalar = p.transcript.squeeze_challenge_scalar(ctx, nchip, schip)?;
                transcript.common_scalar(ctx, nchip, schip, &scalar)?;
            }

            return r;
        })
        .collect::<Result<Vec<Vec<(MultiOpenProof<A>, Vec<A::AssignedPoint>)>>, A::Error>>()?;

    let proofs = multiopen_proofs
        .into_iter()
        .flatten()
        .collect::<Vec<(MultiOpenProof<A>, Vec<A::AssignedPoint>)>>();

    let aggregation_challenge = transcript.squeeze_challenge_scalar(ctx, nchip, schip)?;

    let mut acc: Option<MultiOpenProof<A>> = None;
    let mut commits: Vec<Vec<A::AssignedPoint>> = vec![];
    for (proof, c) in proofs.into_iter() {
        acc = match acc {
            None => Some(proof),
            Some(acc) => Some(MultiOpenProof {
                w_x: acc.w_x * scalar!(aggregation_challenge) + proof.w_x,
                w_g: acc.w_g * scalar!(aggregation_challenge) + proof.w_g,
            }),
        };
        commits.push(c)
    }
    let aggregated_proof = acc.unwrap();

    evaluate_multiopen_proof::<E, A, T>(ctx, schip, pchip, aggregated_proof)
        .map(|pair| (pair.0, pair.1, plain_assigned_instances, commits))
}
