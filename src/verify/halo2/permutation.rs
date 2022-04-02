use crate::arith::api::{ContextGroup, ContextRing, PowConstant};
use crate::schema::EvaluationQuery;

use crate::{arith_in_ctx, infix2postfix};
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct Committed<P> {
    permutation_product_commitments: Vec<P>,
}

#[derive(Debug)]
pub struct EvaluatedSet<S, P> {
    pub(in crate::verify::halo2) permutation_product_commitment: P,
    pub(in crate::verify::halo2) permutation_product_eval: S,
    pub(in crate::verify::halo2) permutation_product_next_eval: S,
    pub(in crate::verify::halo2) permutation_product_last_eval: Option<S>,
    pub(in crate::verify::halo2) chunk_len: usize,
}

#[derive(Debug)]
pub struct CommonEvaluated<'a, S, P> {
    pub permutation_evals: &'a Vec<S>,
    pub permutation_commitments: &'a Vec<P>,
}

#[derive(Debug)]
pub struct Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) x: S,
    // put x_next x_last into circuit
    pub(in crate::verify::halo2) sets: Vec<EvaluatedSet<S, P>>,
    pub(in crate::verify::halo2) evals: Vec<S>,
    pub(in crate::verify::halo2) chunk_len: usize,
    pub(in crate::verify::halo2) _m: PhantomData<(C, Error)>,
}

impl<'a, S: Clone, P: Clone + Debug> CommonEvaluated<'a, S, P> {
    pub(in crate::verify::halo2) fn queries(&self, x: &'a S) -> Vec<EvaluationQuery<'a, S, P>> {
        // Open permutation commitments for each permutation argument at x
        self.permutation_commitments
            .iter()
            .zip(self.permutation_evals.iter())
            .enumerate()
            .map(|(i, (commitment, eval))| {
                EvaluationQuery::<'a, S, P>::new(
                    x.clone(),
                    format!("permutation_commitments{}", i),
                    &commitment,
                    &eval,
                )
            })
            .collect()
    }
}

impl<'a, C, S: Clone + Debug, P: Clone + Debug, Error: Debug> Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) fn expressions<T>(
        &'a self,
        sgate: &'a (impl ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>),
        ctx: &'a mut C,
        common: &'a CommonEvaluated<'a, S, P>,
        l_0: &'a S,
        l_last: &'a S,
        l_blind: &'a S,
        delta: &'a S,
        beta: &'a S,
        gamma: &'a S,
        x: &'a S,
    ) -> Result<Vec<S>, Error> {
        let mut res = vec![];
        let one = &sgate.one(ctx)?;

        //let left = arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma));

        // Enforce only for the first set.
        // l_0(X) * (1 - z_0(X)) = 0
        for first_set in self.sets.first() {
            let z_x = &first_set.permutation_product_eval;
            res.push(arith_in_ctx!([sgate, ctx] l_0 * (one - z_x))?);
        }

        // Enforce only for the last set.
        // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
        for last_set in self.sets.last() {
            let z_x = &last_set.permutation_product_eval;
            res.push(arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x))?);
        }

        // Except for the first set, enforce.
        // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
        for (set, last_set) in self.sets.iter().skip(1).zip(self.sets.iter()) {
            let s = &set.permutation_product_eval;
            let prev_last = last_set.permutation_product_last_eval.as_ref().unwrap();
            res.push(arith_in_ctx!([sgate, ctx](s - prev_last) * l_0)?);
        }

        // And for all the sets we enforce:
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
        // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
        // )
        for (chunk_index, ((set, evals), permutation_evals)) in self
            .sets
            .iter()
            .zip(self.evals.chunks(self.chunk_len))
            .zip(common.permutation_evals.chunks(self.chunk_len))
            .enumerate()
        {
            let mut left = set.permutation_product_next_eval.clone();
            let mut right = set.permutation_product_eval.clone();

            let delta_pow = if chunk_index == 0 {
                one.clone()
            } else {
                sgate
                    .pow_constant(ctx, delta, (chunk_index * self.chunk_len) as u32)
                    .unwrap()
            };
            let delta_pow = &delta_pow;
            let mut d = arith_in_ctx!([sgate, ctx] beta * x * delta_pow).unwrap();

            for (eval, permutation_eval) in evals.iter().zip(permutation_evals) {
                let delta_current = &d;
                let l_current = &left;
                let r_current = &right;
                left =
                    arith_in_ctx!([sgate, ctx](eval + beta * permutation_eval + gamma) * l_current)
                        .unwrap();
                right =
                    arith_in_ctx!([sgate, ctx](eval + delta_current + gamma) * r_current).unwrap();
                d = arith_in_ctx!([sgate, ctx] delta * delta_current).unwrap();
            }
            let (l, r) = (&left, &right);
            res.push(arith_in_ctx!([sgate, ctx](l - r) * (one - (l_last + l_blind))).unwrap());
        }

        Ok(res)
    }
    pub(in crate::verify::halo2) fn queries(
        &'a self,
        x_next: &'a S,
        x_last: &'a S,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        iter::empty()
            .chain(self.sets.iter().enumerate().flat_map(|(i, set)| {
                iter::empty()
                    // FIXME: double check eval or prev-eval
                    // Open permutation product commitments at x and \omega^{-1} x
                    // Open permutation product commitments at x and \omega x
                    .chain(Some(EvaluationQuery::new(
                        self.x.clone(),
                        format!("permutation_product_commitment{}", i),
                        &set.permutation_product_commitment,
                        &set.permutation_product_eval,
                    )))
                    .chain(Some(EvaluationQuery::new(
                        x_next.clone(),
                        format!("permutation_product_commitment{}", i),
                        &set.permutation_product_commitment,
                        &set.permutation_product_next_eval,
                    )))
            }))
            // Open it at \omega^{last} x for all but the last set
            .chain(
                self.sets
                    .iter()
                    .enumerate()
                    .rev()
                    .skip(1)
                    .flat_map(|(i, set)| {
                        Some(EvaluationQuery::new(
                            x_last.clone(),
                            format!("permutation_product_commitment{}", i),
                            &set.permutation_product_commitment,
                            &set.permutation_product_last_eval.as_ref().unwrap(),
                        ))
                    }),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ast::ArrayOpAdd;
    use crate::{
        arith::code::FieldCode,
        schema::utils::VerifySetupHelper,
        verify::{halo2::tests::mul_circuit_builder::*, plonk::bn_to_field},
    };
    use halo2_proofs::arithmetic::CurveAffine;
    use num_bigint::BigUint;
    use pairing_bn256::bn256::Fr;
    use pairing_bn256::bn256::{G1Affine, G1};

    #[test]
    fn test_permutation_pcommon() {
        let (_, _, _, params) = build_verifier_params(true).unwrap();

        let res: Vec<<G1Affine as CurveAffine>::ScalarExt> = vec![
            BigUint::parse_bytes(
                b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"0fa7d2a74c9c0c7aee15a51c6213e9cd05eaa928d4ff3e0e0621552b885c4c08",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"0fa7d2a74c9c0c7aee15a51c6213e9cd05eaa928d4ff3e0e0621552b885c4c08",
                16,
            )
            .unwrap(),
        ]
        .into_iter()
        .map(|ele| bn_to_field(&ele))
        .collect();

        for ele in &params.permutation_evaluated {
            let x_next = &params.x_next;
            let x_last = &params.x_last;
            ele.queries(x_next, x_last)
                .zip(res.iter())
                .for_each(|(query, expected)| assert_eq!(query.point, *expected))
        }
    }

    #[test]
    fn test_permutation_queries() {
        let _ = build_verifier_params(true).unwrap();
    }

    #[test]
    fn test_permutation_expressions() {
        let (_, _, _, param) = build_verifier_params(true).unwrap();
        let sgate = FieldCode::<Fr>::default();

        let mut result = vec![];
        let mut ctx = ();
        let ls = sgate
            .get_lagrange_commits(
                &mut ctx,
                &param.x,
                &param.xn,
                &param.omega,
                param.common.n,
                param.common.l as i32,
            )
            .unwrap();
        let l_last = &(ls[0]);
        let l_0 = &ls[param.common.l as usize];
        let l_blind = &sgate
            .add_array(&mut ctx, ls[1..(param.common.l as usize)].iter().collect())
            .unwrap();
        let pcommon = CommonEvaluated {
            permutation_evals: &param.permutation_evals,
            permutation_commitments: &param.permutation_commitments,
        };

        let expected = vec![
            bn_to_field(
                &BigUint::parse_bytes(
                    b"232c781b8a3c8ef63a989c0ec9fdfaa7734ab4f6821e7ef349fbdf3b73e876f2",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"104893a179bad7d055ae14568eed1290000a737ad9499978d77a27ca933529b7",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"145668dd152b253bd803cb6a0b938f6a8d8e8dbab1293eb0a9918d98642c96af",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1c54cb558b475c1d3af73756d40180ef4e54e23c9b541d9b542e28a00fb03f28",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"168828762a15bef86db4bba10e9baffec033b09ef863bedb5e3b556362b6a386",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"054db75d2125435a1558e5c9408c32ee59d943fe1338f8d7695ce5903667658c",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"17a77d738b74306c25640ab1c93abcb91f07a512c6c332e0b3ee237fcbcf0261",
                    16,
                )
                .unwrap(),
            ),
        ];

        for k in 0..param.advice_evals.len() {
            let permutation = &param.permutation_evaluated[k];

            let p = permutation
                .expressions(
                    &sgate,
                    &mut ctx,
                    &pcommon,
                    l_0,
                    l_last,
                    l_blind,
                    &param.delta,
                    &param.beta,
                    &param.gamma,
                    &param.x,
                )
                .unwrap();
            result.extend(p);
        }
        assert_eq!(result, expected);
    }
}
