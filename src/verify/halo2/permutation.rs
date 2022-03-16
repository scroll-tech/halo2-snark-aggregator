use crate::arith::api::{ContextGroup, ContextRing};
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

impl<'a, S: Clone, P: Clone> CommonEvaluated<'a, S, P> {
    pub(in crate::verify::halo2) fn queries(&self, x: &'a S) -> Vec<EvaluationQuery<'a, S, P>> {
        // Open permutation commitments for each permutation argument at x
        self.permutation_commitments
            .iter()
            .zip(self.permutation_evals.iter())
            .map(|(commitment, eval)| {
                EvaluationQuery::<'a, S, P>::new(x.clone(), &commitment, &eval)
            })
            .collect()
    }
}

impl<'a, C, S: Clone, P: Clone, Error: Debug> Evaluated<C, S, P, Error> {
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
    ) -> Result<impl Iterator<Item = S> + 'a, Error> {
        let one = &sgate.one(ctx)?;

        //let left = arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma));

        Ok(iter::empty()
            // Enforce only for the first set.
            // l_0(X) * (1 - z_0(X)) = 0
            .chain(self.sets.first().map(|first_set| {
                let z_x = &first_set.permutation_product_eval;
                arith_in_ctx!([sgate, ctx] l_0 * (one - z_x)).unwrap()
            }))
            // Enforce only for the last set.
            // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
            .chain(self.sets.last().map(|last_set| {
                let z_x = &last_set.permutation_product_eval;
                arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x)).unwrap()
            }))
            // Except for the first set, enforce.
            // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
            .chain({
                // mutable borrow ctx, can not use closure!
                let mut v = vec![];
                for (set, last_set) in self.sets.iter().skip(1).zip(self.sets.iter()) {
                    let s = &set.permutation_product_eval;
                    let prev_last = &last_set.permutation_product_last_eval.as_ref().unwrap();
                    v.push(arith_in_ctx!([sgate, ctx](s - prev_last) * l_0).unwrap());
                }
                v
            })
            // And for all the sets we enforce:
            // (1 - (l_last(X) + l_blind(X))) * (
            //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
            // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
            // )
            .chain({
                let mut v = vec![];
                for ((set, evals), permutation_evals) in self
                    .sets
                    .iter()
                    .zip(self.evals.chunks(self.chunk_len))
                    .zip(common.permutation_evals.chunks(self.chunk_len))
                {
                    let one = &sgate.one(ctx).unwrap();
                    let mut left = set.permutation_product_next_eval.clone();
                    let mut right = set.permutation_product_eval.clone();
                    let mut d = arith_in_ctx!([sgate, ctx] beta * x * delta).unwrap();
                    for (eval, permutation_eval) in evals.iter().zip(permutation_evals) {
                        let delta_current = &d;
                        let l_current = &left;
                        let r_current = &right;
                        left = arith_in_ctx!(
                            [sgate, ctx](eval + beta * permutation_eval + gamma) * l_current
                        )
                        .unwrap();
                        right =
                            arith_in_ctx!([sgate, ctx](eval + delta + gamma) * r_current).unwrap();
                        d = arith_in_ctx!([sgate, ctx] delta * delta_current).unwrap();
                    }
                    let (l, r) = (&left, &right);
                    v.push(
                        arith_in_ctx!([sgate, ctx](l - r) * (one - (l_last + l_blind))).unwrap(),
                    );
                }
                v
            }))
    }
    pub(in crate::verify::halo2) fn queries(
        &'a self,
        x_next: &'a S,
        x_last: &'a S,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        iter::empty()
            .chain(self.sets.iter().flat_map(|set| {
                iter::empty()
                    // FIXME: double check eval or prev-eval
                    // Open permutation product commitments at x and \omega^{-1} x
                    // Open permutation product commitments at x and \omega x
                    .chain(Some(EvaluationQuery::new(
                        self.x.clone(),
                        &set.permutation_product_commitment,
                        &set.permutation_product_eval,
                    )))
                    .chain(Some(EvaluationQuery::new(
                        x_next.clone(),
                        &set.permutation_product_commitment,
                        &set.permutation_product_next_eval,
                    )))
            }))
            // Open it at \omega^{last} x for all but the last set
            .chain(self.sets.iter().rev().skip(1).flat_map(|set| {
                Some(EvaluationQuery::new(
                    x_last.clone(),
                    &set.permutation_product_commitment,
                    &set.permutation_product_last_eval.as_ref().unwrap(),
                ))
            }))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        schema::{
            ast::{CommitQuery, SchemaItem},
            EvaluationQuery,
        },
        verify::{halo2::tests::mul_circuit_builder::*, plonk::bn_to_field},
    };
    use halo2_proofs::arithmetic::CurveAffine;
    use num_bigint::BigUint;
    use pairing_bn256::bn256::Fr;
    use pairing_bn256::bn256::{G1Affine, G1};

    #[test]
    fn test_permutation_pcommon() {
        let params = build_verifier_params().unwrap();

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
        let params = build_verifier_params().unwrap();

        let points: Vec<<G1Affine as CurveAffine>::ScalarExt> = vec![
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0fa7d2a74c9c0c7aee15a51c6213e9cd05eaa928d4ff3e0e0621552b885c4c08",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0fa7d2a74c9c0c7aee15a51c6213e9cd05eaa928d4ff3e0e0621552b885c4c08",
                    16,
                )
                .unwrap(),
            ),
        ];

        let c = vec![
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1a948b3fb65b41f3dc3b30353e2d1c4adeea001ac3e6d576e741e3538a203af7",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"2dbf1a3f2bdac940961f5abb9a1892327e1670aaa28080df6563aae790130740",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1a948b3fb65b41f3dc3b30353e2d1c4adeea001ac3e6d576e741e3538a203af7",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"2dbf1a3f2bdac940961f5abb9a1892327e1670aaa28080df6563aae790130740",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1470362245575f37b24cb30ac4e794c3acc1f474cfc7ac23c53c4c1914644920",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0643f7719338fba5da586185b0567a92878022ad9e087af96bae210fc8f470c2",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1470362245575f37b24cb30ac4e794c3acc1f474cfc7ac23c53c4c1914644920",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0643f7719338fba5da586185b0567a92878022ad9e087af96bae210fc8f470c2",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"13e7133d4384653fc031c7560a5c4ead30d40b650b16e8adfdbd04e380f75932",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1233dddffdb74bb3aa231f78756496560a56c340dbc306577d8d9bad6668b2db",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"13e7133d4384653fc031c7560a5c4ead30d40b650b16e8adfdbd04e380f75932",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1233dddffdb74bb3aa231f78756496560a56c340dbc306577d8d9bad6668b2db",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1470362245575f37b24cb30ac4e794c3acc1f474cfc7ac23c53c4c1914644920",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0643f7719338fba5da586185b0567a92878022ad9e087af96bae210fc8f470c2",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"1a948b3fb65b41f3dc3b30353e2d1c4adeea001ac3e6d576e741e3538a203af7",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"2dbf1a3f2bdac940961f5abb9a1892327e1670aaa28080df6563aae790130740",
                        16,
                    )
                    .unwrap(),
                ),
                z: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0000000000000000000000000000000000000000000000000000000000000001",
                        16,
                    )
                    .unwrap(),
                ),
            },
        ];

        let evals: Vec<<G1Affine as CurveAffine>::ScalarExt> = vec![
            bn_to_field(
                &BigUint::parse_bytes(
                    b"295d8195e47cf7c64c9be98f577d9b43854fa4b42c28d7f36f9e5a6f48b64d3d",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1f7705f0a0d81073b6f661176a431526d543624c9269438fe6a26fd4f443de2c",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"028d9fd9ff60294a75bd1b784b248689756ef4a3c0d15af78f8640c0cf99bf12",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"13fface0894584564bbdd4810bf4021eabcef946d537d4223f1ea6ad60d72001",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"11deee6cf5a8486104bec0fa9b6fb0c7b65b08ae33fe9b5076c6998c1cdbd9b5",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1d0111d19a1f71d286b6d347b069f5f0d340a85b7bba138dd49446a95a413e47",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0605366d0a26502ae991ca5fdc6f744cc67f58925186e4b9650ab1c13189a2ca",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"1202c4de9d6dc3e14df36286bda3af3e1fa48e654ce05031f15bb36ae018d5e5",
                    16,
                )
                .unwrap(),
            ),
        ];

        let schema_item: Vec<SchemaItem<_, _>> = c
            .iter()
            .zip(evals.iter())
            .map(|(c, eval)| {
                SchemaItem::Add({
                    let commit = SchemaItem::Commit(CommitQuery {
                        c: Some(c),
                        v: Some(eval),
                    });
                    let eval = SchemaItem::Eval(CommitQuery {
                        c: Some(c),
                        v: Some(eval),
                    });
                    vec![commit, eval]
                })
            })
            .collect();

        let expected: Vec<EvaluationQuery<Fr, G1>> = points
            .into_iter()
            .zip(schema_item.into_iter())
            .map(|(point, s)| EvaluationQuery { point, s })
            .collect();

        for ele in &params.permutation_evaluated {
            let x_next = &params.x_next;
            let x_last = &params.x_last;
            for (query, expected) in ele.queries(x_next, x_last).zip(expected.iter()) {
                assert_eq!(query, *expected);
            }
        }
    }
}
