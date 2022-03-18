use super::verify::Evaluable;
use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::utils::VerifySetupHelper;
use crate::schema::EvaluationQuery;
use crate::{arith_in_ctx, infix2postfix};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct PermutationCommitments<P> {
    pub(in crate::verify::halo2) permuted_input_commitment: P,
    pub(in crate::verify::halo2) permuted_table_commitment: P,
}

#[derive(Debug)]
pub struct Committed<P> {
    pub(in crate::verify::halo2) permuted: PermutationCommitments<P>,
    pub(in crate::verify::halo2) product_commitment: P,
}

#[derive(Debug)]
pub struct Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) input_expressions: Vec<Expression<S>>,
    pub(in crate::verify::halo2) table_expressions: Vec<Expression<S>>,
    pub(in crate::verify::halo2) committed: Committed<P>,
    pub(in crate::verify::halo2) product_eval: S, // X
    pub(in crate::verify::halo2) product_next_eval: S, // ωX
    pub(in crate::verify::halo2) permuted_input_eval: S,
    pub(in crate::verify::halo2) permuted_input_inv_eval: S,
    pub(in crate::verify::halo2) permuted_table_eval: S,
    pub(in crate::verify::halo2) _m: PhantomData<(C, Error)>,
}

impl<'a, C, S: Clone + Debug, P: Clone, Error: Debug> Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) fn expressions<T: FieldExt>(
        &'a self,
        sgate: &(impl ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>),
        ctx: &'a mut C,
        fixed_evals: &'a Vec<&'a S>,
        instance_evals: &'a Vec<&'a S>,
        advice_evals: &'a Vec<&'a S>,
        l_0: &'a S,
        l_last: &'a S,
        l_blind: &'a S,
        theta: &'a S,
        beta: &'a S,
        gamma: &'a S,
    ) -> Result<impl Iterator<Item = S>, Error> {
        let _one = sgate.one(ctx)?;
        let one = &_one;
        let z_wx = &self.product_next_eval;
        let z_x = &self.product_eval;
        let a_x = &self.permuted_input_eval;
        let s_x = &self.permuted_table_eval;
        let a_invwx = &self.permuted_input_inv_eval;
        let product_eval = &self.product_eval;

        let left = &arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma))?;

        let input_evals: Vec<S> = self
            .input_expressions
            .iter()
            .map(|expression| {
                expression.ctx_evaluate(
                    sgate,
                    ctx,
                    &|n| fixed_evals[n].clone(),
                    &|n| advice_evals[n].clone(),
                    &|n| instance_evals[n].clone(),
                )
            })
            .collect();
        let input_eval = &sgate.mult_and_add(ctx, input_evals.iter(), theta);

        let table_evals: Vec<S> = self
            .input_expressions
            .iter()
            .map(|expression| {
                expression.ctx_evaluate(
                    sgate,
                    ctx,
                    &|n| fixed_evals[n].clone(),
                    &|n| advice_evals[n].clone(),
                    &|n| instance_evals[n].clone(),
                )
            })
            .collect();
        let table_eval = &sgate.mult_and_add(ctx, table_evals.iter(), theta);

        Ok(iter::empty()
            .chain(
                // l_0(X) * (1 - z'(X)) = 0
                arith_in_ctx!([sgate, ctx] l_0 * (one - z_x)),
            )
            .chain(
                // l_last(X) * (z(X)^2 - z(X)) = 0
                arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x)),
            )
            .chain(
                // (1 - (l_last(X) + l_blind(X))) * (
                //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
                //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
                // ) = 0
                arith_in_ctx!(
                    [sgate, ctx](left - product_eval * (input_eval + beta) * (table_eval + gamma))
                        * (one - (l_last + l_blind))
                ), //active rows
            )
            .chain(
                // l_0(X) * (a'(X) - s'(X)) = 0
                arith_in_ctx!([sgate, ctx] l_0 * (a_x - s_x)),
            )
            .chain(
                // (1 - (l_last(X) + l_blind(X))) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
                arith_in_ctx!(
                    [sgate, ctx](a_x - s_x) * (a_x - a_invwx) * (one - (l_last + l_blind))
                ),
            ))
    }

    pub(in crate::verify::halo2) fn queries(
        &'a self,
        x: &'a S,
        x_inv: &'a S,
        x_next: &'a S,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        iter::empty()
            // Open lookup product commitment at x
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                &self.committed.product_commitment,
                &self.product_eval,
            )))
            // Open lookup input commitments at x
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                &self.committed.permuted.permuted_input_commitment,
                &self.permuted_input_eval,
            )))
            // Open lookup table commitments at x
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                &self.committed.permuted.permuted_table_commitment,
                &self.permuted_table_eval,
            )))
            // Open lookup input commitments at \omega^{-1} x
            .chain(Some(EvaluationQuery::new(
                x_inv.clone(),
                &self.committed.permuted.permuted_input_commitment,
                &self.permuted_input_inv_eval,
            )))
            // Open lookup product commitment at \omega x
            .chain(Some(EvaluationQuery::new(
                x_next.clone(),
                &self.committed.product_commitment,
                &self.product_next_eval,
            )))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use pairing_bn256::bn256::{Fr, G1};

    use crate::{
        schema::EvaluationQuery,
        verify::{halo2::tests::lookup_circuit_builder::build_verifier_params, plonk::bn_to_field},
    };

    #[test]
    fn test_lookup_evaluated() {
        let params = build_verifier_params().unwrap();

        let point = vec![
            bn_to_field(
                &BigUint::parse_bytes(
                    b"015032989a10da518164bbc7813fc9dfbe7f28c5024e986c6f0443fd0ad9c2b8",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"015032989a10da518164bbc7813fc9dfbe7f28c5024e986c6f0443fd0ad9c2b8",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"015032989a10da518164bbc7813fc9dfbe7f28c5024e986c6f0443fd0ad9c2b8",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"16401165f6eff43ae1136c5926b5574a1840fe4ea1d87dc58a5aa76412da32cb",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"035c3590a63a63855b04faaf73652de0a121bad3c6ea9dbd53e7739534bb854f",
                    16,
                )
                .unwrap(),
            ),
        ];

        let commitment = vec![
            G1 {
                x: bn_to_field(
                    &BigUint::parse_bytes(
                        b"077bc1b638c2eb47d048c446e30216553601f420deeecd7f0cecf86e58c144b1",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"2b8e229bc8ba77b92311b3f38e28aefb0a8cf7245b97c4263d7e5144d00331b9",
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
                        b"1f9f3347f9b401e4a768e058eb0f7e8ab2fc98b9bb5c555c9dfec0376f0a367b",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"202fcab76493c549c454946dcf7ef061011e40ed62238c15e3c378fd26662bda",
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
                        b"0ea507d0ef046f4cbfefe16aa304342f385fd331eebd329a3ea5a5ad00c58c18",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"0c0dab138bb190da35d1e7ecea4ed1b59a8110be4c5bcbe019701bf35fc8d7f8",
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
                        b"1f9f3347f9b401e4a768e058eb0f7e8ab2fc98b9bb5c555c9dfec0376f0a367b",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"202fcab76493c549c454946dcf7ef061011e40ed62238c15e3c378fd26662bda",
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
                        b"077bc1b638c2eb47d048c446e30216553601f420deeecd7f0cecf86e58c144b1",
                        16,
                    )
                    .unwrap(),
                ),
                y: bn_to_field(
                    &BigUint::parse_bytes(
                        b"2b8e229bc8ba77b92311b3f38e28aefb0a8cf7245b97c4263d7e5144d00331b9",
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

        let eval: Vec<Fr> = vec![
            bn_to_field(
                &BigUint::parse_bytes(
                    b"16728c6fb9318b519ca10b5b9a4fe407db2243487d60432392f7704bdcda2b1c",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0862fa0438c476f29b2c5bc3a6444024359076dee50a3ea2b30ce94f23657aed",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"15aafc436b1b3892708dd5db1be4362771c722edbf886bbd86fc90cdf4d0e92b",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"263b14a199e642552f0cdabdebc3e6c6490652b9401df903bb3da950dbf9b723",
                    16,
                )
                .unwrap(),
            ),
            bn_to_field(
                &BigUint::parse_bytes(
                    b"0a7bbf6b2bd7865492078952a11996b4a0734e1a2aa9e542bf5a44c607751ed0",
                    16,
                )
                .unwrap(),
            ),
        ];

        let expected = point
            .into_iter()
            .zip(commitment.iter())
            .zip(eval.iter())
            .map(|((p, c), v)| EvaluationQuery::new(p, c, v))
            .collect::<Vec<_>>();

        params.lookup_evaluated.iter().for_each(|lookups| {
            lookups.iter().for_each(|lookup| {
                lookup
                    .queries(&params.x, &params.x_inv, &params.x_next)
                    .zip(expected.iter())
                    .for_each(|(q, expected)| {
                        assert_eq!(q, *expected);
                    });
            })
        })
    }
}
