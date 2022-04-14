use super::*;
use crate::{
    arith::code::FieldCode, verify::halo2::{tests::mul_circuit_builder::build_verifier_params},
};
use pairing_bn256::bn256::Fr;

#[test]
fn test_ctx_evaluate() {
    use crate::verify::halo2::verify::evaluate::Evaluable;

    let sgate = FieldCode::<Fr>::default();
    let zero = sgate.zero(&mut ()).unwrap();

    let (_, _, _, params) = build_verifier_params(true).unwrap();

    params
        .advice_evals
        .iter()
        .zip(params.instance_evals.iter())
        .for_each(|(advice_evals, instance_evals)| {
            params.gates.iter().for_each(|gate| {
                gate.into_iter().for_each(|poly| {
                    let res = poly
                        .ctx_evaluate(
                            &sgate,
                            &mut (),
                            &|n| params.fixed_evals[n],
                            &|n| advice_evals[n],
                            &|n| instance_evals[n],
                            &zero,
                        )
                        .unwrap();
                    let expected: Fr = poly.evaluate(
                        &|scalar| scalar,
                        &|_| panic!("virtual selectors are removed during optimization"),
                        &|n, _, _| params.fixed_evals[n],
                        &|n, _, _| advice_evals[n],
                        &|n, _, _| instance_evals[n],
                        &|a| -a,
                        &|a, b| a + &b,
                        &|a, b| a * &b,
                        &|a, scalar| a * &scalar,
                    );
                    assert_eq!(res, expected);
                })
            })
        });
}

#[cfg(feature = "black2b")]
#[test]
fn test_rotate_omega() {
    let (_, _, _, param) = build_verifier_params(true).unwrap();
    assert_eq!(
        param.x,
        bn_to_field(
            &BigUint::parse_bytes(
                b"0c4490cdcf6545e3e7b951799adab8efd7e0812cf59bb1fde0cb826e5b51448b",
                16
            )
            .unwrap()
        )
    );
    assert_eq!(
        param.x_next,
        bn_to_field(
            &BigUint::parse_bytes(
                b"1a23d5660f0fd2ff2bb5d01c2b69499da64c863234fd8474d2715a59acf918df",
                16
            )
            .unwrap()
        )
    );
    assert_eq!(
        param.x_last,
        bn_to_field(
            &BigUint::parse_bytes(
                b"0fa7d2a74c9c0c7aee15a51c6213e9cd05eaa928d4ff3e0e0621552b885c4c08",
                16
            )
            .unwrap()
        )
    );
    assert_eq!(
        param.x_inv,
        bn_to_field(
            &BigUint::parse_bytes(
                b"18e61e79f9a7becf4090148dd6321acd9f0da0df20b2e26069a360842598beac",
                16
            )
            .unwrap()
        )
    );
    assert_eq!(
        param.xn,
        bn_to_field(
            &BigUint::parse_bytes(
                b"0918f0797719cd0667a1689f6fd167dbfa8ddd0ac5218125c08598dadef28e70",
                16
            )
            .unwrap()
        )
    );
}

#[test]
fn test_verify_queries() {
    let _ = build_verifier_params(true).unwrap();
}

#[test]
fn test_multi_open() {
    use pairing_bn256::bn256::Bn256;

    let (sg, pg, params_verifier, param) = build_verifier_params(false).unwrap();

    let guard = param.batch_multi_open_proofs(&mut (), &sg, &pg).unwrap();

    let (left_s, left_e) = guard.w_x.eval(&sg, &pg, &mut ()).unwrap();
    let left_s = left_e
        .map_or(Ok(left_s.unwrap()), |left_e| {
            let one = pg.one(&mut ())?;
            let left_es = pg.scalar_mul(&mut (), &left_e, &one)?;
            pg.add(&mut (), &left_s.unwrap(), &left_es)
        })
        .unwrap();
    let (right_s, right_e) = guard.w_g.eval(&sg, &pg, &mut ()).unwrap();
    let right_s = right_e
        .map_or(Ok(right_s.unwrap()), |right_e| {
            let one = pg.one(&mut ())?;
            let right_es = pg.scalar_mul(&mut (), &right_e, &one)?;
            pg.minus(&mut (), &right_s.unwrap(), &right_es)
        })
        .unwrap();

    let p1 = Bn256::pairing(&left_s.to_affine(), &params_verifier.s_g2);
    let p2 = Bn256::pairing(&right_s.to_affine(), &params_verifier.g2);

    assert_eq!(p1, p2);
}
