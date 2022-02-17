//use halo2_proofs::arithmetic::{CurveAffine, Field, FieldExt, CurveExt};
use pairing_bn256::arithmetic::{CurveAffine, CurveExt, FieldExt};
use pairing_bn256::group::{Group};
use pairing_bn256::bn256::G1Affine;
use crate::arith::code::{ FieldCode, PointCode };
use crate::arith::api::{ ContextGroup, ContextRing};
use num_bigint::BigUint;

pub fn field_to_bn<F: FieldExt>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

pub fn bn_to_field<F: FieldExt>(bn: &BigUint) -> F {
    F::from_str_vartime(&bn.to_str_radix(10)[..]).unwrap()
}

mod verify;

use verify::{
    ParamsPreprocessed,
    VerifyCommitments,
    VerifyEvals,
    PlonkCommonSetup,
    PlonkVerifierParams,
};

struct PlonkVeriyCode<'a, C:CurveAffine> (
    PlonkVerifierParams<'a, (), C::ScalarExt, C::CurveExt, (), FieldCode<C::ScalarExt>, PointCode<C>>
);
// type PlonkVeriyCircuit = PlonkVerifierParams<'a, Gate ....

fn test() {
    let fc = FieldCode::<<G1Affine as CurveAffine>::ScalarExt> {
        one: <G1Affine as CurveAffine>::ScalarExt::one(),
        zero: <G1Affine as CurveAffine> ::ScalarExt::zero(),
        generator: <G1Affine as CurveAffine>::ScalarExt::one(),
    };

    let pc = PointCode::<G1Affine> {
        one: <G1Affine as CurveAffine>::CurveExt::generator(),
        zero: <G1Affine as CurveAffine>::CurveExt::identity(),
        generator: <G1Affine as CurveAffine>::CurveExt::generator(),
    };

    let w = BigUint::from_bytes_be(b"19540430494807482326159819597004422086093766032135589407132600596362845576832");

    let common_setup = PlonkCommonSetup::<<G1Affine as CurveAffine>::ScalarExt> {
        l: 3,
        n: 6,
        k: vec![],
        one: fc.one(),
        zero: fc.zero(),
        w: &bn_to_field(&w),
    };

    let eval_a = BigUint::from_bytes_be(b"15874696065033092140057970723870056386558847966321247907842185103680672251511");
    let eval_b = BigUint::from_bytes_be(b"12516712789824286583573599278119872606088448672488752257813056689328360583640");
    let eval_c = BigUint::from_bytes_be(b"21731543225022770624058961898502768948001772467212094197481092373058747109017");
    let eval_s1 = BigUint::from_bytes_be(b"1015555625001039730393073161233714366539087349855390795461049905849921044091");
    let eval_s2 = BigUint::from_bytes_be(b"13714551528971161043821001033408458549467433855502908520346647400608731940529");
    let eval_zw = BigUint::from_bytes_be(b"13450562795347361242714833094437276923608543548130434746393967860648863329885");



    let verify_evals = VerifyEvals::<<G1Affine as CurveAffine>::ScalarExt> {
        a_xi: &bn_to_field(&eval_a),
        b_xi: &bn_to_field(&eval_b),
        c_xi: &bn_to_field(&eval_c),
        sigma1_xi: &bn_to_field(&eval_s1),
        sigma2_xi: &bn_to_field(&eval_s2),
        z_xiw: &bn_to_field(&eval_zw),
    };


    let beta = BigUint::from_bytes_be(b"214b571120687bdb81bb4587e352ef485adc334eb7266de648c930078eb834b9");
    let gamma = BigUint::from_bytes_be(b"83238c5b3ec0c81579709bf13275200e4be4f2c8e3149d1e31a781f79756304");
    let alpha = BigUint::from_bytes_be(b"277a420332215ead37ba61fee84f0d23276a6799e5da57c1354dc37d12a7c2dc");
    let xi = BigUint::from_bytes_be(b"2db03a3da77eed4347378701547e5c8558f35a5a9e79fcb76283ee1877632eec");

}

/*
[DEBUG] snarkJS: v1: 241b36e2a052636de79d41ab73f876cacfbdd8e09b48cc0309c541041550bba // v
[DEBUG] snarkJS: v6: 1fd289d840b7896ea4f3f590d0750e417894cb9b4fe8e8d457648304e55eb299 // v6 = v ^ 6
*/


#[cfg(test)]
mod test_marco {
  use crate::arith::api::ContextGroup;
  use crate::arith::api::ContextRing;
  use crate::arith::code::FieldCode;
  use crate::arith::code::PointCode;
  use pairing_bn256::bn256::G1;
}
