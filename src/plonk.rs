//use halo2_proofs::arithmetic::{CurveAffine, Field, FieldExt, CurveExt};
use pairing_bn256::arithmetic::{CurveAffine, CurveExt, FieldExt};
use crate::arith::api::{ ContextGroup, ContextRing};
use crate::arith::code::{ FieldCode, PointCode };
use num_bigint::BigUint;

pub fn field_to_bn<F: FieldExt>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

pub fn bn_to_field<F: FieldExt>(bn: &BigUint) -> F {
    F::from_str_vartime(&bn.to_str_radix(10)[..]).unwrap()
}

macro_rules! parse_point {
    ($x:tt, $y:tt, $z:tt) => {{
        let x = BigUint::from_bytes_be($x);
        let y = BigUint::from_bytes_be($y);
        let z = BigUint::from_bytes_be($z);
        G1 {
            x: bn_to_field(&x),
            y: bn_to_field(&y),
            z: bn_to_field(&z),
        }
    }};
}

mod verify;

use verify::{
    PlonkVerifierParams,
};

struct PlonkVeriyCode<'a, C:CurveAffine> (
    PlonkVerifierParams<'a, (), C::ScalarExt, C::CurveExt, (), FieldCode<C::ScalarExt>, PointCode<C>>
);
// type PlonkVeriyCircuit = PlonkVerifierParams<'a, Gate ....


/*
[DEBUG] snarkJS: v1: 241b36e2a052636de79d41ab73f876cacfbdd8e09b48cc0309c541041550bba // v
[DEBUG] snarkJS: v6: 1fd289d840b7896ea4f3f590d0750e417894cb9b4fe8e8d457648304e55eb299 // v6 = v ^ 6
*/


#[cfg(test)]
mod test_marco {
    use pairing_bn256::arithmetic::{CurveAffine, CurveExt, FieldExt};
    use pairing_bn256::group::{Group};
    use pairing_bn256::bn256::{G1Affine, G1};
    use crate::plonk::bn_to_field;
    use crate::arith::code::{ FieldCode, PointCode };
    use crate::arith::api::{ ContextGroup, ContextRing};
    use crate::schema::{ast::EvaluationAST, SchemaGenerator};
    use num_bigint::BigUint;
    use super::verify::{
        PlonkVerifierParams,
        ParamsPreprocessed,
        VerifyCommitments,
        VerifyEvals,
        PlonkCommonSetup,
    };
    #[test]
    fn test_plonk_verify() {
        use std::marker::PhantomData;
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
        let k1 = fc.from_constant(2).unwrap();
        let k2 = fc.from_constant(3).unwrap();

        let common_setup = PlonkCommonSetup::<<G1Affine as CurveAffine>::ScalarExt> {
            l: 1,
            n: 3,
            k: vec![&k2, &k1],
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

        let params_preprocessed = ParamsPreprocessed::<<G1Affine as CurveAffine>::CurveExt> {
            q_m: &parse_point![b"0",b"1",b"0"],
            q_l: &parse_point![b"1",b"2",b"1"],
            q_r: &parse_point![b"0",b"1",b"0"],
            q_o: &parse_point![b"0",b"1",b"0"],
            q_c: &parse_point![b"0",b"1",b"0"],
            sigma1: &parse_point![
                b"1461695864918269365232199715865940252310195314576131408395620762176371501787",
                b"21084250934669175567011015796084994915431553089071438924590878091161620258097",
                b"1"
            ],
            sigma2: &parse_point![
                b"3169769012051567432925033566765202311392704386909137680965003500853254824955",
                b"19832316947899247057844792124392602068447564863321455059384276227252923045609",
                b"1"
            ],
            sigma3: &parse_point![
                b"1368015179489954701390400359078579693043519447331113978918064868415326638035",
                b"9918110051302171585080402603319702774565515993150576347155970296011118125764",
                b"1"
            ],

        };

        let verify_commits = VerifyCommitments {
            a: &parse_point![b"1",b"2",b"1"],
            b: &parse_point![b"0",b"1",b"0"],
            c: &parse_point![b"0",b"1",b"0"],
            z: &parse_point![b"1",b"2",b"1"],
            tl: &parse_point![
             b"17854219395178748277044640848668150805797528806531578628823778365744595010633",
             b"10996544557551259810885718753373803907340806712576557274408072720931302813031",
             b"1"
            ],
            tm: &parse_point![
             b"7357959165167171189678591040121624636749524226666006904463685750709262425204",
             b"6962971883664889852696016400794273745454851327170170073525743055904065939070",
             b"1"
            ],
            th: &parse_point![
             b"14320693582229639805641451582977352206237888341297101751924787765754461800205",
             b"14543795003186061847774979893616144118620198855074010614418831061093296954138",
             b"1"
            ],
            w_z: &parse_point![
             b"9063146129191295971212274825350647159015385342620013280646997535603969559392",
             b"12015088180096986016696110355727352651993299455354736442921460749200226316173",
             b"1"
            ],
            w_zw: &parse_point![
             b"13245195358167389015007513587105227711952961313976313999629002095959268210532",
             b"8173845022066305694175949735671264110437672168707042527697532466501748461340",
             b"1"
            ],
        };

        let beta = BigUint::from_bytes_be(b"214b571120687bdb81bb4587e352ef485adc334eb7266de648c930078eb834b9");
        let gamma = BigUint::from_bytes_be(b"83238c5b3ec0c81579709bf13275200e4be4f2c8e3149d1e31a781f79756304");
        let alpha = BigUint::from_bytes_be(b"277a420332215ead37ba61fee84f0d23276a6799e5da57c1354dc37d12a7c2dc");
        let xi = BigUint::from_bytes_be(b"2db03a3da77eed4347378701547e5c8558f35a5a9e79fcb76283ee1877632eec");
        let v = BigUint::from_bytes_be(b"241b36e2a052636de79d41ab73f876cacfbdd8e09b48cc0309c541041550bba");
        let u = BigUint::from_bytes_be(b"2bf0d643e52e5e03edec5e060a6e2d57014425cbf7344f2846771ef22efffdfc");

        let verify_params = PlonkVerifierParams::<
                (), // Dummy Context
                <G1Affine as CurveAffine>::ScalarExt,
                <G1Affine as CurveAffine>::CurveExt,
                (), //Error
                FieldCode::<<G1Affine as CurveAffine>::ScalarExt>,
                PointCode::<G1Affine>,
            > {
            common: common_setup,
            params: params_preprocessed,
            commits: verify_commits,
            evals: verify_evals,
            beta: &bn_to_field(&beta),
            gamma: &bn_to_field(&gamma),
            alpha: &bn_to_field(&alpha),
            xi: &bn_to_field(&xi),
            v: &bn_to_field(&v),
            u: &bn_to_field(&u),
            sgate: &fc,
            pgate: &pc,
            _ctx: PhantomData,
            _error: PhantomData,
        };

        let mp = verify_params.batch_multi_open_proofs(&mut ()).unwrap();
        let wx = (mp.w_x).eval(&fc, &pc, &mut ());
        let wg = (mp.w_g).eval(&fc, &pc, &mut ());
        println!("wx is {:?}", wx);
        println!("wg is {:?}", wg);
        //TODO: Calculate and check the pairing  ...
    }

}
