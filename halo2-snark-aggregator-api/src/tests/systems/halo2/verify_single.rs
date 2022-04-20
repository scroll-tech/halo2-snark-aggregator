use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{transcript::PoseidonTranscriptRead, verify::verify_single_proof_in_chip},
    tests::{
        systems::halo2::{test_circuit::test_circuit_builder},
    }, transcript::encode::Encode,
};
use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::{
    pairing::bn256::Fr as Fp,
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Challenge255, PoseidonWrite},
};
use pairing_bn256::bn256::{Bn256, G1Affine};
use rand::SeedableRng;
use rand_pcg::Pcg32;
use rand_xorshift::XorShiftRng;

const K: u32 = 10;

pub fn test_verify_single_proof_in_chip<ScalarChip, NativeChip, EccChip, EncodeChip: Encode<EccChip>>(
    nchip: &NativeChip,
    schip: &ScalarChip,
    pchip: &EccChip,
    ctx: &mut <EccChip as ArithCommonChip>::Context,
) where
    NativeChip: ArithFieldChip<Field = <G1Affine as CurveAffine>::ScalarExt>,
    ScalarChip: ArithFieldChip<Field = <G1Affine as CurveAffine>::ScalarExt>,
    EccChip: ArithEccChip<
        Point = G1Affine,
        Scalar = ScalarChip::Field,
        Native = NativeChip::Field,
        NativeChip = NativeChip,
        ScalarChip = ScalarChip,
        Error = halo2_proofs::plonk::Error,
    >,
{
    fn random() -> Fp {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        Fp::random(rng)
    }

    let circuit = test_circuit_builder(random(), random());
    let params = Params::<G1Affine>::unsafe_setup_rng::<Bn256, _>(K, Pcg32::seed_from_u64(0));
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

    let public_inputs_size = 1;

    let constant = Fp::from(7);
    let a = random();
    let b = random();
    let c = constant * a.square() * b.square();
    let instances: &[&[&[_]]] = &[&[&[c]]];
    let circuit = test_circuit_builder(a, b);
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        instances,
        Pcg32::seed_from_u64(0),
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let params_verifier: &ParamsVerifier<Bn256> = &params.verifier(public_inputs_size).unwrap();

    let mut transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &proof[..],
        ctx,
        &nchip,
        8usize,
        33usize,
    )
    .unwrap();

    verify_single_proof_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        Fp::zero(),
        instances,
        pk.get_vk(),
        params_verifier,
        &mut transcript,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        arith::{ecc::MockEccChip, field::MockFieldChip},
        systems::halo2::transcript_encode::PoseidonEncode,
    };
    use halo2_proofs::plonk::Error;

    #[test]
    fn test_verify_single_proof_in_chip_code() {
        let nchip = MockFieldChip::default();
        let schip = MockFieldChip::default();
        let pchip = MockEccChip::default();
        let ctx = &mut ();
        test_verify_single_proof_in_chip::<
            MockFieldChip<Fp, Error>,
            MockFieldChip<Fp, Error>,
            MockEccChip<G1Affine, Error>,
            PoseidonEncode,
        >(&nchip, &schip, &pchip, ctx);
    }
}
