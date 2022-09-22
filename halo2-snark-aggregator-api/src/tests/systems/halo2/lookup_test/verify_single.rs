use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_single_proof_in_chip, CircuitProof, ProofData},
    },
    tests::systems::halo2::lookup_test::test_circuit::test_circuit_builder,
    transcript::encode::Encode,
};
use halo2_proofs::{
    arithmetic::CurveAffine,
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::ProverGWC,
        },
    },
};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    transcript::{Challenge255, PoseidonWrite},
};
use halo2curves::bn256::Fr as Fp;
use halo2curves::bn256::{Bn256, G1Affine};
use rand::{rngs::OsRng, thread_rng};
use std::marker::PhantomData;

const K: u32 = 6;

pub fn test_verify_single_proof_in_chip<
    ScalarChip,
    NativeChip,
    EccChip,
    EncodeChip: Encode<EccChip>,
>(
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
    let mut test_rng = thread_rng();
    let circuit = test_circuit_builder();
    let params = ParamsKZG::<Bn256>::setup(K, &mut test_rng);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let odd_lookup = vec![
        Fp::from(1),
        Fp::from(3),
        Fp::from(5),
        Fp::from(7),
        Fp::from(9),
    ];
    /*
    let even_lookup = vec![
        Fp::from(0),
        Fp::from(2),
        Fp::from(4),
        Fp::from(6),
        Fp::from(8),
    ];
    */
    let instances: &[&[&[_]]] = &[&[&odd_lookup[..]]];

    let mut transcript = PoseidonWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        instances,
        //            Pcg32::seed_from_u64(0),
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let params_verifier: &ParamsVerifierKZG<Bn256> = params.verifier_params();

    let transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &proof[..],
        ctx,
        nchip,
        8usize,
        63usize,
    )
    .unwrap();

    let pdata = ProofData {
        instances: &instances
            .iter()
            .map(|x| x.iter().map(|y| y.to_vec()).collect::<Vec<Vec<Fp>>>())
            .collect::<Vec<Vec<Vec<Fp>>>>(),
        transcript,
        key: format!("p{}", 0),
        _phantom: PhantomData,
    };

    let mut transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &proof[..],
        ctx,
        nchip,
        8usize,
        63usize,
    )
    .unwrap();

    verify_single_proof_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        &mut CircuitProof {
            name: String::from("lookup_test_single"),
            vk: pk.get_vk(),
            params: params_verifier,
            proofs: vec![pdata],
        },
        &mut transcript,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{
        arith::{
            ecc::MockEccChip,
            field::{MockChipCtx, MockFieldChip},
        },
        transcript_encode::PoseidonEncode,
    };
    use halo2_proofs::plonk::Error;

    #[test]
    fn test_verify_single_proof_in_chip_code() {
        let nchip = MockFieldChip::default();
        let schip = MockFieldChip::default();
        let pchip = MockEccChip::default();
        let ctx = &mut MockChipCtx::default();
        test_verify_single_proof_in_chip::<
            MockFieldChip<Fp, Error>,
            MockFieldChip<Fp, Error>,
            MockEccChip<G1Affine, Error>,
            PoseidonEncode,
        >(&nchip, &schip, &pchip, ctx);
    }
}
