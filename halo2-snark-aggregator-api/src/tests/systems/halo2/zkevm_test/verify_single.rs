use std::marker::PhantomData;

use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_single_proof_in_chip, CircuitProof, ProofData},
    },
    tests::systems::halo2::zkevm_test::zkevm_circuit::TestCircuit,
    transcript::encode::Encode,
};
use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
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
use rand::{rngs::OsRng, thread_rng};

const K: u32 = 16;

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
    let circuit = TestCircuit::<Fr>::default();
    let msg = format!("Setup zkevm circuit with degree = {}", K);
    let start = start_timer!(|| msg);
    let params = ParamsKZG::<Bn256>::setup(K, &mut test_rng);

    end_timer!(start);

    let msg = "Generate key for zkevm circuit".to_string();
    let start = start_timer!(|| msg);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let circuit = &[circuit];
    end_timer!(start);

    let instances: &[&[&[_]]] = &[&[]];

    let mut transcript = PoseidonWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _>(
        &params,
        &pk,
        circuit,
        instances,
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
            .map(|x| x.iter().map(|y| y.to_vec()).collect::<Vec<Vec<Fr>>>())
            .collect::<Vec<Vec<Vec<Fr>>>>(),
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

    let msg = "Verify proof".to_string();
    let start = start_timer!(|| msg);
    verify_single_proof_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        &mut CircuitProof {
            name: String::from("zkevm"),
            vk: pk.get_vk(),
            params: params_verifier,
            proofs: vec![pdata],
        },
        &mut transcript,
    )
    .unwrap();
    end_timer!(start);
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
    fn test_zkevm_verify_single_proof_in_chip_code() {
        let nchip = MockFieldChip::default();
        let schip = MockFieldChip::default();
        let pchip = MockEccChip::default();
        let ctx = &mut MockChipCtx::default();
        test_verify_single_proof_in_chip::<
            MockFieldChip<Fr, Error>,
            MockFieldChip<Fr, Error>,
            MockEccChip<G1Affine, Error>,
            PoseidonEncode,
        >(&nchip, &schip, &pchip, ctx);
    }
}
