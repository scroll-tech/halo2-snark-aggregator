use std::marker::PhantomData;

use crate::tests::systems::halo2::zkevm_test::zkevm_circuit::TestCircuit;
use crate::transcript::encode::Encode;
use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_aggregation_proofs_in_chip, CircuitProof, ProofData},
    },
};
use ark_std::{end_timer, start_timer};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    transcript::{Challenge255, PoseidonWrite},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;
use rand::thread_rng;

const K: u32 = 16;
const NPROOFS: usize = 2usize;

pub fn test_verify_aggregation_proof_in_chip<
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

    let msg = format!("Generate key for zkevm circuit");
    let start = start_timer!(|| msg);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let circuit = &[circuit];
    end_timer!(start);

    let mut n_instances: Vec<_> = vec![];
    let mut n_proof: Vec<_> = vec![];

    let instances: &[&[&[_]]] = &[&[]];

    for i in 0..NPROOFS {
        let mut transcript =
            PoseidonWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);

        let msg = format!("Create {} proof", i + 1);
        let start = start_timer!(|| msg);
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
        end_timer!(start);
        n_proof.push(proof);
        n_instances.push(
            instances
                .iter()
                .map(|l1| {
                    l1.iter()
                        .map(|l2| l2.iter().map(|c: &Fr| *c).collect::<Vec<Fr>>())
                        .collect::<Vec<Vec<Fr>>>()
                })
                .collect::<Vec<Vec<Vec<Fr>>>>(),
        );
    }

    let mut proof_data_list: Vec<
        ProofData<Bn256, _, PoseidonTranscriptRead<_, G1Affine, _, EncodeChip, 9usize, 8usize>>,
    > = vec![];
    for (i, instances) in n_instances.iter().enumerate() {
        let transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
            &n_proof[i][..],
            ctx,
            nchip,
            8usize,
            63usize,
        )
        .unwrap();

        proof_data_list.push(ProofData {
            instances,
            transcript,
            key: format!("p{}", i),
            _phantom: PhantomData,
        })
    }

    let params_verifier: &ParamsVerifierKZG<Bn256> = &params.verifier_params();

    let empty_vec = vec![];
    let mut transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &empty_vec[..],
        ctx,
        nchip,
        8usize,
        63usize,
    )
    .unwrap();
    let msg = format!("Verify aggretation proof");
    let start = start_timer!(|| msg);
    verify_aggregation_proofs_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        vec![CircuitProof {
            name: String::from("zkevm"),
            vk: pk.get_vk(),
            params: &params_verifier,
            proofs: proof_data_list,
        }],
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
    use halo2curves::bn256::Fr as Fp;

    #[test]
    fn test_zkevm_verify_aggreation_proof_in_chip_code() {
        let nchip = MockFieldChip::default();
        let schip = MockFieldChip::default();
        let pchip = MockEccChip::default();
        let ctx = &mut MockChipCtx::default();
        test_verify_aggregation_proof_in_chip::<
            MockFieldChip<Fp, Error>,
            MockFieldChip<Fp, Error>,
            MockEccChip<G1Affine, Error>,
            PoseidonEncode,
        >(&nchip, &schip, &pchip, ctx);
    }
}
