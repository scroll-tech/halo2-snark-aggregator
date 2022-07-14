use std::marker::PhantomData;

use crate::tests::systems::halo2::zkevm_test::zkevm_circuit::TestCircuit;
use crate::transcript::encode::Encode;
use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_aggregation_proofs_in_chip, ProofData, CircuitProof},
    },
};
use ark_std::{end_timer, start_timer};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Challenge255, PoseidonWrite},
};
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;

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
    let circuit = TestCircuit::<Fr>::default();
    let msg = format!("Setup zkevm circuit with degree = {}", K);
    let start = start_timer!(|| msg);
    let general_params = Params::<G1Affine>::unsafe_setup::<Bn256>(K);
    end_timer!(start);

    let msg = format!("Generate key for zkevm circuit");
    let start = start_timer!(|| msg);
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&general_params, vk, &circuit).unwrap();
    let circuit = &[circuit];
    end_timer!(start);

    let mut n_instances: Vec<_> = vec![];
    let mut n_proof: Vec<_> = vec![];

    let instances: &[&[&[_]]] = &[&[]];

    for i in 0..NPROOFS {
        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        let msg = format!("Create {} proof", i + 1);
        let start = start_timer!(|| msg);
        create_proof(
            &general_params,
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
            33usize,
        )
        .unwrap();

        proof_data_list.push(ProofData {
            instances,
            transcript,
            key: format!("p{}", i),
            _phantom: PhantomData,
        })
    }

    let params_verifier: &ParamsVerifier<Bn256> =
        &general_params.verifier((K * 2) as usize).unwrap();

    let empty_vec = vec![];
    let mut transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &empty_vec[..],
        ctx,
        nchip,
        8usize,
        33usize,
    )
    .unwrap();
    let msg = format!("Verify aggretation proof");
    let start = start_timer!(|| msg);
    verify_aggregation_proofs_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        vec![CircuitProof {vk:pk.get_vk(), params:&params_verifier, proofs:proof_data_list}],
        &mut transcript,
    )
    .unwrap();
    end_timer!(start);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{
        arith::{ecc::MockEccChip, field::MockFieldChip},
        transcript_encode::PoseidonEncode,
    };
    use halo2_proofs::pairing::bn256::Fr as Fp;
    use halo2_proofs::plonk::Error;

    #[test]
    fn test_zkevm_verify_aggreation_proof_in_chip_code() {
        let nchip = MockFieldChip::default();
        let schip = MockFieldChip::default();
        let pchip = MockEccChip::default();
        let ctx = &mut ();
        test_verify_aggregation_proof_in_chip::<
            MockFieldChip<Fp, Error>,
            MockFieldChip<Fp, Error>,
            MockEccChip<G1Affine, Error>,
            PoseidonEncode,
        >(&nchip, &schip, &pchip, ctx);
    }
}
