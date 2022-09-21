use crate::tests::systems::halo2::lookup_test::test_circuit::test_circuit_builder;
use crate::transcript::encode::Encode;
use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_aggregation_proofs_in_chip, CircuitProof, ProofData},
    },
};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    transcript::{Challenge255, PoseidonWrite},
};
use halo2curves::bn256::Fr as Fp;
use halo2curves::bn256::{Bn256, G1Affine};
use rand::rngs::OsRng;
use rand::thread_rng;
use std::marker::PhantomData;

const K: u32 = 6;
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
    let circuit_template = test_circuit_builder();
    let params = ParamsKZG::<Bn256>::setup(K, &mut test_rng);
    let vk = keygen_vk(&params, &circuit_template).expect("keygen_vk should not fail");

    let params_verifier: &ParamsVerifierKZG<Bn256> = params.verifier_params();

    let mut n_instances: Vec<_> = vec![];
    let mut n_proof: Vec<_> = vec![];

    for _ in 0..NPROOFS {
        let vk = keygen_vk(&params, &circuit_template).expect("keygen_vk should not fail");
        let circuit = test_circuit_builder();
        let odd_lookup = vec![
            Fp::from(1),
            Fp::from(3),
            Fp::from(5),
            Fp::from(7),
            Fp::from(9),
        ];
        let instances = vec![vec![odd_lookup]];
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
        let mut transcript =
            PoseidonWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);

        let instances1: Vec<Vec<&[Fp]>> = instances
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let instances2: Vec<&[&[Fp]]> = instances1.iter().map(|x| &x[..]).collect();

        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &instances2[..],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        n_proof.push(proof);
        n_instances.push(instances);
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

    let empty_vec = vec![];
    let mut transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &empty_vec[..],
        ctx,
        nchip,
        8usize,
        63usize,
    )
    .unwrap();

    verify_aggregation_proofs_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        vec![CircuitProof {
            name: String::from("lookup_test"),
            vk: &vk,
            params: params_verifier,
            proofs: proof_data_list,
        }],
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
    fn test_verify_aggreation_proof_in_chip_code() {
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
