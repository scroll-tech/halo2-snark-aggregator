use std::marker::PhantomData;

use crate::systems::halo2::verify::CircuitProof;
use crate::tests::systems::halo2::add_mul_test::test_circuit::test_circuit_builder;
use crate::transcript::encode::Encode;
use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_aggregation_proofs_in_chip, ProofData},
    },
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
    fn random() -> Fp {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        Fp::random(rng)
    }

    let circuit_template = test_circuit_builder(Fp::zero(), Fp::zero());
    let params = Params::<G1Affine>::unsafe_setup::<Bn256>(K);
    let vk = keygen_vk(&params, &circuit_template).expect("keygen_vk should not fail");

    let public_inputs_size = 1;
    let params_verifier: &ParamsVerifier<Bn256> = &params.verifier(public_inputs_size).unwrap();

    let mut n_instances: Vec<_> = vec![];
    let mut n_proof: Vec<_> = vec![];

    let constant = Fp::from(7);
    for _ in 0..NPROOFS {
        let vk = keygen_vk(&params, &circuit_template).expect("keygen_vk should not fail");
        let a = random();
        let b = random();
        let c = constant * a.square() * b.square();
        let circuit = test_circuit_builder(a, b);
        let instances = vec![vec![vec![c]]];
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        let instances1: Vec<Vec<&[Fp]>> = instances
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let instances2: Vec<&[&[Fp]]> = instances1.iter().map(|x| &x[..]).collect();

        create_proof(
            &params,
            &pk,
            &[circuit],
            &instances2[..],
            Pcg32::seed_from_u64(0),
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

    let empty_vec = vec![];
    let mut transcript = PoseidonTranscriptRead::<_, G1Affine, _, EncodeChip, 9usize, 8usize>::new(
        &empty_vec[..],
        ctx,
        nchip,
        8usize,
        33usize,
    )
    .unwrap();
    verify_aggregation_proofs_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        vec![CircuitProof {
            name: String::from("test_circuit_add_mul"),
            vk: &vk,
            params: &params_verifier,
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
        arith::{ecc::MockEccChip, field::{MockFieldChip, MockChipCtx}},
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
