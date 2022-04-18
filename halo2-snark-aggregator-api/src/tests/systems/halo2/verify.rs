#[cfg(test)]
mod tests {
    use crate::{
        arith::ecc::ArithEccChip,
        systems::halo2::verify::VerifierParamsBuilder,
        tests::{
            arith::{ecc::MockEccChip, field::MockFieldChip},
            systems::halo2::test_circuit::{test_circuit_builder, MyCircuit},
        },
        transcript::read::TranscriptRead,
    };
    use group::ff::Field;
    use halo2_proofs::{
        dev::MockProver,
        pairing::bn256::Fr as Fp,
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Challenge255, PoseidonRead, PoseidonWrite},
    };
    use pairing_bn256::bn256::{Bn256, G1Affine, G1};
    use rand::SeedableRng;
    use rand_core::OsRng;
    use rand_pcg::Pcg32;

    const K: u32 = 10;

    #[test]
    fn test_verifier_params_builder() {
        let constant = Fp::from(7);
        let a = Fp::from(2);
        let b = Fp::from(3);
        let c = constant * a.square() * b.square();
        let circuit = test_circuit_builder();
        let public_inputs_size = 1;
        let instances: &[&[&[_]]] = &[&[&[c]]];

        let params = Params::<G1Affine>::unsafe_setup_rng::<Bn256, _>(K, Pcg32::seed_from_u64(0));
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], instances, OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof = transcript.finalize();

        let params_verifier: &ParamsVerifier<Bn256> = &params.verifier(public_inputs_size).unwrap();
        let strategy = SingleVerifier::new(params_verifier);

        let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);

        verify_proof(
            params_verifier,
            pk.get_vk(),
            strategy,
            instances,
            &mut transcript,
        )
        .unwrap();

        /*
         * TODO
        let mut transcript = PoseidonTranscriptRead::<
            _,
            G1Affine,
            RegionAux<'_, '_, Fr>,
            AssignedValue<Fr>,
            AssignedPoint<G1Affine, Fr>,
            Error,
            FiveColumnBaseGate<Fr>,
            NativeEccCircuit<'_, G1Affine>,
            PoseidonEncode,
            9usize,
            8usize,
        >::new(&proof[..], r, base_gate, 8usize, 33usize)
        .unwrap();

        let _ = VerifierParamsBuilder {
            ctx: &mut (),
            nchip: &MockFieldChip::default(),
            schip: &MockFieldChip::default(),
            pchip: &MockEccChip::default(),
            xi: Fp::zero(),
            instances: instances,
            vk: &vk,
            params: &params_verifier,
            transcript: &mut transcript,
        };
        */
    }
}
