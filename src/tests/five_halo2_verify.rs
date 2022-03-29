use crate::circuits::five::integer_circuit::FiveColumnIntegerCircuit;
use crate::circuits::native_ecc_circuit::NativeEccCircuit;
use crate::field::bn_to_field;
use crate::gates::base_gate::RegionAux;
use crate::gates::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::gates::five::range_gate::FiveColumnRangeGate;
use crate::gates::range_gate::RangeGateConfig;
use crate::verify::halo2::tests::mul_circuit_builder::MyCircuit;
use crate::verify::halo2::verify::VerifierParams;
use group::ff::Field;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use num_bigint::BigUint;
use pairing_bn256::bn256::{Bn256, Fq, Fr, G1Affine};
use rand::SeedableRng;
use rand_pcg::Pcg32;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    Normal,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Normal
    }
}

#[derive(Clone)]
struct TestFiveColumnHalo2VerifyCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnHalo2VerifyCircuitCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
    _phantom_n: PhantomData<Fr>,
}

impl TestFiveColumnHalo2VerifyCircuitCircuit<G1Affine> {
    fn random() -> Fr {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        Fr::random(rng)
    }

    fn setup_test(
        &self,
        ecc_gate: &NativeEccCircuit<'_, G1Affine>,
        base_gate: &FiveColumnBaseGate<Fr>,
        r: &mut RegionAux<'_, '_, Fr>,
    ) -> Result<(), Error> {
        use crate::verify::halo2::verify::IVerifierParams;
        use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk};
        use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite};

        let circuit = MyCircuit::<Fr> {
            a: Some(Fr::from(1)),
            b: Some(Fr::from(1)),
        };

        let u = bn_to_field::<Fr>(&BigUint::from_bytes_be(
            b"2bf0d643e52e5e03edec5e060a6e2d57014425cbf7344f2846771ef22efffdfc",
        ));

        const K: u32 = 5;
        let public_inputs_size = 1;
        let params: Params<G1Affine> =
            Params::<G1Affine>::unsafe_setup_rng::<Bn256, _>(K, Pcg32::seed_from_u64(42));
        let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let instance = Fr::one();
        create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&[&[instance]]],
            Pcg32::seed_from_u64(42),
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

        let params = VerifierParams::from_transcript(
            base_gate,
            ecc_gate,
            r,
            u,
            &[&[&[instance]]],
            pk.get_vk() as &VerifyingKey<G1Affine>,
            &params_verifier,
            &mut transcript,
        )?;

        let _queries = params.queries(base_gate, r)?;

        Ok(())
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

impl Circuit<Fr> for TestFiveColumnHalo2VerifyCircuitCircuit<G1Affine> {
    type Config = TestFiveColumnHalo2VerifyCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<Fr>::configure(meta);
        let range_gate_config = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::configure(
            meta,
            &base_gate_config,
        );
        TestFiveColumnHalo2VerifyCircuitConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
        let range_gate = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_gate = FiveColumnIntegerCircuit::new(&range_gate);
        let ecc_gate = NativeEccCircuit::new(&integer_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut aux = RegionAux::new(&mut region, &mut base_offset);
                let r = &mut aux;
                let round = 1;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Normal => self.setup_test(&ecc_gate, &base_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_halo2_verify() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnHalo2VerifyCircuitCircuit::<G1Affine> {
        test_case: TestCase::Normal,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
