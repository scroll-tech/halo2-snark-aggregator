use super::super::chips::{
    ecc_chip::EccChip, encode_chip::PoseidonEncodeChip, scalar_chip::ScalarChip,
};
use halo2_ecc_circuit_lib::{
    chips::native_ecc_chip::NativeEccChip,
    five::{
        base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig},
        config::{MUL_COLUMNS, VAR_COLUMNS},
        integer_chip::FiveColumnIntegerChip,
        range_gate::FiveColumnRangeGate,
    },
    gates::{
        base_gate::{BaseGateConfig, Context},
        range_gate::RangeGateConfig,
    },
};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2_snark_aggregator_api::tests::systems::halo2::lookup_test::{
    verify_aggregation::test_verify_aggregation_proof_in_chip,
    verify_single::test_verify_single_proof_in_chip,
};
use halo2curves::bn256::{Fq, Fr, G1Affine};
use std::marker::PhantomData;

enum TestCase {
    Single,
    Aggregation,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Single
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

#[derive(Clone)]
struct TestFiveColumnNativeEccChipConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnNativeEccChipCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
    _phantom_n: PhantomData<C::ScalarExt>,
}

impl TestFiveColumnNativeEccChipCircuit<G1Affine> {
    fn setup_single_proof_verify_test<'a>(
        &self,
        base_gate_config: BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>,
        ecc_chip: &NativeEccChip<G1Affine>,
        ctx: &mut Context<'a, Fr>,
    ) -> Result<(), Error> {
        let native_base_gate = FiveColumnBaseGate::new(base_gate_config.clone());
        let scalar_base_gate = FiveColumnBaseGate::new(base_gate_config);

        test_verify_single_proof_in_chip::<
            ScalarChip<_>,
            ScalarChip<_>,
            EccChip<G1Affine>,
            PoseidonEncodeChip<_>,
        >(
            &ScalarChip::new(&native_base_gate),
            &ScalarChip::new(&scalar_base_gate),
            &EccChip::new(ecc_chip),
            ctx,
        );

        Ok(())
    }

    fn setup_aggregation_proof_verify_test<'a>(
        &self,
        base_gate_config: BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>,
        ecc_chip: &NativeEccChip<G1Affine>,
        ctx: &mut Context<'a, Fr>,
    ) -> Result<(), Error> {
        let native_base_gate = FiveColumnBaseGate::new(base_gate_config.clone());
        let scalar_base_gate = FiveColumnBaseGate::new(base_gate_config);

        test_verify_aggregation_proof_in_chip::<
            ScalarChip<_>,
            ScalarChip<_>,
            EccChip<G1Affine>,
            PoseidonEncodeChip<_>,
        >(
            &ScalarChip::new(&native_base_gate),
            &ScalarChip::new(&scalar_base_gate),
            &EccChip::new(ecc_chip),
            ctx,
        );

        Ok(())
    }
}

impl Circuit<Fr> for TestFiveColumnNativeEccChipCircuit<G1Affine> {
    type Config = TestFiveColumnNativeEccChipConfig;
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
        TestFiveColumnNativeEccChipConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config.clone());
        let range_gate = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_gate = FiveColumnIntegerChip::new(&range_gate);
        let ecc_gate = NativeEccChip::new(&integer_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "",
            |region| {
                let base_offset = 0usize;
                let mut aux = Context::new(region, base_offset);
                let r = &mut aux;
                let round = 1;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Single => self.setup_single_proof_verify_test(
                            config.base_gate_config.clone(),
                            &ecc_gate,
                            r,
                        ),
                        TestCase::Aggregation => self.setup_aggregation_proof_verify_test(
                            config.base_gate_config.clone(),
                            &ecc_gate,
                            r,
                        ),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    #[test]
    fn test_five_column_single_proof_verify() {
        //const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
        const K: u32 = 22;
        let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
            test_case: TestCase::Single,
            _phantom_w: PhantomData,
            _phantom_n: PhantomData,
        };
        let prover = match MockProver::run(K, &chip, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_five_column_aggregation_proof_verify() {
        //const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
        const K: u32 = 22;
        let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
            test_case: TestCase::Aggregation,
            _phantom_w: PhantomData,
            _phantom_n: PhantomData,
        };
        let prover = match MockProver::run(K, &chip, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
