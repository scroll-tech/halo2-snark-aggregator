use super::super::chips::{
    ecc_chip::EccChip, encode_chip::PoseidonEncodeChip, scalar_chip::ScalarChip,
};
use halo2_ecc::{
    fields::fp::FpConfig,
    gates::{Context, ContextParams},
};
use halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2_snark_aggregator_api::tests::systems::halo2::add_mul_test::{
    verify_aggregation::test_verify_aggregation_proof_in_chip,
    verify_single::test_verify_single_proof_in_chip,
};
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

#[derive(Clone)]
struct TestConfig {
    base_field_config: FpConfig<Fr, Fq>,
}

#[derive(Default)]
struct TestCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
    _phantom_n: PhantomData<C::ScalarExt>,
}

impl TestCircuit<G1Affine> {
    fn setup_single_proof_verify_test<'a>(
        &self,
        base_field_config: &FpConfig<Fr, Fq>,
        ctx: &mut Context<'a, Fr>,
    ) -> Result<(), Error> {
        test_verify_single_proof_in_chip::<
            ScalarChip<_>,
            ScalarChip<_>,
            EccChip<G1Affine>,
            PoseidonEncodeChip<_>,
        >(
            &ScalarChip::new(&base_field_config.range.gate),
            &ScalarChip::new(&base_field_config.range.gate),
            &EccChip::new(&base_field_config),
            ctx,
        );

        Ok(())
    }

    fn setup_aggregation_proof_verify_test<'a>(
        &self,
        base_field_config: &FpConfig<Fr, Fq>,
        ctx: &mut Context<'a, Fr>,
    ) -> Result<(), Error> {
        test_verify_aggregation_proof_in_chip::<
            ScalarChip<_>,
            ScalarChip<_>,
            EccChip<G1Affine>,
            PoseidonEncodeChip<_>,
        >(
            &ScalarChip::new(&base_field_config.range.gate),
            &ScalarChip::new(&base_field_config.range.gate),
            &EccChip::new(&base_field_config),
            ctx,
        );

        Ok(())
    }
}

impl Circuit<Fr> for TestCircuit<G1Affine> {
    type Config = TestConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params_str = include_str!("../configs/verify_circuit.config");
        let params: crate::verify_circuit::Halo2VerifierCircuitConfigParams =
            serde_json::from_str(params_str).unwrap();

        println!("{}", serde_json::to_string_pretty(&params).unwrap());

        let base_field_config = FpConfig::configure(
            meta,
            params.strategy,
            params.num_advice,
            params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_base::utils::modulus::<Fq>(),
            0,
            20,
        );
        TestConfig { base_field_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.base_field_config.load_lookup_table(&mut layouter)?;

        let using_simple_floor_planner = true;
        let mut first_pass = true;

        layouter.assign_region(
            || "base",
            |region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }

                println!("starting real stuff");
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: config.base_field_config.range.gate.num_advice,
                        using_simple_floor_planner,
                        first_pass,
                    },
                );
                let ctx = &mut aux;

                let round = 1;
                for _i in 0..round {
                    match self.test_case {
                        TestCase::Single => {
                            println!("single");
                            self.setup_single_proof_verify_test(&config.base_field_config, ctx)
                        }
                        TestCase::Aggregation => {
                            println!("Aggregation");
                            self.setup_aggregation_proof_verify_test(&config.base_field_config, ctx)
                        }
                    }?;
                }
                let (const_rows, total_fixed, _lookup_rows) =
                    config.base_field_config.finalize(ctx)?;

                let advice_rows = ctx.advice_rows.iter();
                println!(
                    "maximum rows used by an advice column: {}",
                    advice_rows.clone().max().or(Some(&0)).unwrap(),
                );
                println!(
                    "minimum rows used by an advice column: {}",
                    advice_rows.clone().min().or(Some(&usize::MAX)).unwrap(),
                );
                let total_cells = advice_rows.sum::<usize>();
                println!("total cells used: {}", total_cells);
                println!(
                    "cells used in special lookup column: {}",
                    ctx.cells_to_lookup.len()
                );
                println!("maximum rows used by a fixed column: {}", const_rows);

                println!("Suggestions:");
                let degree = config.base_field_config.range.lookup_bits + 1;
                println!(
                    "Have you tried using {} advice columns?",
                    (total_cells + (1 << degree) - 1) / (1 << degree)
                );
                println!(
                    "Have you tried using {} lookup columns?",
                    (ctx.cells_to_lookup.len() + (1 << degree) - 1) / (1 << degree)
                );
                println!(
                    "Have you tried using {} fixed columns?",
                    (total_fixed + (1 << degree) - 1) / (1 << degree)
                );
                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    // use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Bn256;
    use halo2_proofs::plonk::keygen_vk;

    use crate::fs::get_params_cached;

    use super::*;

    #[test]
    fn test_mul_add_single_proof_verify() {
        let k = crate::fs::load_verify_circuit_degree();

        let chip = TestCircuit::<G1Affine> {
            test_case: TestCase::Single,
            _phantom_w: PhantomData,
            _phantom_n: PhantomData,
        };

        /*
        let prover = match MockProver::run(k, &chip, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
        println!("mock prover OK");
        */

        let general_params: ParamsKZG<Bn256> = get_params_cached::<G1Affine, Bn256>(k);
        keygen_vk(&general_params, &chip).expect("keygen_vk should not fail");
    }

    #[test]
    fn test_mul_add_aggregation_proof_verify() {
        let k = crate::fs::load_verify_circuit_degree();

        let chip = TestCircuit::<G1Affine> {
            test_case: TestCase::Aggregation,
            _phantom_w: PhantomData,
            _phantom_n: PhantomData,
        };

        let general_params: ParamsKZG<Bn256> = get_params_cached::<G1Affine, Bn256>(k);
        keygen_vk(&general_params, &chip).expect("keygen_vk should not fail");
        /*
        let prover = match MockProver::run(k, &chip, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
        */
    }
}
