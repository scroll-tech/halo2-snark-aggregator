#[cfg(feature = "benches")]
#[cfg(test)]
mod benches;

#[macro_export]
macro_rules! zkaggregate {
    ( $n:expr, $coherent:expr, $( $x:ident ),+ ) => {
        mod zkcli {
            $(
                use crate::$x;
            )*
            use clap::Parser;
            use halo2_proofs::arithmetic::{BaseExt, CurveAffine, MultiMillerLoop};
            use halo2_proofs::plonk::{Circuit, VerifyingKey};
            use halo2_proofs::poly::commitment::Params;
            use halo2_snark_aggregator_circuit::fs::*;
            use halo2_snark_aggregator_circuit::sample_circuit::{
                sample_circuit_random_run, sample_circuit_setup, TargetCircuit,
            };
            use halo2_snark_aggregator_circuit::verify_circuit::{
                CreateProof, Halo2VerifierCircuit, MultiCircuitsCreateProof,
                MultiCircuitsSetup, Setup, SingleProofWitness, VerifyCheck, SingleProofPair,
            };
            use halo2_snark_aggregator_solidity::{SolidityGenerate, MultiCircuitSolidityGenerate};
            use log::info;
            use pairing_bn256::bn256::{Bn256, Fr, G1Affine};
            use std::io::{Cursor, Read, Write};
            use std::marker::PhantomData;
            use std::path::PathBuf;
            use std::rc::Rc;
            use paste::paste;


            #[derive(Parser)]
            struct Cli {
                // TODO: replace it with subcommand
                #[clap(short, long)]
                command: String,
                #[clap(short, long, parse(from_os_str))]
                folder_path: std::path::PathBuf,
                #[clap(short, long, parse(from_os_str))]
                template_path: Option<std::path::PathBuf>,
            }

            paste! {
                pub struct CliBuilder {
                    args: Cli,
                    folder: PathBuf,
                    template_folder: Option<PathBuf>,
                    verify_circuit_k: u32,
                }
            }

            fn env_init() {
                env_logger::init();
                rayon::ThreadPoolBuilder::new()
                    .num_threads(24)
                    .build_global()
                    .unwrap();
            }

            paste! {
                pub fn builder(verify_circuit_k: u32) -> CliBuilder {
                    env_init();

                    let args = Cli::parse();
                    let folder = args.folder_path.clone();
                    let template_folder = args.template_path.clone();

                    CliBuilder {
                        args,
                        folder,
                        template_folder,
                        verify_circuit_k,
                    }
                }
            }

            impl CliBuilder {
                fn compute_verify_public_input_size(&self) -> usize {
                    4
                    $(
                        + <$x as TargetCircuit<G1Affine, Bn256>>::N_PROOFS * <$x as TargetCircuit<G1Affine, Bn256>>::PUBLIC_INPUT_SIZE
                    )*
                }

                fn dispatch_sample_setup(&self) {
                    $(
                        sample_circuit_setup::<G1Affine, Bn256, $x>(self.folder.clone());
                    )*
                }

                fn sample_run_one_circuit<SingleCircuit: TargetCircuit<G1Affine, Bn256>>(&self) {
                    for i in 0..SingleCircuit::N_PROOFS {
                        let (circuit, instances) = SingleCircuit::instance_builder();

                        sample_circuit_random_run::<G1Affine, Bn256, SingleCircuit>(
                            self.folder.clone(),
                            circuit,
                            &instances
                                .iter()
                                .map(|instance| &instance[..])
                                .collect::<Vec<_>>()[..],
                            i,
                        );
                    }
                }

                fn dispatch_sample_run(&self) {
                    $(
                        self.sample_run_one_circuit::<$x>();
                    )*
                }

                fn dispatch_verify_setup(&self) {
                    let setup: [Setup<_, _>; $n] = [
                        $(
                            Setup::new::<$x, _>(&self.folder, &<$x as TargetCircuit<G1Affine, Bn256>>::load_instances),
                        )*
                    ];

                    let request = MultiCircuitsSetup::<_, _, $n> {
                        setups: setup,
                        coherent: $coherent
                    };

                    let (params, vk) = request.call(self.verify_circuit_k);

                    write_verify_circuit_params(&mut self.folder.clone(), &params);
                    write_verify_circuit_vk(&mut self.folder.clone(), &vk);
                }

                fn dispatch_verify_run(&self) {
                    let target_circuit_proofs: [CreateProof<_, _>; $n] = [
                        $(
                            CreateProof::new::<$x, _>(&self.folder, &<$x as TargetCircuit<G1Affine, Bn256>>::load_instances),
                        )*
                    ];

                    let request = MultiCircuitsCreateProof::<_, _, $n> {
                        target_circuit_proofs,
                        verify_circuit_params: &load_verify_circuit_params(&mut self.folder.clone()),
                        verify_circuit_vk: load_verify_circuit_vk(&mut self.folder.clone()),
                        coherent: $coherent
                    };

                    let (_, final_pair, instance, proof) = request.call();

                    write_verify_circuit_instance(&mut self.folder.clone(), &instance);
                    write_verify_circuit_proof(&mut self.folder.clone(), &proof);
                    write_verify_circuit_final_pair(&mut self.folder.clone(), &final_pair);
                }

                fn dispatch_verify_check(&self) {
                    let request = VerifyCheck::<G1Affine>::new(&self.folder, self.compute_verify_public_input_size());
                    request.call::<Bn256>().unwrap();

                    info!("verify check succeed")
                }

                fn dispatch_verify_solidity(&self) {
                    let target_circuits_params: [SolidityGenerate<_>; $n] = [
                        $(
                            SolidityGenerate::new::<$x>(&self.folder),
                        )*
                    ];

                    let request = MultiCircuitSolidityGenerate::<G1Affine, $n> {
                        target_circuits_params,
                        verify_params: &load_verify_circuit_params(&mut self.folder.clone()),
                        verify_vk: &load_verify_circuit_vk(&mut self.folder.clone()),
                        verify_circuit_instance: load_verify_circuit_instance(
                            &mut self.folder.clone(),
                        ),
                        proof: load_verify_circuit_proof(&mut self.folder.clone()),
                        verify_public_inputs_size: self.compute_verify_public_input_size(),
                    };

                    let sol = request.call::<Bn256>(self.template_folder.clone().unwrap());

                    write_verify_circuit_solidity(
                        &mut self.folder.clone(),
                        &Vec::<u8>::from(sol.as_bytes()),
                    );
                }

                pub fn run(&self) {
                    if self.args.command == "sample_setup" {
                        self.dispatch_sample_setup();
                    }

                    if self.args.command == "sample_run" {
                        self.dispatch_sample_run();
                    }

                    if self.args.command == "verify_setup" {
                        self.dispatch_verify_setup();
                    }

                    if self.args.command == "verify_run" {
                        self.dispatch_verify_run();
                    }

                    if self.args.command == "verify_check" {
                        self.dispatch_verify_check();
                    }

                    if self.args.command == "verify_solidity" {
                        self.dispatch_verify_solidity();
                    }
                }
            }
        }
    };
}
