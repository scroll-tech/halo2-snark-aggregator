use clap::Parser;
use halo2_snark_aggregator_circuit::sample_circuit::{
    sample_circuit_random_run, sample_circuit_setup,
};
use halo2_snark_aggregator_circuit::verify_circuit::{
    verify_circuit_check, verify_circuit_run, verify_circuit_setup,
};
use pairing_bn256::bn256::{Bn256, G1Affine};

#[derive(Parser)]
struct Cli {
    // TODO: replace it with subcommand
    #[clap(short, long)]
    command: String,
    #[clap(short, long)]
    nproofs: usize,
    #[clap(short, long, parse(from_os_str))]
    folder_path: std::path::PathBuf,
}

pub fn main() {
    let args = Cli::parse();
    let folder = args.folder_path;

    rayon::ThreadPoolBuilder::new()
        .num_threads(24)
        .build_global()
        .unwrap();

    if args.command == "sample_setup" {
        sample_circuit_setup::<G1Affine, Bn256>(folder.clone());
    }

    if args.command == "sample_run" {
        for i in 0..args.nproofs as usize {
            sample_circuit_random_run::<G1Affine, Bn256>(folder.clone(), i);
        }
    }

    if args.command == "verify_setup" {
        verify_circuit_setup::<G1Affine, Bn256>(folder.clone(), args.nproofs)
    }

    if args.command == "verify_run" {
        verify_circuit_run::<G1Affine, Bn256>(folder.clone(), args.nproofs)
    }

    if args.command == "verify_check" {
        verify_circuit_check::<G1Affine, Bn256>(folder.clone(), args.nproofs)
    }
}
