pub mod chips;
pub mod sample_circuit;
pub mod verify_circuit;

#[cfg(test)]
mod tests;

use clap::Parser;
use pairing_bn256::bn256::{Bn256, G1Affine};

/// Search for a pattern in a file and display the lines that contain it.
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

    if args.command == "sample_setup" {
        sample_circuit::sample_circuit_setup::<G1Affine, Bn256>(folder.clone());
    }

    if args.command == "sample_run" {
        for i in 0..args.nproofs as usize {
            sample_circuit::sample_circuit_random_run::<G1Affine, Bn256>(folder.clone(), i);
        }
    }

    if args.command == "verify_setup" {
        verify_circuit::verify_circuit_setup::<G1Affine, Bn256>(folder.clone(), args.nproofs)
    }

    if args.command == "verify_run" {
        verify_circuit::verify_circuit_run::<G1Affine, Bn256>(folder.clone(), args.nproofs)
    }

    if args.command == "verify_check" {
        verify_circuit::verify_circuit_check::<G1Affine, Bn256>(folder.clone(), args.nproofs)
    }
}
