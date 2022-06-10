use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_snark_aggregator_circuit::sample_circuit::{
    sample_circuit_random_run, sample_circuit_setup,
};
use halo2_snark_aggregator_circuit::verify_circuit::{CreateProof, Setup, VerifyCheck};
use halo2_snark_aggregator_solidity::SolidityGenerate;
use log::info;
use num_bigint::BigUint;
use pairing_bn256::bn256::{Bn256, Fq, G1Affine};

#[derive(Parser)]
struct Cli {
    // TODO: replace it with subcommand
    #[clap(short, long)]
    command: String,
    #[clap(short, long)]
    nproofs: usize,
    #[clap(short, long, parse(from_os_str))]
    folder_path: std::path::PathBuf,
    #[clap(short, long, parse(from_os_str))]
    template_path: Option<std::path::PathBuf>,
}

fn read_file(folder: &mut PathBuf, filename: &str) -> Vec<u8> {
    let mut buf = vec![];

    folder.push(filename);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    fd.read_to_end(&mut buf).unwrap();
    buf
}

fn write_file(folder: &mut PathBuf, filename: &str, buf: &Vec<u8>) {
    folder.push(filename);
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write(buf).unwrap();
}

fn load_target_circuit_params(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "sample_circuit.params")
}

fn load_target_circuit_vk(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "sample_circuit.vkey")
}

fn load_target_circuit_instance(folder: &mut PathBuf, index: usize) -> Vec<u8> {
    read_file(folder, &format!("sample_circuit_instance{}.data", index))
}

fn load_target_circuit_proof(folder: &mut PathBuf, index: usize) -> Vec<u8> {
    read_file(folder, &format!("sample_circuit_proof{}.data", index))
}

fn load_verify_circuit_params(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.params")
}

fn load_verify_circuit_vk(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.vkey")
}

fn load_verify_circuit_instance(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_instance.data")
}

fn load_verify_circuit_proof(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_proof.data")
}

fn write_verify_circuit_params(folder: &mut PathBuf, verify_circuit_params: &Params<G1Affine>) {
    folder.push("verify_circuit.params");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    verify_circuit_params.write(&mut fd).unwrap();
}

fn write_verify_circuit_vk(folder: &mut PathBuf, verify_circuit_vk: &VerifyingKey<G1Affine>) {
    folder.push("verify_circuit.vkey");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    verify_circuit_vk.write(&mut fd).unwrap();
}

fn field_to_bn(f: &Fq) -> BigUint {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    BigUint::from_bytes_le(&bytes[..])
}

fn write_verify_circuit_instance_commitments_be(folder: &mut PathBuf, buf: &Vec<Vec<G1Affine>>) {
    folder.push("verify_circuit_instance_commitments_be.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    for v in buf {
        for commitment in v {
            let x = field_to_bn(&commitment.x);
            let y = field_to_bn(&commitment.y);
            let be = x
                .to_bytes_be()
                .into_iter()
                .chain(y.to_bytes_be().into_iter())
                .collect::<Vec<_>>();
            fd.write_all(&be).unwrap()
        }
    }
}

fn write_verify_circuit_instance(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verify_circuit_instance.data", buf)
}

fn write_verify_circuit_proof(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verify_circuit_proof.data", buf)
}

fn write_verify_circuit_proof_be(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verify_circuit_proof_be.data", buf)
}

fn write_verify_circuit_solidity(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verifier.sol", buf)
}

pub fn main() {
    let args = Cli::parse();
    let folder = args.folder_path;
    let template_folder = args.template_path;

    env_logger::init();
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
        let instances = (0..args.nproofs)
            .map(|index| load_target_circuit_instance(&mut folder.clone(), index))
            .collect::<Vec<_>>();

        let proofs = (0..args.nproofs)
            .map(|index| load_target_circuit_proof(&mut folder.clone(), index))
            .collect::<Vec<_>>();

        let request = Setup {
            params: load_target_circuit_params(&mut folder.clone()),
            vk: load_target_circuit_vk(&mut folder.clone()),
            instances,
            proofs,
            nproofs: args.nproofs,
        };

        let (params, vk) = request.call::<_, Bn256>();

        write_verify_circuit_params(&mut folder.clone(), &params);
        write_verify_circuit_vk(&mut folder.clone(), &vk);
    }

    if args.command == "verify_run" {
        let instances = (0..args.nproofs)
            .map(|index| load_target_circuit_instance(&mut folder.clone(), index))
            .collect::<Vec<_>>();

        let proofs = (0..args.nproofs)
            .map(|index| load_target_circuit_proof(&mut folder.clone(), index))
            .collect::<Vec<_>>();

        let request = CreateProof {
            target_circuit_params: load_target_circuit_params(&mut folder.clone()),
            target_circuit_vk: load_target_circuit_vk(&mut folder.clone()),
            verify_circuit_params: load_verify_circuit_params(&mut folder.clone()),
            verify_circuit_vk: load_verify_circuit_vk(&mut folder.clone()),
            template_instances: instances.clone(),
            template_proofs: proofs.clone(),
            instances: instances,
            proofs: proofs,
            nproofs: args.nproofs,
        };

        let (instance_commitments, instance, proof, proof_be) = request.call::<_, Bn256>();

        write_verify_circuit_instance_commitments_be(&mut folder.clone(), &instance_commitments);
        write_verify_circuit_instance(&mut folder.clone(), &instance);
        write_verify_circuit_proof(&mut folder.clone(), &proof);
        write_verify_circuit_proof_be(&mut folder.clone(), &proof_be);
    }

    if args.command == "verify_check" {
        let request = VerifyCheck {
            params: load_verify_circuit_params(&mut folder.clone()),
            vk: load_verify_circuit_vk(&mut folder.clone()),
            instance: load_verify_circuit_instance(&mut folder.clone()),
            proof: load_verify_circuit_proof(&mut folder.clone()),
        };

        request.call::<_, Bn256>().unwrap();

        info!("verify check succeed")
    }

    if args.command == "verify_solidity" {
        let request = SolidityGenerate {
            params: load_verify_circuit_params(&mut folder.clone()),
            vk: load_verify_circuit_vk(&mut folder.clone()),
            instance: load_verify_circuit_instance(&mut folder.clone()),
            proof: load_verify_circuit_proof(&mut folder.clone()),
        };

        let sol = request.call::<_, Bn256>(template_folder.unwrap());

        write_verify_circuit_solidity(&mut folder.clone(), &Vec::<u8>::from(sol.as_bytes()));
    }
}
