use clap::Parser;
use halo2_proofs::arithmetic::{BaseExt, CurveAffine};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_snark_aggregator_circuit::sample_circuit::{
    sample_circuit_random_run, sample_circuit_setup,
};
use halo2_snark_aggregator_circuit::verify_circuit::{CreateProof, Setup, VerifyCheck};
use halo2_snark_aggregator_solidity::SolidityGenerate;
use log::info;
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};
use std::io::{Read, Write};
use std::path::PathBuf;

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

fn write_verify_circuit_instance(
    folder: &mut PathBuf,
    buf: &Vec<<G1Affine as CurveAffine>::ScalarExt>,
) {
    folder.push("verify_circuit_instance.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    buf.iter().for_each(|x| x.write(&mut fd).unwrap());
}

fn write_verify_circuit_final_pair(folder: &mut PathBuf, pair: &(G1Affine, G1Affine, Vec<Fr>)) {
    folder.push("verify_circuit_final_pair.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    pair.0.x.write(&mut fd).unwrap();
    pair.0.y.write(&mut fd).unwrap();
    pair.1.x.write(&mut fd).unwrap();
    pair.1.y.write(&mut fd).unwrap();

    pair.2.iter().for_each(|scalar| {
        scalar.write(&mut fd).unwrap();
    })
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

pub fn builder<
    TargetCircuit: halo2_snark_aggregator_circuit::sample_circuit::TargetCircuit<G1Affine, Bn256>,
    const VERIFY_CIRCUIT_K: u32,
>() {
    let args = Cli::parse();
    let folder = args.folder_path;
    let template_folder = args.template_path;

    env_logger::init();
    rayon::ThreadPoolBuilder::new()
        .num_threads(24)
        .build_global()
        .unwrap();

    if args.command == "sample_setup" {
        sample_circuit_setup::<G1Affine, Bn256, TargetCircuit>(folder.clone());
    }

    if args.command == "sample_run" {
        for i in 0..args.nproofs as usize {
            /*
            let constant = <G1Affine as CurveAffine>::ScalarExt::from(7);
            let a = <G1Affine as CurveAffine>::ScalarExt::random(OsRng);
            let b = <G1Affine as CurveAffine>::ScalarExt::random(OsRng);
            let circuit = sample_circuit_builder(a, b);
            let instances: &[&[<G1Affine as CurveAffine>::ScalarExt]] =
                &[&[constant * a.square() * b.square()]];
            */
            let (circuit, instances) = TargetCircuit::instance_builder();

            sample_circuit_random_run::<G1Affine, Bn256, TargetCircuit>(
                folder.clone(),
                circuit,
                &instances
                    .iter()
                    .map(|instance| &instance[..])
                    .collect::<Vec<_>>()[..],
                i,
            );
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

        let (params, vk) = request.call::<_, Bn256, TargetCircuit, VERIFY_CIRCUIT_K>();

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

        let (final_pair, instance, _instance_commitments, proof, proof_be) =
            request.call::<_, Bn256, TargetCircuit>();

        write_verify_circuit_instance(&mut folder.clone(), &instance);
        write_verify_circuit_proof(&mut folder.clone(), &proof);
        write_verify_circuit_proof_be(&mut folder.clone(), &proof_be);
        write_verify_circuit_final_pair(&mut folder.clone(), &final_pair);
    }

    if args.command == "verify_check" {
        let request = VerifyCheck {
            params: load_verify_circuit_params(&mut folder.clone()),
            vk: load_verify_circuit_vk(&mut folder.clone()),
            instance: load_verify_circuit_instance(&mut folder.clone()),
            proof: load_verify_circuit_proof(&mut folder.clone()),
            nproofs: args.nproofs,
        };

        request.call::<_, Bn256, TargetCircuit>().unwrap();

        info!("verify check succeed")
    }

    if args.command == "verify_solidity" {
        let request = SolidityGenerate {
            target_params: load_target_circuit_params(&mut folder.clone()),
            verify_params: load_verify_circuit_params(&mut folder.clone()),
            vk: load_verify_circuit_vk(&mut folder.clone()),
            instance: load_verify_circuit_instance(&mut folder.clone()),
            proof: load_verify_circuit_proof(&mut folder.clone()),
            nproofs: args.nproofs,
        };

        let sol = request.call::<_, Bn256, TargetCircuit>(template_folder.unwrap());

        write_verify_circuit_solidity(&mut folder.clone(), &Vec::<u8>::from(sol.as_bytes()));
    }
}
