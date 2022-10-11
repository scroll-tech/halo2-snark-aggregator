use crate::{sample_circuit::TargetCircuit, verify_circuit::Halo2VerifierCircuit};
use halo2_proofs::{
    arithmetic::CurveAffine,
    plonk::{keygen_vk, VerifyingKey},
    poly::{
        commitment::{CommitmentScheme, Params},
        kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
    },
};
use halo2curves::{
    bn256::{Bn256, Fr, G1Affine},
    pairing::MultiMillerLoop,
};
use halo2curves::{group::ff::PrimeField, pairing::Engine};
use std::{
    fmt::Debug,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

pub fn read_file(folder: &mut PathBuf, filename: &str) -> Vec<u8> {
    let mut buf = vec![];

    folder.push(filename);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn write_file(folder: &mut PathBuf, filename: &str, buf: &Vec<u8>) {
    folder.push(filename);
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write_all(buf).unwrap();
}

pub fn read_target_circuit_params<E: MultiMillerLoop, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.params", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_params<E: MultiMillerLoop + Debug, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
) -> ParamsKZG<E> {
    KZGCommitmentScheme::<E>::read_params(&mut Cursor::new(
        &read_target_circuit_params::<E, Circuit>(&mut folder.clone()),
    ))
    .unwrap()
}

pub fn read_target_circuit_vk<E: MultiMillerLoop, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.vkey", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_vk<E: MultiMillerLoop + Debug, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
    params: &ParamsKZG<E>,
) -> VerifyingKey<E::G1Affine> {
    if Circuit::READABLE_VKEY {
        VerifyingKey::<E::G1Affine>::read::<_, Circuit::Circuit, E, _>(
            &mut Cursor::new(&read_target_circuit_vk::<E, Circuit>(&mut folder.clone())),
            &load_target_circuit_params::<E, Circuit>(&mut folder.clone()),
        )
        .unwrap()
    } else {
        let circuit = Circuit::Circuit::default();

        keygen_vk::<E::G1Affine, _, Circuit::Circuit>(params, &circuit)
            .expect("keygen_vk should not fail")
    }
}

pub fn load_target_circuit_instance<Circuit: TargetCircuit<Bn256>>(
    folder: &mut PathBuf,
    index: usize,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_instance_{}{}.data", Circuit::NAME, index),
    )
}

pub fn load_target_circuit_proof<Circuit: TargetCircuit<Bn256>>(
    folder: &mut PathBuf,
    index: usize,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_proof_{}{}.data", Circuit::NAME, index),
    )
}

pub fn read_verify_circuit_params(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.params")
}

pub fn get_params_cached<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
>(
    k: u32,
) -> Params<C> {
    let mut params_folder = std::path::PathBuf::new();
    params_folder.push("../params");
    if !params_folder.is_dir() {
        std::fs::create_dir(params_folder.as_path())
            .expect("params folder creation should not fail");
    }
    params_folder.push(format!("bn254_{}.params", k));

    let path = params_folder.as_path();

    println!("params path: {:?}", path);
    if Path::exists(path) {
        println!("read params from {:?}", path);
        let mut fd = std::fs::File::open(path).unwrap();
        Params::<C>::read(&mut fd).unwrap()
    } else {
        let params = Params::<C>::unsafe_setup::<E>(k);
        println!("write params to {:?}", path);
        let mut fd = std::fs::File::create(path).unwrap();
        params.write(&mut fd).unwrap();
        params
    }
}

pub fn load_verify_circuit_params(folder: &mut PathBuf) -> ParamsKZG<Bn256> {
    KZGCommitmentScheme::<Bn256>::read_params(&mut Cursor::new(&read_verify_circuit_params(
        &mut folder.clone(),
    )))
    .unwrap()
}

pub fn read_verify_circuit_vk(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.vkey")
}

pub fn load_verify_circuit_vk(folder: &mut PathBuf) -> VerifyingKey<G1Affine> {
    folder.push("verify_circuit.vkey");
    let mut f = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    VerifyingKey::<G1Affine>::read::<_, Halo2VerifierCircuit<'_, Bn256>, Bn256, _>(
        &mut Cursor::new(&read_verify_circuit_vk(&mut folder.clone())),
        &load_verify_circuit_params(&mut folder.clone()),
    )
    .unwrap()
}

// currently assuming N in Halo2VerifierCircuits is 1
pub fn load_verify_circuit_vk_cached_params(
    folder: &mut PathBuf,
    verify_circuit_params: &Params<G1Affine>,
) -> VerifyingKey<G1Affine> {
    folder.push("verify_circuit.vkey");
    let mut f = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    VerifyingKey::<G1Affine>::read::<_, Halo2VerifierCircuits<'_, Bn256, 1>>(
        &mut f,
        verify_circuit_params,
    )
    .unwrap()
}

pub fn read_verify_circuit_instance(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_instance.data")
}

fn load_instances<E: MultiMillerLoop>(buf: &[u8]) -> Vec<Vec<Vec<E::Scalar>>> {
    let mut ret = vec![];
    let cursor = &mut std::io::Cursor::new(buf);
    let mut scalar_bytes = <<E as Engine>::Scalar as PrimeField>::Repr::default();

    while cursor.read_exact(scalar_bytes.as_mut()).is_ok() {
        ret.push(<E::Scalar as PrimeField>::from_repr(scalar_bytes).unwrap())
    }

    vec![vec![ret]]
}

pub fn load_verify_circuit_instance(folder: &mut PathBuf) -> Vec<Vec<Vec<Fr>>> {
    let instances = read_verify_circuit_instance(&mut folder.clone());
    load_instances::<Bn256>(&instances)
}

pub fn load_verify_circuit_proof(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_proof.data")
}

pub fn write_verify_circuit_params(folder: &mut PathBuf, verify_circuit_params: &ParamsKZG<Bn256>) {
    folder.push("verify_circuit.params");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    verify_circuit_params.write(&mut fd).unwrap();
}

pub fn write_verify_circuit_vk(folder: &mut PathBuf, verify_circuit_vk: &VerifyingKey<G1Affine>) {
    folder.push("verify_circuit.vkey");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    verify_circuit_vk.write(&mut fd).unwrap();
}

pub fn write_verify_circuit_instance(
    folder: &mut PathBuf,
    buf: &[<G1Affine as CurveAffine>::ScalarExt],
) {
    folder.push("verify_circuit_instance.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    buf.iter().for_each(|x| {
        fd.write_all(x.to_repr().as_ref()).unwrap();
    });
}

pub fn write_verify_circuit_final_pair(folder: &mut PathBuf, pair: &(G1Affine, G1Affine, Vec<Fr>)) {
    folder.push("verify_circuit_final_pair.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write_all(pair.0.x.to_repr().as_ref()).unwrap();
    fd.write_all(pair.0.y.to_repr().as_ref()).unwrap();
    fd.write_all(pair.1.x.to_repr().as_ref()).unwrap();
    fd.write_all(pair.1.y.to_repr().as_ref()).unwrap();

    pair.2.iter().for_each(|scalar| {
        fd.write_all(scalar.to_repr().as_ref()).unwrap();
    })
}

pub fn write_verify_circuit_proof(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verify_circuit_proof.data", buf)
}

pub fn write_verify_circuit_solidity(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verifier.sol", buf)
}

pub fn load_verify_circuit_degree() -> u32 {
    let mut folder = std::path::PathBuf::new();
    folder.push("../halo2-snark-aggregator-circuit/src/configs");
    folder.push("verify_circuit.config");
    let params_str = std::fs::read_to_string(folder.as_path())
        .expect(format!("{} file should exist", folder.to_str().unwrap()).as_str());
    let params: crate::verify_circuit::Halo2VerifierCircuitConfigParams =
        serde_json::from_str(params_str.as_str()).unwrap();
    params.degree
}
