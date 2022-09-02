use halo2_proofs::{
    arithmetic::{BaseExt, CurveAffine, MultiMillerLoop},
    plonk::{keygen_vk, VerifyingKey},
    poly::commitment::Params,
};
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};

use crate::{sample_circuit::TargetCircuit, verify_circuit::Halo2VerifierCircuit};
use std::{
    io::{Cursor, Read, Write},
    path::PathBuf,
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

    fd.write(buf).unwrap();
}

pub fn read_target_circuit_params<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    Circuit: TargetCircuit<C, E>,
>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.params", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_params<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    Circuit: TargetCircuit<C, E>,
>(
    folder: &mut PathBuf,
) -> Params<C> {
    Params::<C>::read(Cursor::new(&read_target_circuit_params::<C, E, Circuit>(
        &mut folder.clone(),
    )))
    .unwrap()
}

pub fn read_target_circuit_vk<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    Circuit: TargetCircuit<C, E>,
>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.vkey", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_vk<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    Circuit: TargetCircuit<C, E>,
>(
    folder: &mut PathBuf,
    params: &Params<C>,
) -> VerifyingKey<C> {
    if Circuit::READABLE_VKEY {
        VerifyingKey::<C>::read::<_, Circuit::Circuit>(
            &mut Cursor::new(&read_target_circuit_vk::<C, E, Circuit>(
                &mut folder.clone(),
            )),
            &load_target_circuit_params::<C, E, Circuit>(&mut folder.clone()),
        )
        .unwrap()
    } else {
        let circuit = Circuit::Circuit::default();
        let vk =
            keygen_vk::<C, Circuit::Circuit>(params, &circuit).expect("keygen_vk should not fail");
        vk
    }
}

pub fn load_target_circuit_instance<Circuit: TargetCircuit<G1Affine, Bn256>>(
    folder: &mut PathBuf,
    index: usize,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_instance_{}{}.data", Circuit::NAME, index),
    )
}

pub fn load_target_circuit_proof<Circuit: TargetCircuit<G1Affine, Bn256>>(
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

pub fn load_verify_circuit_params(folder: &mut PathBuf) -> Params<G1Affine> {
    Params::<G1Affine>::read(Cursor::new(&read_verify_circuit_params(
        &mut folder.clone(),
    )))
    .unwrap()
}

pub fn read_verify_circuit_vk(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.vkey")
}

pub fn load_verify_circuit_vk(folder: &mut PathBuf) -> VerifyingKey<G1Affine> {
    VerifyingKey::<G1Affine>::read::<_, Halo2VerifierCircuit<'_, Bn256>>(
        &mut Cursor::new(&read_verify_circuit_vk(&mut folder.clone())),
        &load_verify_circuit_params(&mut folder.clone()),
    )
    .unwrap()
}

pub fn read_verify_circuit_instance(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_instance.data")
}

fn load_instances<E: MultiMillerLoop>(buf: &[u8]) -> Vec<Vec<Vec<E::Scalar>>> {
    let mut ret = vec![];
    let cursor = &mut std::io::Cursor::new(buf);

    while let Ok(a) = <E::Scalar as BaseExt>::read(cursor) {
        ret.push(a);
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

pub fn write_verify_circuit_params(folder: &mut PathBuf, verify_circuit_params: &Params<G1Affine>) {
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
    buf: &Vec<<G1Affine as CurveAffine>::ScalarExt>,
) {
    folder.push("verify_circuit_instance.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    buf.iter().for_each(|x| x.write(&mut fd).unwrap());
}

pub fn write_verify_circuit_final_pair(folder: &mut PathBuf, pair: &(G1Affine, G1Affine, Vec<Fr>)) {
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

pub fn write_verify_circuit_proof(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verify_circuit_proof.data", buf)
}

pub fn write_verify_circuit_solidity(folder: &mut PathBuf, buf: &Vec<u8>) {
    write_file(folder, "verifier.sol", buf)
}
