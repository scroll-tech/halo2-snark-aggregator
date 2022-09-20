use ark_std::{end_timer, start_timer};
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::{create_proof, keygen_pk};
use halo2_proofs::transcript::PoseidonRead;
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_proofs::{
    arithmetic::{CurveAffine, MultiMillerLoop},
    plonk::Circuit,
    poly::commitment::Params,
};
use rand_core::OsRng;
use std::io::Write;

use crate::fs::load_target_circuit_vk;
use crate::fs::{get_params_cached, load_target_circuit_params};

pub trait TargetCircuit<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>> {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;
    const PARAMS_NAME: &'static str;
    const READABLE_VKEY: bool;

    type Circuit: Circuit<C::ScalarExt> + Default;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<C::ScalarExt>>);
    fn load_instances(buf: &Vec<u8>) -> Vec<Vec<Vec<C::ScalarExt>>>;
}

pub fn sample_circuit_setup<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C>,
    CIRCUIT: TargetCircuit<C, E>,
>(
    mut folder: std::path::PathBuf,
) {
    // TODO: Do not use setup in production
    let params = Params::<C>::unsafe_setup::<E>(CIRCUIT::TARGET_CIRCUIT_K);

    let circuit = CIRCUIT::Circuit::default();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

    {
        folder.push(format!("sample_circuit_{}.params", CIRCUIT::PARAMS_NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        params.write(&mut fd).unwrap();
    }

    {
        folder.push(format!("sample_circuit_{}.vkey", CIRCUIT::PARAMS_NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        vk.write(&mut fd).unwrap();
    }
}

pub fn sample_circuit_random_run<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    CIRCUIT: TargetCircuit<C, E>,
>(
    mut folder: std::path::PathBuf,
    circuit: CIRCUIT::Circuit,
    instances: &[&[C::Scalar]],
    index: usize,
) {
    /*
    // reading vk does not work for all circuits
    let params = load_target_circuit_params::<C, E, CIRCUIT>(&mut folder);
    let vk = load_target_circuit_vk::<C, E, CIRCUIT>(&mut folder, &params);
    */
    let params = get_params_cached::<C, E>(CIRCUIT::TARGET_CIRCUIT_K);
    let empty_circuit = CIRCUIT::Circuit::default();

    let vk_time = start_timer!(|| format!("{} vk time", CIRCUIT::NAME));
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    end_timer!(vk_time);

    let pk_time = start_timer!(|| format!("{} target pk time", CIRCUIT::NAME));
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    end_timer!(pk_time);

    // let instances: &[&[&[C::Scalar]]] = &[&[&[constant * a.square() * b.square()]]];
    let instances: &[&[&[_]]] = &[instances];
    let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);
    let pf_time =  start_timer!(|| format!("{} proving time", CIRCUIT::NAME));
    create_proof(&params, &pk, &[circuit], instances, OsRng, &mut transcript)
        .expect("proof generation should not fail");
    let proof = transcript.finalize();
    end_timer!(pf_time);

    {
        folder.push(format!("sample_circuit_proof_{}{}.data", CIRCUIT::NAME, index));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        fd.write_all(&proof).unwrap();
    }

    {
        folder.push(format!("sample_circuit_instance_{}{}.data", CIRCUIT::NAME, index));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        instances.iter().for_each(|l1| {
            l1.iter().for_each(|l2| {
                l2.iter().for_each(|c: &C::ScalarExt| {
                    c.write(&mut fd).unwrap();
                })
            })
        });
    }

    let params = params.verifier::<E>(CIRCUIT::PUBLIC_INPUT_SIZE).unwrap();
    let strategy = halo2_proofs::plonk::SingleVerifier::new(&params);
    let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);
    halo2_proofs::plonk::verify_proof::<E, _, _, _>(
        &params,
        &pk.get_vk(),
        strategy,
        instances,
        &mut transcript,
    )
    .unwrap();
}
