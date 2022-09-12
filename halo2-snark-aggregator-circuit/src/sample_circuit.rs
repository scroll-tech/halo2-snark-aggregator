use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::{create_proof, keygen_pk};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::PoseidonRead;
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_proofs::{plonk::Circuit, poly::commitment::Params};
use halo2curves::group::ff::PrimeField;
use halo2curves::pairing::{Engine, MultiMillerLoop};
use rand_core::OsRng;
use std::fmt::Debug;
use std::io::Write;

use crate::fs::load_target_circuit_params;
use crate::fs::load_target_circuit_vk;

pub trait TargetCircuit<E: MultiMillerLoop> {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;
    const PARAMS_NAME: &'static str;
    const READABLE_VKEY: bool;

    type Circuit: Circuit<<E as Engine>::Scalar> + Default;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<<E as Engine>::Scalar>>);
    fn load_instances(buf: &[u8]) -> Vec<Vec<Vec<<E as Engine>::Scalar>>>;
}

pub fn sample_circuit_setup<E: MultiMillerLoop + Debug, CIRCUIT: TargetCircuit<E>>(
    mut folder: std::path::PathBuf,
) {
    // TODO: Do not use setup in production
    let params = ParamsKZG::<E>::unsafe_setup(CIRCUIT::TARGET_CIRCUIT_K);

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

pub fn sample_circuit_random_run<E: MultiMillerLoop + Debug, CIRCUIT: TargetCircuit<E>>(
    mut folder: std::path::PathBuf,
    circuit: CIRCUIT::Circuit,
    instances: &[&[E::Scalar]],
    index: usize,
) {
    let params = load_target_circuit_params::<E, CIRCUIT>(&mut folder);

    let vk = load_target_circuit_vk::<E, CIRCUIT>(&mut folder, &params);
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    // let instances: &[&[&[C::Scalar]]] = &[&[&[constant * a.square() * b.square()]]];
    let instances: &[&[&[_]]] = &[instances];
    let mut transcript = PoseidonWrite::<_, E::G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        instances,
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    {
        folder.push(format!(
            "sample_circuit_proof_{}{}.data",
            CIRCUIT::NAME,
            index
        ));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        fd.write_all(&proof).unwrap();
    }

    {
        folder.push(format!(
            "sample_circuit_instance_{}{}.data",
            CIRCUIT::NAME,
            index
        ));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        instances.iter().for_each(|l1| {
            l1.iter().for_each(|l2| {
                l2.iter().for_each(|c: &E::Scalar| {
                    fd.write_all(c.to_repr().as_ref()).unwrap();
                })
            })
        });
    }

    let strategy = SingleStrategy::new(&params);
    let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);
    halo2_proofs::plonk::verify_proof::<_, VerifierGWC<_>, _, _, _>(
        &params,
        pk.get_vk(),
        strategy,
        instances,
        &mut transcript,
    )
    .unwrap();
}
