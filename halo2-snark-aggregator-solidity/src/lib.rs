pub(crate) mod chips;
pub(crate) mod code_generator;
pub(crate) mod transcript;
use crate::chips::{
    ecc_chip::SolidityEccChip, encode_chip::PoseidonEncode, scalar_chip::SolidityFieldChip,
};
use crate::code_generator::aggregate::aggregate;
use crate::code_generator::ctx::SolidityCodeGeneratorContext;
use crate::code_generator::linear_scan::memory_optimize;
use crate::transcript::codegen::CodegenTranscriptRead;
use code_generator::ctx::{CodeGeneratorCtx, G2Point, Statement};
use halo2_proofs::arithmetic::{BaseExt, Field};
use halo2_proofs::arithmetic::{CurveAffine, MultiMillerLoop};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use halo2_snark_aggregator_api::systems::halo2::verify::{
    assign_instance_commitment, verify_single_proof_no_eval,
};
use halo2_snark_aggregator_circuit::verify_circuit::{load_instances, Halo2VerifierCircuit};
use log::info;
use num_bigint::BigUint;
use std::io::Cursor;
use tera::{Context, Tera};

fn render_verifier_sol_template<C: CurveAffine>(
    args: CodeGeneratorCtx,
    template_folder: std::path::PathBuf,
) -> String {
    let path = format!(
        "{}/*",
        template_folder
            .as_path()
            .canonicalize()
            .unwrap()
            .to_str()
            .unwrap()
    );
    let tera = Tera::new(&path).unwrap();
    let mut ctx = Context::new();
    let mut opcodes = vec![];
    let mut incremental_ident = 0u64;
    let mut equations = vec![];
    for s in args.assignments {
        equations.append(&mut s.to_solidity_string(&mut opcodes, &mut incremental_ident));
    }
    equations.append(&mut Statement::opcodes_to_solidity_string(&mut opcodes));

    ctx.insert("wx", &(args.wx).to_typed_string());
    ctx.insert("wg", &(args.wg).to_typed_string());
    ctx.insert("statements", &equations);
    ctx.insert("target_circuit_s_g2_x0", &args.target_circuit_s_g2.x.0.to_str_radix(10));
    ctx.insert("target_circuit_s_g2_x1", &args.target_circuit_s_g2.x.1.to_str_radix(10));
    ctx.insert("target_circuit_s_g2_y0", &args.target_circuit_s_g2.y.0.to_str_radix(10));
    ctx.insert("target_circuit_s_g2_y1", &args.target_circuit_s_g2.y.1.to_str_radix(10));
    ctx.insert("target_circuit_n_g2_x0", &args.target_circuit_n_g2.x.0.to_str_radix(10));
    ctx.insert("target_circuit_n_g2_x1", &args.target_circuit_n_g2.x.1.to_str_radix(10));
    ctx.insert("target_circuit_n_g2_y0", &args.target_circuit_n_g2.y.0.to_str_radix(10));
    ctx.insert("target_circuit_n_g2_y1", &args.target_circuit_n_g2.y.1.to_str_radix(10));
    ctx.insert("verify_circuit_s_g2_x0", &args.verify_circuit_s_g2.x.0.to_str_radix(10));
    ctx.insert("verify_circuit_s_g2_x1", &args.verify_circuit_s_g2.x.1.to_str_radix(10));
    ctx.insert("verify_circuit_s_g2_y0", &args.verify_circuit_s_g2.y.0.to_str_radix(10));
    ctx.insert("verify_circuit_s_g2_y1", &args.verify_circuit_s_g2.y.1.to_str_radix(10));
    ctx.insert("verify_circuit_n_g2_x0", &args.verify_circuit_n_g2.x.0.to_str_radix(10));
    ctx.insert("verify_circuit_n_g2_x1", &args.verify_circuit_n_g2.x.1.to_str_radix(10));
    ctx.insert("verify_circuit_n_g2_y0", &args.verify_circuit_n_g2.y.0.to_str_radix(10));
    ctx.insert("verify_circuit_n_g2_y1", &args.verify_circuit_n_g2.y.1.to_str_radix(10));
    ctx.insert("memory_size", &args.memory_size);
    ctx.insert("absorbing_length", &args.absorbing_length);
    tera.render("verifier.sol", &ctx)
        .expect("failed to render template")
}

pub fn g2field_to_bn<F: BaseExt>(f: &F) -> (BigUint, BigUint) {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    (
        BigUint::from_bytes_le(&bytes[32..64]),
        BigUint::from_bytes_le(&bytes[..32]),
    )
}

pub(crate) fn get_xy_from_g2point<E: MultiMillerLoop>(point: E::G2Affine) -> G2Point {
    let coordinates = point.coordinates();
    let x = coordinates
        .map(|v| v.x().clone())
        .unwrap_or(<E::G2Affine as CurveAffine>::Base::zero());
    let y = coordinates
        .map(|v| v.y().clone())
        .unwrap_or(<E::G2Affine as CurveAffine>::Base::zero());
    // let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());
    let x = g2field_to_bn(&x);
    let y = g2field_to_bn(&y);
    G2Point { x, y }
}

pub struct SolidityGenerate {
    pub target_params: Vec<u8>,
    pub verify_params: Vec<u8>,
    pub vk: Vec<u8>,
    // serialized instance
    pub instance: Vec<u8>,
    // serialized proof
    pub proof: Vec<u8>,
}

impl SolidityGenerate {
    pub fn call<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>>(
        &self,
        template_folder: std::path::PathBuf,
    ) -> String {
        let target_circuit_params = Params::<C>::read(Cursor::new(&self.target_params)).unwrap();
        let target_params = target_circuit_params.verifier::<E>(4).unwrap();
        let target_circuit_s_g2 = get_xy_from_g2point::<E>(target_params.s_g2);
        let target_circuit_n_g2 = get_xy_from_g2point::<E>(-target_params.g2);

        let verify_circuit_params = Params::<C>::read(Cursor::new(&self.verify_params)).unwrap();
        let verify_circuit_vk = {
            VerifyingKey::<C>::read::<_, Halo2VerifierCircuit<'_, E>>(
                &mut Cursor::new(&self.vk),
                &verify_circuit_params,
            )
            .unwrap()
        };
        let verify_circuit_instance = load_instances::<E>(&self.instance);
        let verify_params = verify_circuit_params.verifier::<E>(4).unwrap();

        let nchip = &SolidityFieldChip::new();
        let schip = nchip;
        let pchip = &SolidityEccChip::new();
        let ctx = &mut SolidityCodeGeneratorContext::new();

        let mut transcript =
            CodegenTranscriptRead::<_, C, _, PoseidonEncode<_>, 9usize, 8usize>::new(
                &self.proof[..],
                ctx,
                schip,
                8usize,
                33usize,
            )
            .unwrap();

        let verify_circuit_instance1: Vec<Vec<&[E::Scalar]>> = verify_circuit_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[E::Scalar]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        ctx.enter_instance();
        let assigned_instances = assign_instance_commitment(
            ctx,
            schip,
            pchip,
            &verify_circuit_instance2[..],
            &verify_circuit_vk,
            &verify_params,
        )
        .unwrap();
        ctx.exit_instance();

        let proof = verify_single_proof_no_eval(
            ctx,
            nchip,
            schip,
            pchip,
            assigned_instances,
            &verify_circuit_vk,
            &verify_params,
            &mut transcript,
            "".to_owned(),
        )
        .unwrap();

        let one = schip.assign_one(ctx).unwrap();

        let (left_s, left_e) = proof.w_x.eval::<_, _>(ctx, schip, pchip, &one).unwrap();
        let (right_s, right_e) = proof.w_g.eval::<_, _>(ctx, schip, pchip, &one).unwrap();

        let generator = pchip.assign_one(ctx).unwrap();
        let left = match left_e {
            None => left_s,
            Some(eval) => {
                let s = pchip.scalar_mul(ctx, &eval, &generator).unwrap();
                pchip.add(ctx, &left_s, &s).unwrap()
            }
        };
        let right = match right_e {
            None => right_s,
            Some(eval) => {
                let s = pchip.scalar_mul(ctx, &eval, &generator).unwrap();
                pchip.sub(ctx, &right_s, &s).unwrap()
            }
        };

        let verify_circuit_s_g2 = get_xy_from_g2point::<E>(verify_params.s_g2);
        let verify_circuit_n_g2 = get_xy_from_g2point::<E>(-verify_params.g2);

        let sol_ctx = CodeGeneratorCtx {
            wx: (*left.expr).clone(),
            wg: (*right.expr).clone(),
            target_circuit_s_g2,
            target_circuit_n_g2,
            verify_circuit_s_g2,
            verify_circuit_n_g2,
            assignments: ctx.statements.clone(),
            memory_size: ctx.memory_offset,
            absorbing_length: if ctx.absorbing_offset > ctx.max_absorbing_offset {
                ctx.absorbing_offset
            } else {
                ctx.max_absorbing_offset
            },
        };

        let sol_ctx: CodeGeneratorCtx = memory_optimize(sol_ctx);
        let sol_ctx: CodeGeneratorCtx = aggregate(sol_ctx);

        let template = render_verifier_sol_template::<C>(sol_ctx, template_folder.clone());
        info!("generate solidity succeeds");

        template
    }
}
