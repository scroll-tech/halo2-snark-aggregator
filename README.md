# halo2-snark-aggregator
halo2 verify circuit for plonk and halo2 verify schemes.

## Base Trait
This repo is supposed to be used as a convenient tool for the following purpose:
* Generating verifying code, circuit and contract by providing different implementation of a few unified traits for a single verify implementation. 
* Constructing prove aggregators that can aggregate multi halo2 proofs.
* Generating contract for the verification of the proof of the aggregator.

## Simple use case

* Generate single verify circuit for a precompiled circuit:

```
        let mut transcript = PoseidonRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

        let params = VerifierParams::from_transcript(
            base_gate,
            ecc_gate,
            r,
            u,
            &[&[&[instance]]],
            pk.get_vk() as &VerifyingKey<G1Affine>,
            &params_verifier,
            &mut transcript,
        )?;

        let guard = params.batch_multi_open_proofs(r, base_gate, ecc_gate)?;

        let (left_s, left_e) = guard.w_x.eval(base_gate, ecc_gate, r)?;
        let (right_s, right_e) = guard.w_g.eval(base_gate, ecc_gate, r)?;
```

* Generate single verify code for a precompiled circuit:

```
        let mut transcript = PoseidonRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);
        let sgate = FieldCode::<Fp>::default();
        let pgate = PointCode::<G1Affine>::default();
        let params = VerifierParams::from_transcript(
            sgate,
            pgate,
            r,
            u,
            &[&[&[instance]]],
            pk.get_vk() as &VerifyingKey<G1Affine>,
            &params_verifier,
            &mut transcript,
        )?;

        let guard = params.batch_multi_open_proofs(r, base_gate, ecc_gate)?;

        let (left_s, left_e) = guard.w_x.eval(base_gate, ecc_gate, r)?;
        let (right_s, right_e) = guard.w_g.eval(base_gate, ecc_gate, r)?;
```

## Proof Aggregator:
Suppose we have a bunch of proof of circuit C.
1. Generate multiple proofs P(1) of C under poseidon hash config.
1. Applying this tool to generate verify circuit VC of C under poseidon hash config and get multiopen proofs by
    * w_x_i, w_g_i = VC.batch_multi_open_proofs(...)
    * batch w_x_i and w_g_i to get w_x and w_g
3. Prove VC under sha256 hash config and get its proof P.
4. Apply this tool to generate verify contract of VC and get the final contract that can verify the final aggregated proof P.
