use crate::arith::api::{ContextGroup, ContextRing};
use crate::hash::poseidon::Poseidon;
use group::ff::PrimeField;
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use halo2_proofs::plonk::Error;
use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;

pub trait TranscriptRead<
    C,
    S: Clone + Debug,
    P: Clone,
    Error,
    TS,
    TP,
    SGate: ContextGroup<C, S, S, TS, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, TP, Error>,
>
{
    fn read_point(&mut self, ctx: &mut C, sgate: &SGate, pgate: &PGate) -> Result<P, Error>;
    fn read_constant_point(
        &mut self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<P, Error>;
    fn read_constant_scalar(&mut self, ctx: &mut C, sgate: &SGate) -> Result<S, Error>;
    fn read_scalar(&mut self, ctx: &mut C, sgate: &SGate) -> Result<S, Error>;
    fn common_point(
        &mut self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
        p: &P,
    ) -> Result<(), Error>;
    fn common_scalar(&mut self, ctx: &mut C, sgate: &SGate, s: &S) -> Result<(), Error>;
    fn squeeze_challenge_scalar(&mut self, ctx: &mut C, sgate: &SGate) -> Result<S, Error>;
}

pub trait Encode<
    CTX,
    S: Clone + Debug,
    P: Clone,
    Error,
    TS: FieldExt,
    TP,
    SGate: ContextGroup<CTX, S, S, TS, Error> + ContextRing<CTX, S, S, Error>,
    PGate: ContextGroup<CTX, S, P, TP, Error>,
>
{
    fn encode_point(ctx: &mut CTX, sgate: &SGate, pgate: &PGate, v: &P) -> Result<Vec<S>, Error>;
    fn encode_scalar(ctx: &mut CTX, sgate: &SGate, v: &S) -> Result<Vec<S>, Error>;
}

pub struct PoseidonTranscriptRead<
    R: io::Read,
    C: CurveAffine,
    CTX,
    S: Clone + Debug,
    P: Clone,
    Error,
    SGate: ContextGroup<CTX, S, S, C::ScalarExt, Error> + ContextRing<CTX, S, S, Error>,
    PGate: ContextGroup<CTX, S, P, C, Error>,
    E: Encode<CTX, S, P, Error, C::ScalarExt, C, SGate, PGate>,
    const T: usize,
    const RATE: usize,
> {
    hash: Poseidon<CTX, S, Error, C::ScalarExt, SGate, T, RATE>,
    reader: R,
    _phantom: PhantomData<((P, E), PGate)>,
}

impl<
        R: io::Read,
        C: CurveAffine,
        CTX,
        S: Clone + Debug,
        P: Clone,
        SGate: ContextGroup<CTX, S, S, C::ScalarExt, Error> + ContextRing<CTX, S, S, Error>,
        PGate: ContextGroup<CTX, S, P, C, Error>,
        E: Encode<CTX, S, P, Error, C::ScalarExt, C, SGate, PGate>,
        const T: usize,
        const RATE: usize,
    > PoseidonTranscriptRead<R, C, CTX, S, P, Error, SGate, PGate, E, T, RATE>
{
    pub fn new(
        reader: R,
        ctx: &mut CTX,
        sgate: &SGate,
        r_f: usize,
        r_p: usize,
    ) -> Result<PoseidonTranscriptRead<R, C, CTX, S, P, Error, SGate, PGate, E, T, RATE>, Error>
    {
        Ok(PoseidonTranscriptRead {
            hash: Poseidon::new(ctx, sgate, r_f, r_p)?,
            reader,
            _phantom: PhantomData,
        })
    }
}

impl<
        R: io::Read,
        C: CurveAffine,
        CTX,
        S: Clone + Debug,
        P: Clone,
        SGate: ContextGroup<CTX, S, S, C::ScalarExt, Error> + ContextRing<CTX, S, S, Error>,
        PGate: ContextGroup<CTX, S, P, C, Error>,
        E: Encode<CTX, S, P, Error, C::ScalarExt, C, SGate, PGate>,
        const T: usize,
        const RATE: usize,
    > TranscriptRead<CTX, S, P, Error, C::ScalarExt, C, SGate, PGate>
    for PoseidonTranscriptRead<R, C, CTX, S, P, Error, SGate, PGate, E, T, RATE>
{
    fn read_point(&mut self, ctx: &mut CTX, sgate: &SGate, pgate: &PGate) -> Result<P, Error> {
        let mut compressed = C::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
            Error::Transcript(io::Error::new(
                io::ErrorKind::Other,
                "invalid point encoding in proof",
            ))
        })?;
        let assigned_point = pgate.from_var(ctx, point)?;

        self.common_point(ctx, sgate, pgate, &assigned_point)?;

        Ok(assigned_point)
    }

    fn read_constant_point(
        &mut self,
        ctx: &mut CTX,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<P, Error> {
        let mut compressed = C::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
            Error::Transcript(io::Error::new(
                io::ErrorKind::Other,
                "invalid point encoding in proof",
            ))
        })?;
        let assigned_point = pgate.from_constant(ctx, point)?;

        self.common_point(ctx, sgate, pgate, &assigned_point)?;

        Ok(assigned_point)
    }

    fn read_scalar(&mut self, ctx: &mut CTX, sgate: &SGate) -> Result<S, Error> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "invalid field element encoding in proof",
            )
        })?;
        let assigned_scalar = sgate.from_var(ctx, scalar)?;

        self.common_scalar(ctx, sgate, &assigned_scalar)?;

        Ok(assigned_scalar)
    }

    fn read_constant_scalar(&mut self, ctx: &mut CTX, sgate: &SGate) -> Result<S, Error> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "invalid field element encoding in proof",
            )
        })?;
        let assigned_scalar = sgate.from_constant(ctx, scalar)?;

        self.common_scalar(ctx, sgate, &assigned_scalar)?;

        Ok(assigned_scalar)
    }

    fn squeeze_challenge_scalar(&mut self, ctx: &mut CTX, sgate: &SGate) -> Result<S, Error> {
        let s = self.hash.squeeze(ctx, sgate)?;
        Ok(s)
    }

    fn common_point(
        &mut self,
        ctx: &mut CTX,
        sgate: &SGate,
        pgate: &PGate,
        p: &P,
    ) -> Result<(), Error> {
        let encoded = E::encode_point(ctx, sgate, pgate, p)?;

        self.hash.update(&encoded);
        Ok(())
    }

    fn common_scalar(&mut self, ctx: &mut CTX, sgate: &SGate, s: &S) -> Result<(), Error> {
        let encoded = E::encode_scalar(ctx, sgate, s)?;

        self.hash.update(&encoded);
        Ok(())
    }
}
