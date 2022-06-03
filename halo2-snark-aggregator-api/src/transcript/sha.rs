use std::io::{self, Read, Write};
use std::marker::PhantomData;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptWrite;
use halo2_proofs::arithmetic::Coordinates;
use halo2_proofs::transcript::Transcript;
use halo2_proofs::transcript::TranscriptRead;
use halo2_proofs::arithmetic::BaseExt;
use group::ff::PrimeField;

use sha2::{Sha256, Digest};


/// Prefix to a prover's message soliciting a challenge
const SHA_PREFIX_CHALLENGE: u8 = 0;
/// Prefix to a prover's message containing a curve point
const SHA_PREFIX_POINT: u8 = 1;
/// Prefix to a prover's message containing a scalar
const SHA_PREFIX_SCALAR: u8 = 2;
///



#[derive(Debug, Clone)]
pub struct ShaRead<R: Read, C: CurveAffine, E: EncodedChallenge<C>> {
    state: Sha256,
    reader: R,
    _marker: PhantomData<(C, E)>,
}

impl<R: Read, C: CurveAffine, E: EncodedChallenge<C>> ShaRead<R, C, E> {
    /// Initialize a transcript given an input buffer.
    pub fn init(reader: R) -> Self {
        ShaRead {
            state: Sha256::new(),
            reader,
            _marker: PhantomData,
        }
    }
}

impl<R: Read, C: CurveAffine> TranscriptRead<C, Challenge255<C>>
    for ShaRead<R, C, Challenge255<C>>
{
    fn read_point(&mut self) -> io::Result<C> {
        let mut compressed = C::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "invalid point encoding in proof")
        })?;
        self.common_point(point)?;

        Ok(point)
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "invalid field element encoding in proof",
            )
        })?;
        self.common_scalar(scalar)?;

        Ok(scalar)
    }
}

impl<R: Read, C: CurveAffine> Transcript<C, Challenge255<C>>
    for ShaRead<R, C, Challenge255<C>>
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        self.state.update(&[SHA_PREFIX_CHALLENGE]);
        let hasher = self.state.clone();
        let result: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
        let mut bytes = result.to_vec();
        bytes.resize(64, 0u8);
        Challenge255::<C>::new(&bytes.try_into().unwrap())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[SHA_PREFIX_POINT]);
        let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "cannot write points at infinity to the transcript",
            )
        })?;
        coords.x().write(&mut self.state)?;
        coords.y().write(&mut self.state)?;

        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.state.update(&[SHA_PREFIX_SCALAR]);
        self.state.update(scalar.to_repr().as_ref());

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ShaWrite <W: Write, C: CurveAffine, E: EncodedChallenge<C>> {
    state: Sha256,
    writer: W,
    _marker: PhantomData<(C, E)>,
}

impl<W: Write, C: CurveAffine, E: EncodedChallenge<C>> ShaWrite<W, C, E> {
    /// Initialize a transcript given an output buffer.
    pub fn init(writer: W) -> Self {
        ShaWrite {
            state: Sha256::new(),
            writer,
            _marker: PhantomData,
        }
    }

    /// Conclude the interaction and return the output buffer (writer).
    pub fn finalize(self) -> W {
        // TODO: handle outstanding scalars? see issue #138
        self.writer
    }
}

impl<W: Write, C: CurveAffine> TranscriptWrite<C, Challenge255<C>>
    for ShaWrite<W, C, Challenge255<C>>
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        self.common_point(point)?;
        let compressed = point.to_bytes();
        self.writer.write_all(compressed.as_ref())
    }
    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.common_scalar(scalar)?;
        let data = scalar.to_repr();
        self.writer.write_all(data.as_ref())
    }
}

impl<W: Write, C: CurveAffine> Transcript<C, Challenge255<C>>
    for ShaWrite<W, C, Challenge255<C>>
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        self.state.update(&[SHA_PREFIX_CHALLENGE]);
        let hasher = self.state.clone();
        let result: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
        let mut bytes = result.to_vec();
        bytes.resize(64, 0u8);
        Challenge255::<C>::new(&bytes.try_into().unwrap())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[SHA_PREFIX_POINT]);
        let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "cannot write points at infinity to the transcript",
            )
        })?;
        coords.x().write(&mut self.state)?;
        coords.y().write(&mut self.state)?;

        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.state.update(&[SHA_PREFIX_SCALAR]);
        self.state.update(scalar.to_repr().as_ref());

        Ok(())
    }
}
