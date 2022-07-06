use digest::Digest;
use group::ff::PrimeField;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::Coordinates;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::Transcript;
use halo2_proofs::transcript::TranscriptRead;
use halo2_proofs::transcript::TranscriptWrite;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

/// Prefix to a prover's message soliciting a challenge
const SHA_PREFIX_CHALLENGE: u8 = 0;
/// Prefix to a prover's message containing a curve point
const SHA_PREFIX_POINT: u8 = 1;
/// Prefix to a prover's message containing a scalar
const SHA_PREFIX_SCALAR: u8 = 2;
///

#[derive(Debug, Clone)]
pub struct ShaRead<R: Read, C: CurveAffine, E: EncodedChallenge<C>, D: Digest> {
    state: D,
    reader: R,
    _marker: PhantomData<(C, E)>,
}

impl<R: Read, C: CurveAffine, E: EncodedChallenge<C>, D: Digest> ShaRead<R, C, E, D> {
    /// Initialize a transcript given an input buffer.
    pub fn init(reader: R) -> Self {
        ShaRead {
            state: D::new(),
            reader,
            _marker: PhantomData,
        }
    }
}

impl<R: Read, C: CurveAffine, D: Digest + Clone> TranscriptRead<C, Challenge255<C>>
    for ShaRead<R, C, Challenge255<C>, D>
{
    fn read_point(&mut self) -> io::Result<C> {
        // let mut compressed = C::Repr::default();
        let x = <C::Base as BaseExt>::read(&mut self.reader)?;
        let y = <C::Base as BaseExt>::read(&mut self.reader)?;

        let point: C = Option::from(C::from_xy(x, y)).ok_or_else(|| {
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

impl<R: Read, C: CurveAffine, D: Digest + Clone> Transcript<C, Challenge255<C>>
    for ShaRead<R, C, Challenge255<C>, D>
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        self.state.update(&[SHA_PREFIX_CHALLENGE]);
        let hasher = self.state.clone();
        let result: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();

        self.state = D::new();
        self.state.update(result);

        let mut bytes = result.to_vec();
        bytes.resize(64, 0u8);
        Challenge255::<C>::new(&bytes.try_into().unwrap())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[0u8; 31]);
        self.state.update(&[SHA_PREFIX_POINT]);
        let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "cannot write points at infinity to the transcript",
            )
        })?;

        for base in vec![coords.x(), coords.y()] {
            let mut buf = vec![];
            base.write(&mut buf)?;
            buf.resize(32, 0u8);
            buf.reverse();
            self.state.update(buf);
        }

        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.state.update(&[0u8; 31]);
        self.state.update(&[SHA_PREFIX_SCALAR]);

        {
            let mut buf = vec![];
            scalar.write(&mut buf)?;
            buf.resize(32, 0u8);
            buf.reverse();
            self.state.update(buf);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ShaWrite<W: Write, C: CurveAffine, E: EncodedChallenge<C>, D: Digest> {
    state: D,
    writer: W,
    _marker: PhantomData<(C, E)>,
}

impl<W: Write, C: CurveAffine, E: EncodedChallenge<C>, D: Digest> ShaWrite<W, C, E, D> {
    /// Initialize a transcript given an output buffer.
    pub fn init(writer: W) -> Self {
        ShaWrite {
            state: D::new(),
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

impl<W: Write, C: CurveAffine, D: Digest + Clone> TranscriptWrite<C, Challenge255<C>>
    for ShaWrite<W, C, Challenge255<C>, D>
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        self.common_point(point)?;
        // let compressed = point.to_bytes();

        let coords = point.coordinates();
        let x = coords
            .map(|v| v.x().clone())
            .unwrap_or(<C as CurveAffine>::Base::zero());
        let y = coords
            .map(|v| v.y().clone())
            .unwrap_or(<C as CurveAffine>::Base::zero());

        for base in vec![&x, &y] {
            base.write(&mut self.writer)?;
        }

        Ok(())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.common_scalar(scalar)?;
        let data = scalar.to_repr();

        self.writer.write_all(data.as_ref())
    }
}

impl<W: Write, C: CurveAffine, D: Digest + Clone> Transcript<C, Challenge255<C>>
    for ShaWrite<W, C, Challenge255<C>, D>
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        self.state.update(&[SHA_PREFIX_CHALLENGE]);
        let hasher = self.state.clone();
        let result: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();

        self.state = D::new();
        self.state.update(result);

        let mut bytes = result.to_vec();
        bytes.resize(64, 0u8);
        Challenge255::<C>::new(&bytes.try_into().unwrap())
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.state.update(&[0u8; 31]);
        self.state.update(&[SHA_PREFIX_POINT]);
        let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "cannot write points at infinity to the transcript",
            )
        })?;

        for base in vec![coords.x(), coords.y()] {
            let mut buf = vec![];
            base.write(&mut buf)?;
            buf.resize(32, 0u8);
            buf.reverse();
            self.state.update(buf);
        }

        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.state.update(&[0u8; 31]);
        self.state.update(&[SHA_PREFIX_SCALAR]);

        {
            let mut buf = vec![];
            scalar.write(&mut buf)?;
            buf.resize(32, 0u8);
            buf.reverse();
            self.state.update(buf);
        }

        Ok(())
    }
}
