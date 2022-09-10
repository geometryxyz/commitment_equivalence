use std::io;

#[derive(Debug)]
pub enum Error {
    FiatShamirError(io::Error),
    PolyCommitError(ark_poly_commit::Error),
    KZGFailed,
    IPAFailed,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::FiatShamirError(e)
    }
}

impl From<ark_poly_commit::Error> for Error {
    fn from(e: ark_poly_commit::Error) -> Self {
        Self::PolyCommitError(e)
    }
}
