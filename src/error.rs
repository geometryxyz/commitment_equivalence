use std::io;

#[derive(Debug)]
pub enum Error {
    FiatShamirError(io::Error),
    PolyCommitError(ark_poly_commit::Error),
    KZGFailed,
    IPAFailed,
    PCError { error: String },
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

/// Convert an ark_poly_commit error
pub fn from_pc_error<F, PC>(error: PC::Error) -> Error
where
    F: ark_ff::Field,
    PC: ark_poly_commit::PolynomialCommitment<F, ark_poly::univariate::DensePolynomial<F>>,
{
    println!("Polynomial Commitment Error: {:?}", error);
    Error::PCError {
        error: format!("Polynomial Commitment Error: {:?}", error),
    }
}
