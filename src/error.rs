use std::io;

#[derive(Debug)]
pub enum Error {
    FiatShamirError(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::FiatShamirError(e)
    }
}
