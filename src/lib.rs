use std::marker::PhantomData;

use ark_ec::PairingEngine;
use ark_ff::{Field, to_bytes};

mod error;
use ark_marlin::rng::FiatShamirRng;
use ark_poly_commit::{
    ipa_pc,
    kzg10,
    LabeledCommitment,
};
use digest::Digest;
pub use error::Error;

pub struct PolyCommitEquivalence<F: Field> {
    _field: PhantomData<F>,
}

impl<F: Field> PolyCommitEquivalence<F> {
    pub fn prove<D: Digest, E: PairingEngine>(
        commitments: (
            LabeledCommitment<kzg10::Commitment<E>>,
            LabeledCommitment<ipa_pc::Commitment<E::G1Affine>>,
        ),
    ) -> Result<(), Error> {
        // Derive a challenge point
        let mut fs_rng = FiatShamirRng::<D>::from_seed(b"");
        fs_rng.absorb(&to_bytes!(commitments.0.commitment(), commitments.1.commitment())?);

        let challenge_point = F::rand(&mut fs_rng);

        // Open both commitments at the challenge point

        // Return openings

        Ok(())
    }

    pub fn verify() -> Result<(), Error> {
        // Check both openings
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
