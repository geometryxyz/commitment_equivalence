use ark_ec::PairingEngine;
use ark_ff::to_bytes;
use ark_marlin::rng::FiatShamirRng;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_poly_commit::{
    ipa_pc::{self, InnerProductArgPC},
    kzg10,
    sonic_pc::{self, SonicKZG10},
    LabeledCommitment, LabeledPolynomial, PolynomialCommitment,
};
use ark_std::{iter, marker::PhantomData, UniformRand};
use digest::Digest;
use rand::thread_rng;

mod error;
pub use error::Error;

pub struct PolyCommitEquivalence<D: Digest, E: PairingEngine, P: Polynomial<E::Fr>> {
    _digest: PhantomData<D>,
    _pairing: PhantomData<E>,
    _poly: PhantomData<P>,
}

pub struct Proof<E: PairingEngine> {
    pub eval: E::Fr,
    pub openings: (kzg10::Proof<E>, ipa_pc::Proof<E::G1Affine>),
}

impl<D: Digest, E: PairingEngine> PolyCommitEquivalence<D, E, DensePolynomial<E::Fr>> {
    pub fn prove(
        commit_keys: (
            &sonic_pc::CommitterKey<E>,
            &ipa_pc::CommitterKey<E::G1Affine>,
        ),
        polynomial: &LabeledPolynomial<E::Fr, DensePolynomial<E::Fr>>,
        commitments: (
            &LabeledCommitment<sonic_pc::Commitment<E>>,
            &LabeledCommitment<ipa_pc::Commitment<E::G1Affine>>,
        ),
        randomnesses: (
            &sonic_pc::Randomness<E::Fr, DensePolynomial<E::Fr>>,
            &ipa_pc::Randomness<E::G1Affine>,
        ),
    ) -> Result<Proof<E>, Error> {
        let rng = &mut thread_rng();

        // Derive a challenge point
        let mut fs_rng = FiatShamirRng::<D>::from_seed(b"");
        fs_rng.absorb(&to_bytes!(
            commitments.0.commitment(),
            commitments.1.commitment()
        )?);

        let challenge_point = E::Fr::rand(&mut fs_rng);
        let opening_challenge = E::Fr::rand(&mut fs_rng);

        // Compute the evaluation
        let evaluation = polynomial.evaluate(&challenge_point);

        // Open both commitments at the challenge point
        let kzg_opening = SonicKZG10::open(
            commit_keys.0,
            iter::once(polynomial),
            iter::once(commitments.0),
            &challenge_point,
            opening_challenge,
            iter::once(randomnesses.0),
            Some(rng),
        )?;

        let ipa_opening = InnerProductArgPC::<E::G1Affine, D, DensePolynomial<E::Fr>>::open(
            commit_keys.1,
            iter::once(polynomial),
            iter::once(commitments.1),
            &challenge_point,
            opening_challenge,
            iter::once(randomnesses.1),
            Some(rng),
        )?;

        // Return openings
        let proof = Proof {
            eval: evaluation,
            openings: (kzg_opening, ipa_opening),
        };
        Ok(proof)
    }

    pub fn verify(
        verifier_keys: (&sonic_pc::VerifierKey<E>, &ipa_pc::VerifierKey<E::G1Affine>),
        commitments: (
            &LabeledCommitment<sonic_pc::Commitment<E>>,
            &LabeledCommitment<ipa_pc::Commitment<E::G1Affine>>,
        ),
        proof: Proof<E>,
    ) -> Result<(), Error> {
        let rng = &mut thread_rng();

        // Derive a challenge point
        let mut fs_rng = FiatShamirRng::<D>::from_seed(b"");
        fs_rng.absorb(&to_bytes!(
            commitments.0.commitment(),
            commitments.1.commitment()
        )?);
        let challenge_point = E::Fr::rand(&mut fs_rng);
        let opening_challenge = E::Fr::rand(&mut fs_rng);

        // Check both openings
        let kzg_check = SonicKZG10::<E, DensePolynomial<E::Fr>>::check(
            verifier_keys.0,
            iter::once(commitments.0),
            &challenge_point,
            iter::once(proof.eval),
            &proof.openings.0,
            opening_challenge,
            Some(rng),
        );
        match kzg_check {
            Ok(true) => (),
            Ok(false) => return Err(Error::KZGFailed),
            Err(e) => return Err(Error::PolyCommitError(e)),
        }

        let ipa_check = InnerProductArgPC::<E::G1Affine, D, DensePolynomial<E::Fr>>::check(
            verifier_keys.1,
            iter::once(commitments.1),
            &challenge_point,
            iter::once(proof.eval),
            &proof.openings.1,
            opening_challenge,
            Some(rng),
        );
        match ipa_check {
            Ok(true) => (),
            Ok(false) => return Err(Error::IPAFailed),
            Err(e) => return Err(Error::PolyCommitError(e)),
        }

        Ok(())
    }
}

#[cfg(test)]

mod tests {
    use ark_bn254::{Bn254, Fr};
    use ark_ec::PairingEngine;
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use ark_poly_commit::{
        ipa_pc::InnerProductArgPC, sonic_pc::SonicKZG10, LabeledPolynomial, PolynomialCommitment,
    };
    use blake2::Blake2s;
    use rand::thread_rng;
    use std::iter;

    use crate::PolyCommitEquivalence;

    type KZG = SonicKZG10<Bn254, DensePolynomial<Fr>>;
    type IPA = InnerProductArgPC<<Bn254 as PairingEngine>::G1Affine, Blake2s, DensePolynomial<Fr>>;

    #[test]
    fn ipa_kzg_equivalence() {
        let rng = &mut thread_rng();
        let max_degree = 20;
        let max_hiding = 1;

        // Random polynomial
        let poly: DensePolynomial<Fr> = DensePolynomial::rand(max_degree - 1, rng);
        let poly = LabeledPolynomial::new(String::from("poly"), poly, Some(max_degree), Some(1));

        // Setup commitment schemes
        let kzg_pp = KZG::setup(max_degree, None, rng).unwrap();
        let (kzg_ck, kzg_vk) =
            KZG::trim(&kzg_pp, max_degree, max_hiding, Some(&[max_degree])).unwrap();

        let ipa_pp = IPA::setup(max_degree, None, rng).unwrap();
        let (ipa_ck, ipa_vk) =
            IPA::trim(&ipa_pp, max_degree, max_hiding, Some(&[max_degree])).unwrap();

        // Commit to the polynomial with both schemes
        let (kzg_commit, kzg_rand) = KZG::commit(&kzg_ck, iter::once(&poly), Some(rng)).unwrap();
        let (ipa_commit, ipa_rand) = IPA::commit(&ipa_ck, iter::once(&poly), Some(rng)).unwrap();

        // Proof of equivalence
        let proof = PolyCommitEquivalence::<Blake2s, Bn254, DensePolynomial<Fr>>::prove(
            (&kzg_ck, &ipa_ck),
            &poly,
            (&kzg_commit[0], &ipa_commit[0]),
            (&kzg_rand[0], &ipa_rand[0]),
        )
        .unwrap();

        // Verify proof
        PolyCommitEquivalence::<Blake2s, Bn254, DensePolynomial<Fr>>::verify(
            (&kzg_vk, &ipa_vk),
            (&kzg_commit[0], &ipa_commit[0]),
            proof,
        )
        .unwrap();
    }
}
