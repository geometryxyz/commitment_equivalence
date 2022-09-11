use ark_ec::PairingEngine;
use ark_ff::to_bytes;
use ark_marlin::rng::FiatShamirRng;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    iter,
    marker::PhantomData,
    UniformRand,
};
use digest::Digest;
use error::from_pc_error;
use rand::thread_rng;

mod error;
pub use error::Error;

/// A proof system that attests to the fact that the same polynomial was committed to
/// under two different polynomial commitment scheme
pub struct PolyCommitEquivalence<
    D: Digest,
    E: PairingEngine,
    P: Polynomial<E::Fr>,
    PC1: PolynomialCommitment<E::Fr, P>,
    PC2: PolynomialCommitment<E::Fr, P>,
> {
    _digest: PhantomData<D>,
    _pairing: PhantomData<E>,
    _poly: PhantomData<P>,
    _pc1: PhantomData<PC1>,
    _pc2: PhantomData<PC2>,
}

/// Proof for the PolyCommitEquivalence protocol
#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<
    E: PairingEngine,
    P: Polynomial<E::Fr>,
    PC1: PolynomialCommitment<E::Fr, P>,
    PC2: PolynomialCommitment<E::Fr, P>,
> {
    pub eval: E::Fr,
    pub openings: (PC1::Proof, PC2::Proof),
}

impl<D, E, PC1, PC2> PolyCommitEquivalence<D, E, DensePolynomial<E::Fr>, PC1, PC2>
where
    D: Digest,
    E: PairingEngine,
    PC1: PolynomialCommitment<E::Fr, DensePolynomial<E::Fr>>,
    PC2: PolynomialCommitment<E::Fr, DensePolynomial<E::Fr>>,
{
    pub fn prove(
        commit_keys: (&PC1::CommitterKey, &PC2::CommitterKey),
        polynomial: &LabeledPolynomial<E::Fr, DensePolynomial<E::Fr>>,
        commitments: (
            &LabeledCommitment<PC1::Commitment>,
            &LabeledCommitment<PC2::Commitment>,
        ),
        randomnesses: (&PC1::Randomness, &PC2::Randomness),
    ) -> Result<Proof<E, DensePolynomial<E::Fr>, PC1, PC2>, Error> {
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
        let pc1_opening = PC1::open(
            commit_keys.0,
            iter::once(polynomial),
            iter::once(commitments.0),
            &challenge_point,
            opening_challenge,
            iter::once(randomnesses.0),
            Some(rng),
        )
        .map_err(from_pc_error::<E::Fr, PC1>)?;

        let pc2_opening = PC2::open(
            commit_keys.1,
            iter::once(polynomial),
            iter::once(commitments.1),
            &challenge_point,
            opening_challenge,
            iter::once(randomnesses.1),
            Some(rng),
        )
        .map_err(from_pc_error::<E::Fr, PC2>)?;

        // Return openings
        let proof = Proof {
            eval: evaluation,
            openings: (pc1_opening, pc2_opening),
        };
        Ok(proof)
    }

    pub fn verify(
        verifier_keys: (&PC1::VerifierKey, &PC2::VerifierKey),
        commitments: (
            &LabeledCommitment<PC1::Commitment>,
            &LabeledCommitment<PC2::Commitment>,
        ),
        proof: Proof<E, DensePolynomial<E::Fr>, PC1, PC2>,
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
        let kzg_check = PC1::check(
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
            Err(e) => return Err(from_pc_error::<E::Fr, PC1>(e)),
        }

        let ipa_check = PC2::check(
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
            Err(e) => return Err(from_pc_error::<E::Fr, PC2>(e)),
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
    type PCEquivalence = PolyCommitEquivalence<Blake2s, Bn254, DensePolynomial<Fr>, KZG, IPA>;

    #[test]
    fn ipa_kzg_equivalence_accept() {
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
        let proof = PCEquivalence::prove(
            (&kzg_ck, &ipa_ck),
            &poly,
            (&kzg_commit[0], &ipa_commit[0]),
            (&kzg_rand[0], &ipa_rand[0]),
        )
        .unwrap();

        // Verify proof
        PCEquivalence::verify((&kzg_vk, &ipa_vk), (&kzg_commit[0], &ipa_commit[0]), proof).unwrap();
    }

    #[test]
    fn ipa_kzg_equivalence_reject() {
        let rng = &mut thread_rng();
        let max_degree = 20;
        let max_hiding = 1;

        // Random polynomial
        let poly: DensePolynomial<Fr> = DensePolynomial::rand(max_degree - 1, rng);
        let poly = LabeledPolynomial::new(String::from("poly"), poly, Some(max_degree), Some(1));

        let other_poly: DensePolynomial<Fr> = DensePolynomial::rand(max_degree - 1, rng);
        let other_poly =
            LabeledPolynomial::new(String::from("poly"), other_poly, Some(max_degree), Some(1));

        // Setup commitment schemes
        let kzg_pp = KZG::setup(max_degree, None, rng).unwrap();
        let (kzg_ck, kzg_vk) =
            KZG::trim(&kzg_pp, max_degree, max_hiding, Some(&[max_degree])).unwrap();

        let ipa_pp = IPA::setup(max_degree, None, rng).unwrap();
        let (ipa_ck, ipa_vk) =
            IPA::trim(&ipa_pp, max_degree, max_hiding, Some(&[max_degree])).unwrap();

        // Commit to different polynomials with both schemes
        let (kzg_commit, kzg_rand) = KZG::commit(&kzg_ck, iter::once(&poly), Some(rng)).unwrap();
        let (ipa_commit, ipa_rand) =
            IPA::commit(&ipa_ck, iter::once(&other_poly), Some(rng)).unwrap();

        // Proof of equivalence
        let proof = PCEquivalence::prove(
            (&kzg_ck, &ipa_ck),
            &poly,
            (&kzg_commit[0], &ipa_commit[0]),
            (&kzg_rand[0], &ipa_rand[0]),
        )
        .unwrap();

        // Verify proof
        let check =
            PCEquivalence::verify((&kzg_vk, &ipa_vk), (&kzg_commit[0], &ipa_commit[0]), proof);

        assert!(check.is_err());
    }
}
