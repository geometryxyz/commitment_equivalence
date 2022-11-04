use ark_bn254::{Bn254, Fr};
use ark_ec::PairingEngine;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_poly_commit::{
    ipa_pc::InnerProductArgPC, sonic_pc::SonicKZG10, LabeledPolynomial, PolynomialCommitment,
};
use blake2::Blake2s;
use commitment_equivalence::PolyCommitEquivalence;
use rand::thread_rng;
use std::iter;

// Shorthand for the concrete instances of the types we use
type KZG = SonicKZG10<Bn254, DensePolynomial<Fr>>;
type IPA = InnerProductArgPC<<Bn254 as PairingEngine>::G1Affine, Blake2s, DensePolynomial<Fr>>;
type PCEquivalence = PolyCommitEquivalence<Blake2s, Bn254, DensePolynomial<Fr>, KZG, IPA>;

fn main() {
    let rng = &mut thread_rng();
    let max_degree = 20;
    let max_hiding = 1;

    // Random polynomial
    let poly: DensePolynomial<Fr> = DensePolynomial::rand(max_degree - 1, rng);
    let poly = LabeledPolynomial::new(String::from("poly"), poly, Some(max_degree), Some(1));

    // Setup commitment schemes
    let kzg_pp = KZG::setup(max_degree, None, rng).unwrap();
    let (kzg_ck, kzg_vk) = KZG::trim(&kzg_pp, max_degree, max_hiding, Some(&[max_degree])).unwrap();

    let ipa_pp = IPA::setup(max_degree, None, rng).unwrap();
    let (ipa_ck, ipa_vk) = IPA::trim(&ipa_pp, max_degree, max_hiding, Some(&[max_degree])).unwrap();

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
    match PCEquivalence::verify((&kzg_vk, &ipa_vk), (&kzg_commit[0], &ipa_commit[0]), proof).is_ok() {
        true => println!("The proof is valid"),
        false => println!("The proof is not valid")
    }
    
}
