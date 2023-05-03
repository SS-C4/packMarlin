use ark_bls12_381_old::G1Affine;
use ark_marlin::ahp::LabeledPolynomial;
use ark_marlin::rng::FiatShamirRng;
use ark_marlin::{ IndexProverKey, IndexVerifierKey, Proof};
use ark_poly::{ EvaluationDomain, Evaluations as EvaluationsOnDomain, UVPolynomial };
use ark_poly::GeneralEvaluationDomain;
use ark_poly_commit::{LabeledCommitment, PolynomialCommitment};
use ark_poly_commit::marlin_pc::Commitment;
use ark_poly_commit::marlin_pc::CommitterKey;
use ark_std::{ start_timer, end_timer, cfg_into_iter };
use rand::rngs::StdRng;
use std::process::Command;
use std::vec;

use crate::Blake2s;
use crate::SimpleHashFiatShamirRng;
use crate::DensePolynomial;
use crate::ChaChaRng;
use crate::MarlinKZG10;
use crate::Marlin;
use crate::ark_ff::UniformRand;
use crate::prove::{PROTOCOL_NAME, ZtProof};
use crate::{ Bls12_381, BlsFr };
use crate::UniversalSRS;
use crate::{ R1CSFile, R1CS, CircomCircuit, ConstraintSystem, ConstraintSynthesizer };
use crate::{ BufReader, Cursor, read, read_to_string, FromStr };

fn commit_to_diff(poso_rand: Vec<BlsFr>, loc_comm: Vec<G1Affine>, ck: CommitterKey<Bls12_381>) -> LabeledCommitment<Commitment<Bls12_381>> {
    let diff_time = start_timer!(|| "Committing to diff polynomial");
    
    let mut diff = poso_rand.clone();

    let diff = DensePolynomial::from_coefficients_vec(diff);
    let diff = LabeledPolynomial::new("diff".to_string(), diff, None, None);
    let diff_p = vec![&diff].into_iter();
    let (diff_comm, diff_rand) = 
        MarlinKZG10::<Bls12_381,DensePolynomial<BlsFr>>::commit(&ck.clone(), diff_p, None).unwrap();
    
    end_timer!(diff_time);

    diff_comm[0].clone()
}

fn zt_verify(ztpf: ZtProof) -> bool {
    let zt_time = start_timer!(|| "Verifying zt proof");

    let mut fs_rng: SimpleHashFiatShamirRng<Blake2s,ChaChaRng> = FiatShamirRng::initialize(&to_bytes![&PROTOCOL_NAME, &ztpf.quotient_poly_comm].unwrap());

    end_timer!(zt_time);

    let is_valid = true;

    is_valid
}

pub(crate) fn verify(
    vk: &IndexVerifierKey<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>,
    pubinp: Vec<BlsFr>,
    proof: Proof<BlsFr, MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>,
    ztpf: ZtProof,
    rng: &mut StdRng,
    loc_comm: Vec<G1Affine>,
    ck_trim: CommitterKey<Bls12_381>
) -> bool {

    let poso_time = start_timer!(|| "Computing poso_rand");

    let mut fs_rng: SimpleHashFiatShamirRng<Blake2s,ChaChaRng> = FiatShamirRng::initialize(&to_bytes![&PROTOCOL_NAME, &vk, &pubinp].unwrap());
    fs_rng.absorb(&proof.commitments[1]);

    let poso_rand = cfg_into_iter!(0..10000*11)
        .map(|_| u16::from(u8::rand(&mut fs_rng)) + 1)
        .collect::<Vec<u16>>();

    let poso_rand: Vec<BlsFr> = poso_rand
        .iter()
        .map(|w| {
            BlsFr::from(*w)
        })
        .collect::<Vec<BlsFr>>();

    end_timer!(poso_time);

    commit_to_diff(poso_rand, loc_comm, ck_trim);

    let is_valid = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::verify(&vk, &pubinp, &proof, rng);

    zt_verify(ztpf) & is_valid.unwrap()
}