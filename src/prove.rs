use std::process::Command;

use ark_marlin::ahp::LabeledPolynomial;
use ark_marlin::rng::FiatShamirRng;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain,
    GeneralEvaluationDomain, UVPolynomial,
};
use ark_poly_commit::marlin_pc::{Commitment, Randomness};
use ark_poly_commit::{PolynomialCommitment, LabeledCommitment};
use crate::{ R1CSFile, R1CS, CircomCircuit, ConstraintSystem, ConstraintSynthesizer };
use ark_std::{ start_timer, end_timer , cfg_into_iter, UniformRand};
use rand::rngs::StdRng;
use crate::{ BufReader, Cursor, read, read_to_string, FromStr };


use crate::Blake2s;
use crate::SimpleHashFiatShamirRng;
use crate::ChaChaRng;
use crate::MarlinKZG10;
use crate::Marlin;
use crate::{ Bls12_381, BlsFr };
use ark_marlin::{IndexProverKey, Proof};
use ark_ff::Zero;

pub const PROTOCOL_NAME: &'static [u8] = b"packmarlin";

pub(crate) fn write_poso_rand(poso_rand: Vec<BlsFr>) {
    // convert poso_rand to vector of strings
    let poso_rand: Vec<String> = poso_rand
        .iter()
        .map(|w| {
            w.to_string()
        })
        .collect::<Vec<String>>();

    let poso_rand = serde_json::to_string(&poso_rand).unwrap();
    std::fs::write("./packR1CS/scripts/.output/poso_rand.json", poso_rand).unwrap();
}


pub(crate) fn prove(
    pk: &IndexProverKey<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>,
    circuit: CircomCircuit<Bls12_381>,
    rng: &mut StdRng,
    poso_size: usize
) -> (Vec<LabeledCommitment<Commitment<Bls12_381>>>, Vec<Randomness<BlsFr, DensePolynomial<BlsFr>>>, Proof<BlsFr, MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>) {
    assert!(circuit.r1cs.num_inputs == pk.index.index_info.num_instance_variables);

    let domain_h = GeneralEvaluationDomain::new(pk.index.index_info.num_constraints).unwrap();
    let domain_x = GeneralEvaluationDomain::new(pk.index.index_info.num_instance_variables).unwrap();

    let witness = circuit.witness.clone().unwrap();
    let public_input: Vec<BlsFr> = witness[1..circuit.r1cs.num_inputs].to_vec();
    let mut w_extended = witness.clone();
    w_extended.extend(vec![
        BlsFr::zero();
        pk.index.index_info.num_constraints - circuit.r1cs.num_inputs - witness.len()
    ]);

    
    let w_poly_time = start_timer!(|| "Computing w polynomial");
    
    let ratio = domain_h.size() / domain_x.size();
    let v_H = domain_h.vanishing_polynomial().into();
    let w_poly_evals = cfg_into_iter!(0..domain_h.size())
        .map(|k| {
            if k % ratio == 0 {
                BlsFr::zero()
            } else {
                w_extended[k - (k / ratio) - 1] - &public_input[k]
            }
        })
        .collect();

    let w_poly = &EvaluationsOnDomain::from_vec_and_domain(w_poly_evals, domain_h)
        .interpolate()
        + &(&DensePolynomial::from_coefficients_slice(&[BlsFr::rand(rng)]) * &v_H);
    let (w_poly, remainder) = w_poly.divide_by_vanishing_poly(domain_x).unwrap();
    assert!(remainder.is_zero());

    let w = LabeledPolynomial::new("w".to_string(), w_poly, None, Some(1));
    end_timer!(w_poly_time);


    let w_poly_comm_time = start_timer!(|| "Committing to w polynomial");

    let binding = w.clone();
    let w_p = vec![&binding].into_iter();
    let (witness_comm, witness_rand) = MarlinKZG10::<Bls12_381,DensePolynomial<BlsFr>>::commit(&pk.committer_key, w_p, Some(rng)).unwrap();

    end_timer!(w_poly_comm_time);


    // compute poso_rand
    let poso_time = start_timer!(|| "Computing poso_rand");
    let mut fs_rng: SimpleHashFiatShamirRng<Blake2s,ChaChaRng> = FiatShamirRng::initialize(&to_bytes![&PROTOCOL_NAME, &pk.index_vk, &public_input].unwrap());
    fs_rng.absorb(&witness_comm);

    let poso_rand = cfg_into_iter!(0..poso_size)
        .map(|_| BlsFr::rand(&mut fs_rng))
        .collect::<Vec<BlsFr>>();

    write_poso_rand(poso_rand);
    end_timer!(poso_time);

    // update vk inside pk
    let mut mod_pk = pk.clone();

    // re0run packer and re-read witness
    let packer_time = start_timer!(|| "Running packer.js with randomness");
    let _ = Command::new("node")
        .arg("./packR1CS/scripts/packer.js")
        .arg("rand")
        .output()
        .expect("packer.js failed");
    end_timer!(packer_time);

    let file_time = start_timer!(|| "Loading new witness file");
    let file: String = "./packR1CS/scripts/.output/".to_string();

    let data = read(file.clone()+"packed_subcircuit.r1cs").unwrap();
    let witness = read_to_string(file.clone()+"packed_witness.json").unwrap();

    let reader = BufReader::new(Cursor::new(&data[..]));
    let r1csfile = R1CSFile::<Bls12_381>::new(reader).unwrap();
    let r1cs = R1CS::from(r1csfile);

    let witness: Vec<String> = serde_json::from_str(&witness).unwrap();

    // convert witness into field elements
    let witness = witness
        .iter()
        .map(|w| {
            BlsFr::from_str(&w).unwrap()
        })
        .collect::<Vec<BlsFr>>();

    let witness = Some(witness);

    let gen_time = start_timer!(|| "Generating constraints");
    let mut circuit = CircomCircuit::<Bls12_381>{r1cs, witness};
    let cs = ConstraintSystem::<BlsFr>::new_ref();
    circuit.r1cs.wire_mapping = None;
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    end_timer!(gen_time);
    end_timer!(file_time);

    // DONT run indexer again, run normal marlin prover and zerotest prover
    let proof = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::prove(&mod_pk, circuit.clone(), rng);

    // let zt_proof = zt_prover();

    // send proof consisting of 0th msg and normal proof and zerotest proof
    // (zt_proof, proof.unwrap())
    (witness_comm, witness_rand, proof.unwrap())
    
}