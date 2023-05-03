use ark_marlin::ahp::LabeledPolynomial;
use ark_marlin::{ IndexProverKey, IndexVerifierKey};
use ark_poly::{ EvaluationDomain, Evaluations as EvaluationsOnDomain };
use ark_poly::GeneralEvaluationDomain;
use ark_poly_commit::{LabeledCommitment, PolynomialCommitment};
use ark_poly_commit::marlin_pc::Commitment;
use ark_poly_commit::marlin_pc::CommitterKey;
use ark_std::{ start_timer, end_timer };
use std::process::Command;
use std::vec;

use crate::Blake2s;
use crate::SimpleHashFiatShamirRng;
use crate::DensePolynomial;
use crate::ChaChaRng;
use crate::MarlinKZG10;
use crate::Marlin;
use crate::{ Bls12_381, BlsFr , G1Affine};
use crate::UniversalSRS;
use crate::{ R1CSFile, R1CS, CircomCircuit, ConstraintSystem, ConstraintSynthesizer };
use crate::{ BufReader, Cursor, read, read_to_string, FromStr };

pub(crate) fn loc_comm(circuit: CircomCircuit<Bls12_381>, ck: CommitterKey<Bls12_381>) -> Vec<G1Affine> {
    let rand_commitments_time = start_timer!(|| "Packmarlin::Commitments to locations of randomness");

    let offset = 100; // offset for location of randomness
    let poso_size = 10000;
    let num_poso = 8;
    // compute commitments and return them
    // let mut onehot_list = vec![vec![BlsFr::from(0); 80000]; poso_size];

    // let domain = GeneralEvaluationDomain::new(80000).unwrap();

    // for i in 0..poso_size {
    //     for j in 0..num_poso {
    //         onehot_list[i][offset + i + j*num_poso] = BlsFr::from(1);
    //     }
    // }

    // let mut onehot_interpolated = vec![];
    // let mut onehot_labeled = vec![];
    // for i in 0..poso_size {
    //     onehot_interpolated.push(EvaluationsOnDomain::from_vec_and_domain(onehot_list[i].clone(), domain).interpolate());
    //     onehot_labeled.push(LabeledPolynomial::new("w".to_string(), onehot_interpolated[i].clone(), None, None));
    // }

    // let (onehot_comm, _) = 
    //     MarlinKZG10::<Bls12_381,DensePolynomial<BlsFr>>::commit(&ck, &onehot_labeled, None).unwrap();

    let onehot_comm = ck.clone().powers;

    end_timer!(rand_commitments_time);

    onehot_comm
}

pub(crate) fn index(
    srs: &UniversalSRS<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>
) -> (IndexProverKey<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>, 
      IndexVerifierKey<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>, 
      Vec<G1Affine>)
{
    let s_index = start_timer!(|| "Packmarlin::Index");

    let packer_time = start_timer!(|| "Running packer.js");
    let _ = Command::new("node")
        .arg("./packR1CS/scripts/packer.js")
        .arg("norand")
        .output()
        .expect("packer.js failed");
    end_timer!(packer_time);

    let file_time = start_timer!(|| "Loading R1CS and witness files");
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

    assert!(cs.is_satisfied().unwrap(), "Unsatisfied constraint system");

    end_timer!(gen_time);

    end_timer!(file_time);
    
    let (pk, vk) = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::index(&srs, circuit.clone())
    .unwrap();

    let loc_comm = loc_comm(circuit.clone(), pk.committer_key.clone());

    end_timer!(s_index);

    // return loc_comm output as well
    (pk, vk, loc_comm)
} 
