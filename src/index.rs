use ark_marlin::{ IndexProverKey, IndexVerifierKey};
use ark_std::{ start_timer, end_timer };
use std::process::Command;

use crate::Blake2s;
use crate::SimpleHashFiatShamirRng;
use crate::DensePolynomial;
use crate::ChaChaRng;
use crate::MarlinKZG10;
use crate::Marlin;
use crate::{ Bls12_381, BlsFr };
use crate::UniversalSRS;
use crate::{ R1CSFile, R1CS, CircomCircuit, ConstraintSystem, ConstraintSynthesizer };
use crate::{ BufReader, Cursor, read, read_to_string, FromStr };

pub(crate) fn index(
    srs: &UniversalSRS<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>
) -> (IndexProverKey<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>, IndexVerifierKey<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>)
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
    end_timer!(s_index);

    (pk, vk)
} 
