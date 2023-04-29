use ark_circom::{circom::{R1CSFile, R1CS}, CircomCircuit};
use ark_bls12_381_old::{Bls12_381, Fr as BlsFr};
use ark_std::io::{BufReader, Cursor};
use std::{str::FromStr, fs::{read, read_to_string}};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use std::time::Instant;

use rand::rngs::StdRng;
use ark_marlin::Marlin;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly::univariate::DensePolynomial;
use blake2::Blake2s;
use rand_chacha::ChaChaRng;
use ark_marlin::SimpleHashFiatShamirRng;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_marlin::UniversalSRS;

pub mod setup;
pub mod index;
pub mod prove;
pub mod verify;

fn load_values(file: String) -> (R1CS<Bls12_381>, Option<Vec<BlsFr>>, Vec<BlsFr>, UniversalSRS<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>) {
    let data = read(file.clone()+".r1cs").unwrap();
    let witness = read_to_string(file.clone()+"_witness.json").unwrap();

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

    let pubinp: Vec<BlsFr> = witness[1..r1cs.num_inputs].to_vec();
    let witness = Some(witness);

    let srs_bytes = std::fs::read(file+"_srs.bin").unwrap();
    let srs = 
        UniversalSRS::<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>::deserialize_unchecked(&srs_bytes[..]).unwrap();

    (r1cs, witness, pubinp, srs)
}

#[allow(dead_code)]
fn setup(file: String, rng: &mut StdRng) {
    let mut nc: usize = 0;
    let mut nv: usize = 0;
    let mut nz: usize = 0;

    if file == "example" {
        (nc, nv, nz) = (100, 100, 100);
    } else if file == "packed" {
        (nc, nv, nz) = ( 440000,  561000, 4660000);
    } else if file == "nopack" {
        (nc, nv, nz) = (1300000, 1300000, 6000000);
    } 
    
    let srs = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::universal_setup(nc, nv, nz, rng)
    .unwrap();

    // Write srs 
    let mut srs_bytes = vec![];
    srs.serialize_uncompressed(&mut srs_bytes).unwrap();
    std::fs::write(file+"_srs.bin", srs_bytes).unwrap();
}

fn main() {
    let file = "packed";

    let rng = &mut ark_std::test_rng();
    // setup(file.to_string(), rng);

    let s_load = Instant::now();

        let (r1cs, witness, pubinp, srs) 
            = load_values(file.to_string());

        let mut circuit = CircomCircuit::<Bls12_381>{r1cs, witness};
        let cs = ConstraintSystem::<BlsFr>::new_ref();
        circuit.r1cs.wire_mapping = None;
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied, "Constraints not satisfied");

    let t_load = s_load.elapsed();
    println!("load: {:?}", t_load);

    let s_index = Instant::now();
        let (pk, vk) = Marlin::<
            BlsFr,
            MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::index(&srs, circuit.clone())
        .unwrap();
    let t_index = s_index.elapsed();
    println!("index: {:?}", t_index);

    let s_prove = Instant::now();
        let proof = Marlin::<
            BlsFr,
            MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::prove(&pk, circuit.clone(), rng);
    let t_prove = s_prove.elapsed();
    println!("prove: {:?}", t_prove);

    let s_verify = Instant::now();
        let is_valid = Marlin::<
            BlsFr,
            MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::verify(&vk, &pubinp, &proof.unwrap(), rng);
    let t_verify = s_verify.elapsed();
    println!("verify: {:?}", t_verify);

    println!("is_valid: {}", is_valid.unwrap());
}
