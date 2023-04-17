use ark_circom::{circom::{R1CSFile, R1CS}, CircomCircuit};
use ark_bls12_381_old::{Bls12_381, Fr as BlsFr};
use ark_std::io::{BufReader, Cursor};
use std::str::FromStr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

fn main() {
    // open pack.r1cs and read into data
    let data = include_bytes!("../example.r1cs");

    let reader = BufReader::new(Cursor::new(&data[..]));
    let file = R1CSFile::<Bls12_381>::new(reader).unwrap();
    let r1cs = R1CS::from(file);
    
    let witness = include_str!("../witness.json");
    let witness: Vec<String> = serde_json::from_str(&witness).unwrap();

    // convert witness into field elements
    let witness = Some(witness
        .iter()
        .map(|w| {
            BlsFr::from_str(&w).unwrap()
        })
        .collect::<Vec<BlsFr>>());

    let pubinput = include_str!("../public.json");
    let pubinput: Vec<String> = serde_json::from_str(&pubinput).unwrap();

    // convert public input into field elements
    let pubinput = pubinput
        .iter()
        .map(|w| {
            BlsFr::from_str(&w).unwrap()
        })
        .collect::<Vec<BlsFr>>();

    let mut circuit = CircomCircuit::<Bls12_381>{r1cs, witness};

    let cs = ConstraintSystem::<BlsFr>::new_ref();
    
    circuit.r1cs.wire_mapping = None;
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    
    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        println!(
            "Unsatisfied constraint: {:?}",
            cs.which_is_unsatisfied().unwrap()
        );
    }

    println!("is_satisfied: {}", is_satisfied);

    use ark_marlin::Marlin;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_poly::univariate::DensePolynomial;
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;
    use ark_marlin::SimpleHashFiatShamirRng;

    let rng = &mut ark_std::test_rng();

    let srs = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::universal_setup(1000, 2000, 2400, rng)
    .unwrap();

    println!("srs");

    let (pk, vk) = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::index(&srs, circuit.clone())
    .unwrap();

    println!("pk");

    let proof = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::prove(&pk, circuit.clone(), rng);

    println!("proof");

    let is_valid = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::verify(&vk, &pubinput, &proof.unwrap(), rng);

    println!("is_valid: {}", is_valid.unwrap());

}
