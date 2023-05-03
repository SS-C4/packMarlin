use ark_std::{start_timer, end_timer};

use crate::Blake2s;
use crate::SimpleHashFiatShamirRng;
use crate::DensePolynomial;
use crate::ChaChaRng;
use crate::MarlinKZG10;
use crate::Marlin;
use crate::{Bls12_381, BlsFr};
use crate::{CanonicalSerialize, CanonicalDeserialize};
use crate::UniversalSRS;

#[allow(dead_code)]
pub(crate) fn universal_setup() -> UniversalSRS<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>> {
    let nc = 5000000;
    let nv = 5000000;
    let nz = 10000000;

    let uni_setup_time = start_timer!(|| "Packmarlin::New_Setup");
    let rng = &mut ark_std::test_rng();

    let srs = Marlin::<
        BlsFr,
        MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>,
        SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
    >::universal_setup(nc, nv, nz, rng)
    .unwrap();

    // Write srs 
    let mut srs_bytes = vec![];
    srs.serialize_uncompressed(&mut srs_bytes).unwrap();
    std::fs::write("packed_srs.bin", srs_bytes).unwrap();
    
    end_timer!(uni_setup_time);

    srs
}

#[allow(dead_code)]
pub(crate) fn load_srs() -> UniversalSRS<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>> {
    
    let load_existing_setup_time = start_timer!(|| "Packmarlin::Load_Existing_Setup");
    let srs_bytes = std::fs::read("packed_srs.bin").unwrap();
    
    let srs = 
        UniversalSRS::<BlsFr,MarlinKZG10<Bls12_381,DensePolynomial<BlsFr>>>::deserialize_unchecked(&srs_bytes[..]).unwrap();
    end_timer!(load_existing_setup_time);

    srs
}