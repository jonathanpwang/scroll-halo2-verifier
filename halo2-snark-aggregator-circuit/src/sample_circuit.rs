use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::plonk::{create_proof, keygen_pk};
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::{
    arithmetic::{CurveAffine, MultiMillerLoop},
    plonk::Circuit,
    poly::commitment::Params,
};
use halo2_snark_aggregator_api::transcript::sha::{ShaRead, ShaWrite};
use rand_core::OsRng;
use std::io::Write;

pub trait TargetCircuit<C: CurveAffine, E: MultiMillerLoop<G1Affine = C>> {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;

    type Circuit: Circuit<C::ScalarExt> + Default;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<C::ScalarExt>>);
}

pub fn sample_circuit_setup<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C>,
    CIRCUIT: TargetCircuit<C, E>,
>(
    mut folder: std::path::PathBuf,
) {
    // TODO: Do not use setup in production
    let params = Params::<C>::unsafe_setup::<E>(CIRCUIT::TARGET_CIRCUIT_K);

    let circuit = CIRCUIT::Circuit::default();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

    {
        folder.push(format!("sample_circuit_{}.params", CIRCUIT::NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        params.write(&mut fd).unwrap();
    }

    {
        folder.push(format!("sample_circuit_{}.vkey", CIRCUIT::NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        vk.write(&mut fd).unwrap();
    }
}

pub fn sample_circuit_random_run<
    C: CurveAffine,
    E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>,
    CIRCUIT: TargetCircuit<C, E>,
>(
    mut folder: std::path::PathBuf,
    circuit: CIRCUIT::Circuit,
    instances: &[&[C::Scalar]],
    index: usize,
) -> (Params<C>, VerifyingKey<C>, Vec<u8>) {
    /*
    let params = {
        folder.push(format!("sample_circuit_{}.params", CIRCUIT::NAME));
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        Params::<C>::read(&mut fd).unwrap()
    };

    let vk = {
        folder.push(format!("sample_circuit_{}.vkey", CIRCUIT::NAME));
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        VerifyingKey::<C>::read::<_, CIRCUIT::Circuit>(&mut fd, &params).unwrap()
    };
    */

    let params = Params::<C>::unsafe_setup::<E>(CIRCUIT::TARGET_CIRCUIT_K);

    println!("generating vk...");
    let default_circuit = CIRCUIT::Circuit::default();
    let vk = keygen_vk(&params, &default_circuit).expect("keygen_vk should not fail");

    println!("generating pk...");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    {
        folder.push(format!("sample_circuit_{}.params", CIRCUIT::NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        params.write(&mut fd).unwrap();
    }

    println!("done with vk & pk");
    // let instances: &[&[&[C::Scalar]]] = &[&[&[constant * a.square() * b.square()]]];
    // let instances: &[&[&[_]]] = &[instances];
    // no public inputs for now
    let mut transcript = ShaWrite::<_, _, Challenge255<_>, sha2::Sha256>::init(vec![]);
    println!("creating proof...");
    create_proof(&params, &pk, &[circuit], &[], OsRng, &mut transcript)
        .expect("proof generation should not fail");
    let proof = transcript.finalize();

    {
        folder.push(format!(
            "sample_circuit_proof_{}{}.data",
            CIRCUIT::NAME,
            index
        ));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        fd.write_all(&proof).unwrap();
    }

    /*
    {
        folder.push(format!(
            "sample_circuit_instance_{}{}.data",
            CIRCUIT::NAME,
            index
        ));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        instances.iter().for_each(|l1| {
            l1.iter().for_each(|l2| {
                l2.iter().for_each(|c: &C::ScalarExt| {
                    c.write(&mut fd).unwrap();
                })
            })
        });
    }
    */

    /*
    let vk = {
        folder.push(format!("sample_circuit_{}.vkey", CIRCUIT::NAME));
        let mut fd = std::fs::File::open(folder.as_path()).unwrap();
        folder.pop();
        VerifyingKey::<C>::read::<_, CIRCUIT::Circuit>(&mut fd, &params).unwrap()
    };
    */
    let params_verifier = params.verifier::<E>(CIRCUIT::PUBLIC_INPUT_SIZE).unwrap();
    let strategy = halo2_proofs::plonk::SingleVerifier::new(&params_verifier);
    let mut transcript = ShaRead::<_, _, Challenge255<_>, sha2::Sha256>::init(&proof[..]);
    halo2_proofs::plonk::verify_proof::<E, _, _, _>(
        &params_verifier,
        &pk.get_vk(),
        strategy,
        &[],
        &mut transcript,
    )
    .unwrap();
    println!("proof was verified");

    let vk = keygen_vk(&params, &default_circuit).expect("keygen_vk should not fail");
    (params, vk, proof)
}
