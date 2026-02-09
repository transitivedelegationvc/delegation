use std::thread;
use std::thread::JoinHandle;
use ark_ec::pairing::Pairing;
use vb_accumulator::prelude::{Accumulator, MembershipWitness, PositiveAccumulator, PublicKey, SetupParams};
use crate::delegation::accumulators::accumulator_utils::AccumulatorUtils;

pub struct AccumulatorVerifier<E: Pairing> {
    accumulator_value: PositiveAccumulator<E>,
    public_key: PublicKey<E>,
    params: SetupParams<E>
}

impl <E:Pairing> AccumulatorVerifier<E> {

    pub fn new(accumulator_value: String, public_key: PublicKey<E>, params: SetupParams<E>) -> Result<Self, String> {
        let accumulator_value: PositiveAccumulator<E> = AccumulatorUtils::<E>::deserialize(&accumulator_value)?;

        Ok(AccumulatorVerifier { accumulator_value, public_key, params })
    }

    fn verify_accumulator_witness(accumulator_value: &PositiveAccumulator<E>, witness: &String, element: &String, public_key: &PublicKey<E>, params: &SetupParams<E>) -> Result<(), String> {
        let element_value: E::ScalarField = AccumulatorUtils::<E>::deserialize(&element)?;
        let witness_value: MembershipWitness<E::G1Affine> = AccumulatorUtils::<E>::deserialize(&witness)?;

        match accumulator_value.verify_membership(&element_value, &witness_value, &public_key, &params) {
            true => Ok(()),
            false => Err(format!("Could not verify membership for element {element}"))
        }
    }

    pub fn verify_accumulator_witnesses(&self, witnesses: Vec<String>, elements: Vec<String>, parallel: bool) -> Result<(), String> {

        if elements.len() != witnesses.len() {
            return Err(format!("Witnesses length does not match elements [{} - {}]", elements.len(), witnesses.len()));
        }

        if !parallel {
            for (witness, element) in witnesses.iter().zip(elements.iter()) {
                AccumulatorVerifier::verify_accumulator_witness(&self.accumulator_value, witness, element, &self.public_key, &self.params)?;
            }
        } else {

            let mut threads: Vec<JoinHandle<Result<(), String>>> = vec![];

            for (witness, element) in witnesses.iter().zip(elements.iter()) {

                let accumulator_value = self.accumulator_value.clone();
                let witness = witness.clone();
                let element = element.clone();
                let public_key = self.public_key.clone();
                let params = self.params.clone();

                let thread = thread::spawn(move || {
                    match AccumulatorVerifier::verify_accumulator_witness(&accumulator_value, &witness, &element, &public_key, &params) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(e)
                    }
                });
                threads.push(thread);
            }

            for thread in threads {
                match thread.join() {
                    Ok(_) => {}
                    Err(_) => {
                        return Err(String::from("Thread verifying witness panicked"));
                    }
                }
            }
        }

        Ok(())
    }

}