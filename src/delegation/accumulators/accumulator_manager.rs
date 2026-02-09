use ark_ec::pairing::Pairing;
use vb_accumulator::positive::{Accumulator, PositiveAccumulator};
use vb_accumulator::prelude::{ SecretKey, SetupParams};
use crate::delegation::accumulators::accumulator_utils::AccumulatorUtils;
use crate::delegation::accumulators::in_memory_state::InMemoryState;

pub struct AccumulatorManager<'sk, E: Pairing> {
    secret_key: &'sk SecretKey<E::ScalarField>,
    accumulator: PositiveAccumulator<E>,
    state: InMemoryState<E::ScalarField>,
}

impl <'keypair, E: Pairing>AccumulatorManager<'keypair, E> {

    pub fn new(secret_key: &'keypair SecretKey<E::ScalarField>, params: &'keypair SetupParams<E>) -> AccumulatorManager<'keypair, E> {

        let accumulator = PositiveAccumulator::<E>::initialize(params);
        let state: InMemoryState<E::ScalarField> = InMemoryState::new();
        AccumulatorManager { secret_key, accumulator, state}

    }

    pub fn clone_accumulator(&self) -> Result<String, String> {
        AccumulatorUtils::<E>::serialize(&self.accumulator)
    }

    pub fn add_element(&mut self, element: E::ScalarField) -> Result<(), String> {
        match self.accumulator.add(element, &self.secret_key, &mut self.state) {
            Ok(accumulator) => {
                self.accumulator = accumulator;
                Ok(())
            }
            Err(err) => { Err(format!("Error in adding single element: [{:?}]", err))}
        }
    }

    pub fn add_elements(&mut self, elements: Vec<E::ScalarField>) -> Result<(), String> {
        match self.accumulator.add_batch(elements, &self.secret_key, &mut self.state) {
            Ok(accumulator) => {
                self.accumulator = accumulator;
                Ok(())
            }
            Err(err) => { Err(format!("Error in adding batch elements: [{:?}]", err)) }
        }
    }

    pub fn remove_element(&mut self, element: E::ScalarField) -> Result<(), String> {
        match self.accumulator.remove(&element, &self.secret_key, &mut self.state) {
            Ok(accumulator) => {
                self.accumulator = accumulator;
                Ok(())
            }
            Err(err) => { Err(format!("Error in removing single element: [{:?}]", err))}
        }
    }

    pub fn remove_elements(&mut self, elements: &[E::ScalarField]) -> Result<(), String> {
        match self.accumulator.remove_batch(elements, &self.secret_key, &mut self.state) {
            Ok(accumulator) => {
                self.accumulator = accumulator;
                Ok(())
            }
            Err(err) => { Err(format!("Error in removing batch elements: [{:?}]", err)) }
        }
    }

    pub fn compute_witness(&mut self, element: E::ScalarField) -> Result<String, String> {
        let witness = self.accumulator.compute_membership_witness(&element, &self.secret_key);
        AccumulatorUtils::<E>::serialize(&witness)
    }

    pub fn compute_witnesses(&mut self, elements: &[E::ScalarField]) -> Result<Vec<String>, String> {
        let witnesses = self.accumulator.compute_membership_witnesses_for_batch(elements, &self.secret_key);
        let mut result = vec![];

        for witness in witnesses {
            result.push(AccumulatorUtils::<E>::serialize(&witness)?);
        }
        Ok(result)

    }

}
