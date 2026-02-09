use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use vb_accumulator::prelude::{PublicKey, SetupParams};

#[derive(Clone,Debug,CanonicalSerialize,CanonicalDeserialize)]
pub struct DLTSimAccEntry<E: Pairing> {
    pub public_key: PublicKey<E>,
    pub setup_params: SetupParams<E>
}

impl <E: Pairing> DLTSimAccEntry<E> {
    pub fn new(public_key: PublicKey<E>, setup_params: SetupParams<E>) -> Self {
        DLTSimAccEntry { public_key, setup_params }
    }
}