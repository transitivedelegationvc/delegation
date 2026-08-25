use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use vb_accumulator::prelude::{PublicKey, SetupParams};

/// Utility structure to be kept in the DLTSimulator for managing accumulators (which is just a hashmap).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLTSimAccEntry<E: Pairing> {
    pub public_key: PublicKey<E>,
    pub setup_params: SetupParams<E>,
}

impl<E: Pairing> DLTSimAccEntry<E> {
    /// Creates a new instance of DLTSimAccEntry.
    ///
    /// # Arguments
    /// * `public_key` - Accumulator manager's (issuer) public key.
    /// * `setup_params` - Accumulator manager's (issuer) setup parameters.
    ///
    /// # Returns
    /// An instance of DLTSimAccEntry.
    pub fn new(public_key: PublicKey<E>, setup_params: SetupParams<E>) -> Self {
        DLTSimAccEntry {
            public_key,
            setup_params,
        }
    }
}
