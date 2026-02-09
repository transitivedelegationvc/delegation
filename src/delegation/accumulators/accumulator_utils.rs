use std::marker::PhantomData;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::Digest;
use sha2::Sha256;

pub struct AccumulatorUtils<E: Pairing> {
    phantom: PhantomData<E>,
}

impl <E: Pairing> AccumulatorUtils<E> {
    /// Maps strings to scalar values by concatenating key and value and hashing them.
    ///
    /// # Arguments
    ///
    /// * `key` - Name of the element.
    /// * `value` - Value of the element.
    ///
    /// # Returns
    /// This function returns the converted scalar.
    pub fn convert_string_to_scalar(value: &String) -> E::ScalarField {

        let mut hasher = Sha256::new();
        hasher.update(value);
        let result = hasher.finalize();

        E::ScalarField::from_be_bytes_mod_order(&result.as_slice())

    }


    /// Utility function to serialize structs that implement CanonicalSerialize like accumulators and witnesses.
    ///
    /// # Arguments
    /// * `element` - Element to be serialized.
    ///
    /// # Returns
    /// This function returns a result wrapping the encoding of the element or a string illustrating the error, if it occurs.
    pub fn serialize<S>(element: &S) -> Result<String, String>
    where S: CanonicalSerialize {
        let mut compressed_bytes: Vec<u8> = Vec::new();
        match element.serialize_compressed(&mut compressed_bytes) {
            Ok(()) => { () }
            Err(err) => { return Err(format!("Error in serialization of element: [{err}]")) }
        };

        Ok(multibase::Base::Base64Url.encode(compressed_bytes))
    }


    /// Utility function to deserialize structs that implement CanonicalDeserialize like accumulators and witnesses.
    ///
    /// # Arguments
    ///
    /// * `encoded_element` - String containing the element to be deserialized.
    ///
    /// # Returns
    /// This function returns a result wrapping the deserialization of element or a string illustrating the error, if it occurs.
    pub fn deserialize<D>(encoded_element: &String) -> Result<D, String>
    where D: CanonicalDeserialize {
        let decoded = match multibase::Base::Base64Url.decode(encoded_element) {
            Ok(byte_array) => { byte_array }
            Err(err) => { return Err(format!("Error in decoding element: [{err}]")) }
        };
        let deserialized_element = match CanonicalDeserialize::deserialize_compressed(&*decoded) {
            Ok(element) => { element },
            Err(err) => { return Err(format!("Error in deserializing element: [{err}]")) }
        };

        Ok(deserialized_element)
    }
}
