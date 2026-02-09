// Credential type as defined in the short paper "A Self Sovereign Identity Approach to Decentralized Access Control with Transitive Delegations"
// by Pieter Jan Vrielynck et Al. available at https://dl.acm.org/doi/10.1145/3649158.3657045
// Authors Pieter-Jan Vrielynck, Tim Van hamme, Rawad Ghostin, Bert Lagaisse, Davy Preuveneers, Wouter JoosenAuthors
// The struct name is the acronym of the first author, Pieter-Jan Vrielynck - PJV.

use crate::delegation::credentials::pjv::pjv_delegator::PJVDelegator;
use crate::delegation::traits::credential::Credential;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt::Display;
use crate::delegation::credentials::pjv::pjv_signature::PJVSignature;

#[derive(Clone, Serialize, Deserialize)]
pub struct PJVDelegationCredential {
    #[serde(rename = "claims")]
    delegator: PJVDelegator,
    #[serde(rename = "auth")]
    signature: PJVSignature,
}


impl PJVDelegationCredential {
    pub fn new(delegator: PJVDelegator, signature: PJVSignature) -> Result<PJVDelegationCredential, String> {
        Ok(PJVDelegationCredential { delegator, signature })
    }

    pub fn delegator(&self) -> &PJVDelegator {&self.delegator}
    pub fn signature(&self) -> &PJVSignature {&self.signature}

    pub fn mut_signature(&mut self) -> &mut PJVSignature { &mut self.signature}
}

impl Credential for PJVDelegationCredential {
    fn credential_type(&self) -> &'static str {
        "PJVDelegationCredential"
    }

    fn from_map(map: Map<String, Value>) -> Result<Self, String> {
        match serde_json::from_value::<PJVDelegationCredential>(Value::Object(map.clone())) {
            Ok(credential) => Ok(credential),
            Err(err) => Err(format!("Error in parsing PJVDelegationCredential: {err}")),
        }
    }

    fn from_string(str: String) -> Result<Self, String>
    {
        match serde_json::from_str::<PJVDelegationCredential>(&str) {
            Ok(credential) => Ok(credential),
            Err(err) => { Err(format!("Failed to deserialize PJVDelegationCredential [{err}]")) }
        }
    }

    fn to_map(&self) -> Result<Map<String, Value>, String> {
        let map_value = match::serde_json::to_value(&self) {
            Ok(map_value) => map_value,
            Err(err) => { return Err(format!("Failed to serialize PJVDelegationCredential to map [{err}]")) }
        };

        match map_value {
            Value::Object(map) => Ok(map),
            _ => Err(format!("Serialized map is not an object [{map_value}]")),
        }
    }

    fn to_string(&self) -> Result<String, String> {
        match serde_json::to_string(&self) {
            Ok(str) => Ok(str),
            Err(err) => { Err(format!("Failed to serialize PJVDelegationCredential to json string [{err}]")) }
        }
    }

    fn retain_only(&mut self, allowed: Vec<String>) -> Result<Vec<usize>, String> {

        let mut removable_indices: Vec<usize> = vec![];

        for (i, operation) in self.delegator.operations().iter().enumerate() {
            if !allowed.contains(&operation) {
                removable_indices.push(i);
            }
        }

        for i in removable_indices.iter().rev() {
            self.delegator.mut_operations().remove(*i);
        }

        Ok(removable_indices)
    }

    fn is_empty(&self) -> bool {
        self.delegator.operations().is_empty() || self.delegator.resource_uri().is_empty()
    }
}

impl Display for PJVDelegationCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {

        match Credential::to_string(self) {
            Ok(result) => write!(f, "{}", result),
            Err(e) => {
                eprintln!("PJVDelegationCredential serialization failed: {}", e);
                Err(std::fmt::Error)
            }
        }
    }
}