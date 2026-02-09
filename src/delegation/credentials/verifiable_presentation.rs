use crate::delegation::credentials::verifiable_credential::VerifiableCredential;
use crate::delegation::traits::credential::Credential;
use josekit::jwk::Jwk;
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation<C: Credential> {
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "issuer")]
    issuer: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(rename = "credentialSubject")]
    credential: C,
}

impl <C: Credential> VerifiablePresentation<C> {

    pub fn new(context: Vec<String>, credential_type: Vec<String>, id: String, issuer: String,
               valid_from: String, credential: C) -> Self {

        VerifiablePresentation { context, credential_type, id, issuer, valid_from, credential }
    }

    pub fn context(&self) -> &Vec<String> { &self.context }
    pub fn credential_type(&self) -> &Vec<String> { &self.credential_type }
    pub fn id(&self) -> &String { &self.id }
    pub fn issuer(&self) -> &String { &self.issuer }
    pub fn valid_from(&self) -> &String { &self.valid_from }
    pub fn credential(&self) -> &C { &self.credential }

    pub fn mut_credential(&mut self) -> &mut C { &mut self.credential }

    pub fn from_verifiable_credential(vc: VerifiableCredential<C>, claims_to_keep: Vec<String>) -> Result<Self, String> {
        let mut vc = VerifiablePresentation::new(
            vc.context().clone(),
            vc.credential_type().clone(),
            vc.id().clone(),
            vc.issuer().clone(),
            vc.valid_from().clone(),
            vc.credential().clone(),
        );

        // Only keep the claims we want to disclose, remove the rest
        let _removed_indices = vc.credential.retain_only(claims_to_keep)?;
        // TODO: check for no removal using the result?

        match vc.credential.is_empty() {
            true => Err(String::from("VerifiablePresentation is empty")),
            false => Ok(vc),
        }
    }

    pub fn from_signed_jwt<CC: Credential + DeserializeOwned>(jwt: String, public_key: &Jwk) -> Result<VerifiablePresentation<CC>, String> {

        let verifier = match EdDSA.verifier_from_jwk(public_key) {
            Ok(verifier) => { verifier}
            Err(err) => { return Err(format!("Could not create verifier [{}]", err.to_string())) }
        };

        let (payload, _) = match jwt::decode_with_verifier(jwt, &verifier) {
            Ok((payload, header)) => { (payload, header) }
            Err(err) => { return Err(format!("Failed to decode and verify jwt [{}]", err.to_string())) }
        };

        let vp_map = Value::Object(payload.claims_set().clone());

        match serde_json::from_value(vp_map) {
            Ok(vp) => { Ok(vp) }
            Err(err) => { Err(format!("Could not deserialize VerifiablePresentation [{}]", err.to_string())) }
        }

    }

    pub fn to_signed_jwt(&self, private_key: &Jwk) -> Result<String, String> {

        let map_value = match serde_json::to_value(self) {
            Ok(map_value) => map_value,
            Err(err) => { return Err(format!("Failed to encode VerifiablePresentation to a value {err}")) }
        };

        let map = match map_value {
            Value::Object(map) => map,
            _ => { return Err(String::from("VerifiablePresentation is not an object")); }
        };

        let mut header: JwsHeader = JwsHeader::new();
        header.set_algorithm("P256");

        let payload: JwtPayload = match JwtPayload::from_map(map) {
            Ok(payload) => { payload }
            Err(err) => { return Err(format!("Failed to encode payload from map: [{err}]")); }
        };

        let signer = match EdDSA.signer_from_jwk(private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        let jwt = match jwt::encode_with_signer(&payload, &header, &signer) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to encode and sign jwt: [{err}]")); }
        };

        Ok(jwt)
    }
}

impl <C: Credential> Display for VerifiablePresentation<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(result) => write!(f, "{}", result),
            Err(e) => {
                eprintln!("Verifiable Presentation serialization failed: {}", e);
                Err(std::fmt::Error)
            }
        }
    }
}
