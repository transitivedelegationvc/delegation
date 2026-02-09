use crate::delegation::traits::credential::Credential;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifiableCredential<C: Credential> {
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

impl<C: Credential> VerifiableCredential<C> {
    pub fn new(context: Vec<String>, id: String, issuer: String, valid_from: String, credential: C) -> VerifiableCredential<C> {
        let credential_type = vec![ credential.credential_type().to_string() ];
        VerifiableCredential { context, credential_type, id, issuer, valid_from, credential }
    }

    pub fn context(&self) -> &Vec<String> { &self.context }

    pub fn credential_type(&self) -> &Vec<String> { &self.credential_type }

    pub fn id(&self) -> &String { &self.id }

    pub fn issuer(&self) -> &String { &self.issuer }

    pub fn valid_from(&self) -> &String { &self.valid_from }

    pub fn credential(&self) -> &C { &self.credential }
}

impl<C: Credential> Display for VerifiableCredential<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {

        match serde_json::to_string(self) {
            Ok(result) => write!(f, "{}", result),
            Err(e) => {
                eprintln!("Verifiable Credential serialization failed: {}", e);
                Err(std::fmt::Error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::delegation::credentials::verifiable_credential::VerifiableCredential;
    use serde_json::{Map, Value};
    use crate::delegation::credentials::ours::our_delegation_credential::OurDelegationCredential;

    #[test]
    fn parse_dc() -> Result<(), String> {

        let vcs: Vec<&str> = vec![RAW_VC_D1, RAW_VC_D2, RAW_VC_D3, RAW_VC_D4];
        let names: Vec<&str> = vec!["D1", "D2", "D3", "D4"];

        for (name, vc) in names.iter().zip(vcs.iter()) {
            let value_raw_vc: Value = match serde_json::from_str::<Value>(vc) {
                Ok(value_raw_vc) => { value_raw_vc }
                Err(err) => { return Err(format!("Failed to parse [{name}] Raw Verifiable Credential from string. [{err}]")); }
            };

            let raw_vc = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
                Ok(raw_vc) => raw_vc,
                Err(err) => { return Err(format!("Failed to parse [{name}] Raw Verifiable Credential from Value. [{err}]")); }
            };

            let vc = match serde_json::from_value::<VerifiableCredential<OurDelegationCredential>>(Value::Object(raw_vc)) {
                Ok(vc) => vc,
                Err(err) => { return Err(format!("Error in serialization of vc: [{err}]"))}
            };

            println!("Parsed VC [{name}]: {vc}");

        }

        Ok(())
    }

    pub const RAW_VC_D1: &str = r#"{
    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
    "type": [ "DelegationCredential" ],
    "id": "http://delegation.example/credentials/1337",
    "issuer": "https://vc.example/delegators/d0",
    "validFrom": "2010-01-01T00:00:00Z",

    "credentialSubject": {
        "delegatee_id": "https://vc.example/delegators/d1",
        "accumulator_value": "accumulator_value_d1",
        "iat": "0000000001",
        "exp": "1000000000",
        "permissions": [ "https://vc.example/resources/r1:p0", "https://vc.example/resources/r1:p1", "https://vc.example/resources/r1:p2" ],
        "metadata_witnesses": [ "w_delegatee_id_d1", "w_iat_d1", "w_exp_d1" ],
        "permission_witnesses": [ "w0d1", "w1d1", "w2d1" ],
        "hierarchy": []
    }
}"#;

    pub const RAW_VC_D2: &str = r#"{
    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
    "type": [ "DelegationCredential" ],
    "id": "http://delegation.example/credentials/1338",
    "issuer": "https://vc.example/delegators/d1",
    "validFrom": "2010-01-01T00:00:00Z",

    "credentialSubject": {
        "delegatee_id": "https://vc.example/delegators/d2",
        "accumulator_value": "accumulator_value_d2",
        "iat": "0000000002",
        "exp": "1000000000",
        "permissions": [ "https://vc.example/resources/r1:p0", "https://vc.example/resources/r1:p1" ],
        "metadata_witnesses": [ "w_delegatee_id_d2", "w_iat_d2", "w_exp_d2" ],
        "permission_witnesses": [ "w0d2", "w1d2" ],
        "hierarchy": [
            {
                "id": "https://vc.example/delegators/d0",
                "delegatee_id": "https://vc.example/delegators/d1",
                "iat": "0000000001",
                "exp": "1000000000",
                "accumulator_value": "accumulator_value_d1",
                "metadata_witnesses": [ "w_delegatee_id_d1", "w_iat_d1", "w_exp_d1" ],
                "permission_witnesses": [ "w0d1", "w1d1" ]
            }
        ]
    }
}"#;

    pub const RAW_VC_D3: &str = r#"{
    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
    "type": [ "DelegationCredential" ],
    "id": "http://delegation.example/credentials/1339",
    "issuer": "https://vc.example/delegators/d2",
    "validFrom": "2010-01-01T00:00:00Z",

    "credentialSubject": {
        "delegatee_id": "https://vc.example/delegators/d3",
        "accumulator_value": "accumulator_value_d3",
        "iat": "0000000003",
        "exp": "1000000000",
        "permissions": [ "https://vc.example/resources/r1:p0", "https://vc.example/resources/r1:p1" ],
        "metadata_witnesses": [ "w_delegatee_id_d3", "w_iat_d3", "w_exp_d3" ],
        "permission_witnesses": [ "w0d3", "w1d3" ],
        "hierarchy": [
            {
                "id": "https://vc.example/delegators/d0",
                "delegatee_id": "https://vc.example/delegators/d1",
                "iat": "0000000001",
                "exp": "1000000000",
                "accumulator_value": "accumulator_value_d1",
                "metadata_witnesses": [ "w_delegatee_id_d1", "w_iat_d1", "w_exp_d1" ],
                "permission_witnesses": [ "w0d1", "w1d1" ]
            },
            {
                "id": "https://vc.example/delegators/d1",
                "delegatee_id": "https://vc.example/delegators/d2",
                "iat": "0000000002",
                "exp": "1000000000",
                "accumulator_value": "accumulator_value_d2",
                "metadata_witnesses": [ "w_delegatee_id_d2", "w_iat_d2", "w_exp_d2" ],
                "permission_witnesses": [ "w0d2", "w1d2" ]
            }
        ]
    }
}"#;


    pub const RAW_VC_D4: &str = r#"{
    "@context": [ "https://www.w3.org/ns/credentials/v2" ],
    "type": [ "DelegationCredential" ],
    "id": "http://delegation.example/credentials/1340",
    "issuer": "https://vc.example/delegators/d3",
    "validFrom": "2010-01-01T00:00:00Z",

    "credentialSubject": {
        "delegatee_id": "https://vc.example/delegators/d4",
        "accumulator_value": "accumulator_value_d4",
        "iat": "0000000004",
        "exp": "1000000000",
        "permissions": [ "https://vc.example/resources/r1:p0" ],
        "metadata_witnesses": [ "w_delegatee_id_d4", "w_iat_d4", "w_exp_d4" ],
        "permission_witnesses": [ "w0d4" ],
        "hierarchy": [
            {
                "id": "https://vc.example/delegators/d0",
                "delegatee_id": "https://vc.example/delegators/d1",
                "iat": "0000000001",
                "exp": "1000000000",
                "accumulator_value": "accumulator_value_d1",
                "metadata_witnesses": [ "w_delegatee_id_d1", "w_iat_d1", "w_exp_d1" ],
                "permission_witnesses": [ "w0d1" ]
            },
            {
                "id": "https://vc.example/delegators/d1",
                "delegatee_id": "https://vc.example/delegators/d2",
                "iat": "0000000002",
                "exp": "1000000000",
                "accumulator_value": "accumulator_value_d2",
                "metadata_witnesses": [ "w_delegatee_id_d2", "w_iat_d2", "w_exp_d2" ],
                "permission_witnesses": [ "w0d2" ]
            },
            {
                "id": "https://vc.example/delegators/d2",
                "delegatee_id": "https://vc.example/delegators/d3",
                "iat": "0000000003",
                "exp": "1000000000",
                "accumulator_value": "accumulator_value_d3",
                "metadata_witnesses": [ "w_delegatee_id_d3", "w_iat_d3", "w_exp_d3" ],
                "permission_witnesses": [ "w0d3" ]
            }
        ]
    }
}"#;

}