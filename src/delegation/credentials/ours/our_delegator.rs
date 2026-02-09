use serde::{Deserialize, Serialize};
use std::fmt::Display;
use crate::delegation::credentials::ours::our_delegation::OurDelegation;

#[derive(Clone, Serialize, Deserialize)]
pub struct OurDelegator {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "sub")]
    delegatee_id: String,
    #[serde(rename = "iat")]
    iat: String,
    #[serde(rename = "exp")]
    exp: String,
    #[serde(rename = "av")]
    accumulator_value: String,
    #[serde(rename = "mw")]
    metadata_witnesses: Vec<String>,
    #[serde(rename = "pw")]
    permission_witnesses: Vec<String>,
}

impl OurDelegator {
    pub fn new(id: String, delegatee_id: String, iat: String, exp: String, accumulator_value: String, metadata_witnesses: Vec<String>, permission_witnesses: Vec<String>) -> OurDelegator {
        OurDelegator { id, delegatee_id, iat, exp, accumulator_value, metadata_witnesses, permission_witnesses }
    }

    pub fn id(&self) -> &String {
        &self.id
    }

    pub fn mut_permission_witnesses(&mut self) -> &mut Vec<String> {
        &mut self.permission_witnesses
    }

}

impl OurDelegation for OurDelegator {
    fn delegatee_id(&self) -> &String {
        &self.delegatee_id
    }
    fn accumulator_value(&self) -> &String {
        &self.accumulator_value
    }
    fn iat(&self) -> &String {
        &self.iat
    }
    fn exp(&self) -> &String {
        &self.exp
    }
    fn metadata_witnesses(&self) -> &Vec<String> {
        &self.metadata_witnesses
    }
    fn permission_witnesses(&self) -> &Vec<String> {
        &self.permission_witnesses
    }
}

impl Display for OurDelegator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        match serde_json::to_string(self) {
            Ok(result) => write!(f, "{}", result),
            Err(e) => {
                eprintln!("OurDelegator serialization failed: {}", e);
                Err(std::fmt::Error)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use serde_json::Value;
    use super::*;

    const DELEGATOR_OBJECT: &str =
        r#"{
                "id": "https://vc.example/delegators/d0",
                "sub": "https://vc.example/delegators/d1",
                "iat": "0000000001",
                "exp": "1000000000",
                "av": "accumulator_value_d1",
                "mw": [ "w_delegatee_id_d1", "w_iat_d1", "w_exp_d1" ],
                "pw": [ "w0d1", "w1d1" ]
        }"#;

    #[test]
    fn display_delegator() -> Result<(), String> {

        let delegator_value = match serde_json::from_str::<Value>(DELEGATOR_OBJECT) {
            Ok(delegator_value) => delegator_value,
            Err(e) => return Err(format!("Failed to parse delegator object: [{e}]")),
        };
        let delegator_map = match delegator_value {
            Value::Object(delegator_map) => delegator_map,
            _ => return Err(format!("Parsed delegator {delegator_value} is not an object.")),
        };

        let delegator_value = Value::Object(delegator_map);
        let delegator = match serde_json::from_value::<OurDelegator>(delegator_value) {
            Ok(delegator) => delegator,
            Err(err) => return Err(format!("Failed to parse delegator object: [{err}]")),
        };

        println!("{delegator}");

        Ok(())
    }
}
