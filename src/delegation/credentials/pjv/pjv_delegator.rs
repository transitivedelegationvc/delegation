use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize)]
pub struct PJVDelegator {
    #[serde(rename = "owner")]
    owner: String,
    #[serde(rename = "iss")]
    iss: String,
    #[serde(rename = "sub")]
    sub: String,
    #[serde(rename = "iat")]
    iat: String,
    #[serde(rename = "exp")]
    exp: String,
    #[serde(rename = "uri")]
    resource_uri: String,
    #[serde(rename = "ops")]
    operations: Vec<String>,
    #[serde(rename = "hierarchy")]
    hierarchy: String,
}

impl PJVDelegator {
    pub fn new(owner: String, iss: String, sub: String, iat: String, exp: String, resource_uri: String, operations: Vec<String>, hierarchy: String) -> PJVDelegator {
        PJVDelegator { owner, iss, sub, iat, exp, resource_uri, operations, hierarchy}
    }

    pub fn owner(&self) -> &String {&self.owner}
    pub fn iss(&self) -> &String {&self.iss}
    pub fn sub(&self) -> &String {&self.sub}
    pub fn iat(&self) -> &String {&self.iat}
    pub fn exp(&self) -> &String {&self.exp}
    pub fn resource_uri(&self) -> &String {&self.resource_uri}
    pub fn operations(&self) -> &Vec<String> {&self.operations}
    pub fn mut_operations(&mut self) -> &mut Vec<String> {&mut self.operations}
    pub fn hierarchy(&self) -> &String {&self.hierarchy}
}

impl Display for PJVDelegator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        match serde_json::to_string(self) {
            Ok(result) => write!(f, "{}", result),
            Err(e) => {
                eprintln!("PJVDelegator serialization failed: {}", e);
                Err(std::fmt::Error)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const DELEGATOR_OBJECT: &str =
        r#"{
                "owner": "https://vc.example/delegators/d0",
                "iss": "https://vc.example/delegators/d0",
                "sub": "https://vc.example/delegators/d1",
                "iat": "0000000001",
                "exp": "1000000000",
                "uri": "https://api.example.edu/main-door",
                "ops": ["GET"],
                "hierarchy": ""
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
        let delegator = match serde_json::from_value::<PJVDelegator>(delegator_value) {
            Ok(delegator) => delegator,
            Err(err) => return Err(format!("Failed to parse delegator object: [{err}]")),
        };

        println!("{delegator}");

        Ok(())
    }
}
