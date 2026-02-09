use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct PJVSignature {
    #[serde(rename = "ED25519Signature")]
    pub signature: String,
}

impl PJVSignature {

    pub fn new(signature: String) -> PJVSignature {
        PJVSignature { signature }
    }

    pub fn signature(&self) -> &String {&self.signature}
}