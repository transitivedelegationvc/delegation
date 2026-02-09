use std::fmt::Display;
use serde::Serialize;
use serde_json::{Map, Value};

pub trait Credential: Clone + Display + Serialize  {
    fn credential_type(&self) -> &'static str;

    fn from_map(map: Map<String, Value>) -> Result<Self, String> where Self: Sized;

    fn from_string(str: String) -> Result<Self, String> where Self: Sized;

    fn to_map(&self) -> Result<Map<String, Value>, String>;

    fn to_string(&self) -> Result<String, String>;

    fn retain_only(&mut self, allowed: Vec<String>) -> Result<Vec<usize>, String>;

    fn is_empty(&self) -> bool;
}