use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// DLT Simulator. In theory, it should be a DLT in which issuers post their public data for authentication and from which verifiers retrieve it.
/// In practice, it's just a hashmap wrapped in a Rc struct to share ownership and into a RefCell struct to make it mutable.
pub type DLTSim<T> = Rc<RefCell<HashMap<String, T>>>;

/// Utility function to create a new DLT Sim struct.
pub fn new_dlt_sim<T>() -> DLTSim<T> {
    Rc::new(RefCell::new(HashMap::new()))
}
