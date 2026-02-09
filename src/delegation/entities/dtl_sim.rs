use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub type DLTSim<T> = Rc<RefCell<HashMap<String, T>>>;

pub fn new_dlt_sim<T>() -> DLTSim<T>{
    Rc::new(RefCell::new(HashMap::new()))
}