pub trait OurDelegation {
     fn delegatee_id(&self) -> &String;
     fn accumulator_value(&self) -> &String;
     fn iat(&self) -> &String;
     fn exp(&self) -> &String;
     fn metadata_witnesses(&self) -> &Vec<String>;
     fn permission_witnesses(&self) -> &Vec<String>;
}