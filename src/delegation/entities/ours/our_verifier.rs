use crate::delegation::accumulators::accumulator_verifier::AccumulatorVerifier;
use crate::delegation::credentials::verifiable_presentation::VerifiablePresentation;
use ark_ec::pairing::Pairing;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use josekit::jwk::Jwk;
use crate::delegation::credentials::ours::our_delegation::OurDelegation;
use crate::delegation::credentials::ours::our_delegation_credential::OurDelegationCredential;
use crate::delegation::entities::dtl_sim::DLTSim;
use crate::delegation::entities::ours::dlt_acc_entry::DLTSimAccEntry;
use crate::delegation::entities::verifier::verify_timings;

pub struct OurVerifier<E: Pairing> {
    accumulator_dlt: DLTSim<DLTSimAccEntry<E>>,
    verification_dlt: DLTSim<Jwk>
}

impl<E: Pairing> OurVerifier<E> {
    pub fn new(accumulator_dlt: DLTSim<DLTSimAccEntry<E>>, verification_dlt: DLTSim<Jwk>) -> Result<Self, String> {
        Ok(OurVerifier { accumulator_dlt, verification_dlt })
    }

    fn verify_delegation<D: OurDelegation>(&self, delegation: &D, issuer: &String, permissions: &Vec<String>, now_ns: u128, parallel: bool) -> Result<(), String> {

        verify_timings(now_ns, delegation.iat(), delegation.exp())?;

        let entry = match self.accumulator_dlt.borrow().get(issuer) {
            None => { return Err(format!("Could not find issuer {issuer} in DLTSim")) }
            Some(entry) => { entry.clone() }
        };

        let accumulator_value = delegation.accumulator_value().clone();
        let metadata_witnesses = delegation.metadata_witnesses().clone();
        let metadata = vec![ delegation.delegatee_id().clone(), delegation.iat().clone(), delegation.exp().clone() ];
        let permission_witnesses = delegation.permission_witnesses().clone();

        let delegator_av = AccumulatorVerifier::new(accumulator_value, entry.public_key, entry.setup_params)?;
        delegator_av.verify_accumulator_witnesses(metadata_witnesses, metadata, parallel)?;
        delegator_av.verify_accumulator_witnesses(permission_witnesses, permissions.clone(), parallel)?;

        Ok(())
    }

    pub fn verify_verifiable_presentation(&self, presenter_id: String, signed_jwt: String, parallel: bool) -> Result<(), String>{

        let ecc_pk = match self.verification_dlt.borrow().get(&presenter_id) {
            None => { return Err(format!("Could not find presenter {presenter_id} in DLTSim")) }
            Some(ecc_pk) => { ecc_pk.clone() }
        };

        let vp: VerifiablePresentation<OurDelegationCredential> =
            VerifiablePresentation::<OurDelegationCredential>::from_signed_jwt(signed_jwt, &ecc_pk)?;
        let dc = vp.credential();

        let permissions = dc.permissions().iter().map(|s| s.clone()).collect::<Vec<String>>();

        // Get now timestamp and convert it to nanoseconds
        let now: Duration = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(e) => return Err(format!("Error encountered in computing issuance time: {e}")),
        };
        let now_ns = now.as_nanos();

        // Assert:
        //  - the hierarchy is valid by using each permission and metadata
        //  - for each delegator in hierarchy, check that the issuer of the credential is the
        //    delegatee in the previous credential
        //  - every timing constraint is respected
        let hierarchy = dc.hierarchy();
        let mut previous: &String;
        let mut current: &String = vp.issuer();
        if hierarchy.len() > 0 {
            for delegator in hierarchy.iter().rev() {
                previous = delegator.delegatee_id();
                if previous != current {
                    return Err(format!("Previous delegator {previous} does not match current delegatee {current}"));
                }

                self.verify_delegation(delegator, &previous, &permissions, now_ns, parallel)?;
                current = delegator.id();
            }
        }
        self.verify_delegation(dc, &vp.issuer(), &permissions, now_ns, parallel)?;

        // TODO: generalization of credential, not only DelegationCredential

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use std::time::Duration;
    use josekit::jwk::Jwk;
    use crate::delegation::entities::dtl_sim::new_dlt_sim;
    use crate::delegation::entities::ours::our_issuer::OurIssuer;

    #[test]
    fn verify_vp() -> Result<(), String> {
        type Curve = Bn254;
        let accumulator_dlt: DLTSim<DLTSimAccEntry<Curve>> = new_dlt_sim();
        let verification_dlt: DLTSim<Jwk> = new_dlt_sim();

        let id = String::from("https://vc.example/delegators/d0");
        let previous_vc = None;
        let issuer: OurIssuer<Curve> = OurIssuer::new(id, accumulator_dlt.clone(), verification_dlt.clone())?;
        let context: Vec<String> = vec![String::from("https://www.w3.org/ns/credentials/v2")];
        let credential_id = String::from("http://delegation.example/credentials/1337");
        let valid_from = String::from("2026-01-01T00:00:00Z");
        let delegatee_id = String::from("https://vc.example/delegators/d1");
        let validity_period: Duration = Duration::new(3600, 0);
        let permissions: Vec<String> = vec![String::from("https://vc.example/resources/r1:p0"), String::from("https://vc.example/resources/r1:p1"), String::from("https://vc.example/resources/r1:p2")];
        let vc = issuer.issue_delegation_verifiable_credential(context, credential_id, valid_from, delegatee_id, validity_period, permissions, previous_vc)?;

        let id = String::from("https://vc.example/delegators/d1");
        let previous_vc = Some(vc);
        let issuer: OurIssuer<Bn254> = OurIssuer::new(id, accumulator_dlt.clone(), verification_dlt.clone())?;
        let context: Vec<String> = vec![ String::from("https://www.w3.org/ns/credentials/v2") ];
        let credential_id = String::from("http://delegation.example/credentials/1338");
        let valid_from =  String::from("2026-01-01T00:00:00Z");
        let delegatee_id = String::from("https://vc.example/delegators/d2");
        let validity_period: Duration = Duration::new(3600, 0);
        let permissions: Vec<String> = vec![ String::from("https://vc.example/resources/r1:p0"), String::from("https://vc.example/resources/r1:p1") ];
        let vc = issuer.issue_delegation_verifiable_credential(context, credential_id, valid_from, delegatee_id, validity_period, permissions, previous_vc)?;

        let id = String::from("https://vc.example/delegators/d2");
        let previous_vc = Some(vc);
        let issuer: OurIssuer<Bn254> = OurIssuer::new(id, accumulator_dlt.clone(), verification_dlt.clone())?;
        let context: Vec<String> = vec![ String::from("https://www.w3.org/ns/credentials/v2") ];
        let credential_id = String::from("http://delegation.example/credentials/1339");
        let valid_from =  String::from("2026-01-01T00:00:00Z");
        let delegatee_id = String::from("https://vc.example/delegators/d3");
        let validity_period: Duration = Duration::new(3600, 0);
        let permissions: Vec<String> = vec![ String::from("https://vc.example/resources/r1:p0"), String::from("https://vc.example/resources/r1:p1") ];
        let vc = issuer.issue_delegation_verifiable_credential(context, credential_id, valid_from, delegatee_id, validity_period, permissions, previous_vc)?;

        let id = String::from("https://vc.example/delegators/d3");
        let previous_vc = Some(vc);
        let issuer: OurIssuer<Bn254> = OurIssuer::new(id, accumulator_dlt.clone(), verification_dlt.clone())?;
        let context: Vec<String> = vec![ String::from("https://www.w3.org/ns/credentials/v2") ];
        let credential_id = String::from("http://delegation.example/credentials/1340");
        let valid_from = String::from("2026-01-01T00:00:00Z");
        let delegatee_id = String::from("https://vc.example/delegators/d4");
        let validity_period: Duration = Duration::new(3600, 0);
        let permissions: Vec<String> = vec![ String::from("https://vc.example/resources/r1:p0") ];
        let vc = issuer.issue_delegation_verifiable_credential(context, credential_id, valid_from, delegatee_id.clone(), validity_period, permissions, previous_vc)?;

        let id = delegatee_id.clone();
        let issuer: OurIssuer<Bn254> = OurIssuer::new(id.clone(), accumulator_dlt.clone(), verification_dlt.clone())?;

        let disclosed_permissions: Vec<String> = vec![String::from("https://vc.example/resources/r1:p0")];
        let signed_vp = issuer.issue_delegation_verifiable_presentation(vc, disclosed_permissions)?;

        let verifier = OurVerifier::new(accumulator_dlt, verification_dlt)?;
        verifier.verify_verifiable_presentation(id, signed_vp, true)?;

        Ok(())
    }
}