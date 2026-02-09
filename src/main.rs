use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use delegation::delegation::entities::dtl_sim::{new_dlt_sim, DLTSim};
use delegation::delegation::entities::ours::dlt_acc_entry::DLTSimAccEntry;
use delegation::delegation::entities::ours::our_issuer::OurIssuer;
use delegation::delegation::entities::ours::our_verifier::OurVerifier;
use delegation::delegation::entities::pjv::pjv_issuer_verifier::PJVIssuerVerifier;
use josekit::jwk::Jwk;
use std::env;
use std::str::FromStr;
use std::time::Duration;
use delegation::benchmark::Benchmark;
use delegation::csv_writer::CSVWriter;

fn fetch_usize_env_variable(variable_name: &str) -> Result<usize, String> {
    let variable = fetch_env_variable(variable_name)?;
    match usize::from_str(variable.as_str()) {
        Ok(variable) => Ok(variable),
        Err(err) => {
            Err(format!("The environment variable {variable_name} cannot be parsed to i32 [{err}]"))
        }
    }
}

fn fetch_env_variable(variable_name: &str) -> Result<String, String> {
    match env::var(&variable_name) {
        Ok(variable) => Ok(variable),
        Err(err) => {
            Err(format!("The environment variable {variable_name} is not set [{err}]"))
        },
    }
}

fn get<I>(vector: &Vec<I>, i: usize) -> Result<&I, String> {
    match vector.get(i) {
        Some(item) => Ok(item),
        None => { Err(format!("No item found at index {i}")) },
    }
}

fn setup_ours<E: Pairing>(delegators_size: usize) ->
    Result<(
        DLTSim<DLTSimAccEntry<E>>,
        DLTSim<Jwk>,
        Vec<String>,
        Vec<String>,
        Vec<OurIssuer<E>>,
        Vec<String>,
        String,
        Duration
    ), String>
{
    let accumulator_dlt: DLTSim<DLTSimAccEntry<E>> = new_dlt_sim();
    let verification_dlt: DLTSim<Jwk> = new_dlt_sim();

    let mut delegator_ids: Vec<String> = vec![];
    let mut credential_ids: Vec<String> = vec![];
    let mut delegators: Vec<OurIssuer<E>> = vec![];

    for i in 0..delegators_size {
        let id = format!("https://vc.example/delegators/d{i}");
        delegator_ids.push(id.clone());

        let credential_id = format!("http://delegation.example/credentials/{i}");
        credential_ids.push(credential_id.clone());

        let delegator = OurIssuer::new(id, accumulator_dlt.clone(), verification_dlt.clone())?;
        delegators.push(delegator);
    }

    let id = format!("https://vc.example/delegators/d{delegators_size}");
    delegator_ids.push(id);

    let context: Vec<String> = vec![ String::from("https://www.w3.org/ns/credentials/v2") ];

    let valid_from =  String::from("2026-01-01T00:00:00Z");
    let validity_period: Duration = Duration::new(3600, 0);

    Ok((accumulator_dlt, verification_dlt, delegator_ids, credential_ids, delegators, context, valid_from, validity_period))

}

fn setup_pjvs(delegators_size: usize) ->
Result<(
    Vec<String>,
    Vec<String>,
    Vec<PJVIssuerVerifier>,
    Vec<String>,
    String,
    Duration,
    String,
    String
), String>
{
    let encryption_dlt: DLTSim<Jwk> = new_dlt_sim();
    let verification_dlt: DLTSim<Jwk> = new_dlt_sim();

    let mut delegator_ids: Vec<String> = vec![];
    let mut credential_ids: Vec<String> = vec![];
    let mut delegators: Vec<PJVIssuerVerifier> = vec![];

    for i in 0..delegators_size {
        let id = format!("https://vc.example/delegators/d{i}");
        delegator_ids.push(id.clone());

        let credential_id = format!("http://delegation.example/credentials/{i}");
        credential_ids.push(credential_id.clone());

        let delegator = PJVIssuerVerifier::new(id, encryption_dlt.clone(), verification_dlt.clone())?;
        delegators.push(delegator);
    }

    let id = format!("https://vc.example/delegators/d{delegators_size}");
    delegator_ids.push(id);

    let valid_from =  String::from("2026-01-01T00:00:00Z");
    let validity_period: Duration = Duration::new(3600, 0);

    let owner = get(&delegator_ids, 0)?.clone();
    let resource_uri: String = String::from("https://vc.example/resources/r1");

    let context: Vec<String> = vec![ String::from("https://www.w3.org/ns/credentials/v2") ];

    Ok((delegator_ids, credential_ids, delegators, context, valid_from, validity_period, owner, resource_uri))

}

fn iterate_over_delegators<E: Pairing>(max_delegators: usize, total_permissions: usize, disclose: usize, iterations: i8) -> Result<(), String> {

    if disclose > total_permissions {
        return Err(format!("Cannot disclose more permissions than those included in the credential [{disclose} > {total_permissions}]"))
    } else if disclose < 1 {
        return Err(format!("Permissions to disclose must be at least 1 [{disclose}]"))
    }

    const IOD_VC_ISSUANCE: &str = "iod_vc_issuance";
    const IOD_VP_LENGTH: &str = "iod_vp_jwt_length";
    const IOD_VP_ISSUANCE: &str = "iod_vp_issuance";
    const IOD_VP_VERIFICATION: &str = "iod_vp_verification";

    let mut iod_vc_issuance = disclose.to_string();
    iod_vc_issuance.push('_');
    iod_vc_issuance.push_str(IOD_VC_ISSUANCE);
    let mut iod_vp_length = disclose.to_string();
    iod_vp_length.push('_');
    iod_vp_length.push_str(IOD_VP_LENGTH);
    let mut iod_vp_issuance = disclose.to_string();
    iod_vp_issuance.push('_');
    iod_vp_issuance.push_str(IOD_VP_ISSUANCE);
    let mut iod_vp_verification = disclose.to_string();
    iod_vp_verification.push('_');
    iod_vp_verification.push_str(IOD_VP_VERIFICATION);

    let mut writer = CSVWriter::new(vec![String::from("Ours"), String::from("PJVs")])?;
    writer.add_file(&iod_vc_issuance)?;
    writer.add_file(&iod_vp_length)?;
    writer.add_file(&iod_vp_issuance)?;
    writer.add_file(&iod_vp_verification)?;

    // =============================================================================================
    // ==================================        OURS        =======================================
    // =============================================================================================
    let mut our_vps: Vec<String> = vec![];
    let mut our_vc_issuance_duration: Vec<Duration> = vec![];
    let mut our_vp_issuance_duration: Vec<Duration> = vec![];
    let mut our_vp_verification_duration: Vec<Duration> = vec![];

    let (accumulator_dlt, verification_dlt, delegator_ids, credential_ids, delegators, context, valid_from, validity_period) = setup_ours(max_delegators)?;

    let mut permissions: Vec<String> = vec![];
    for i in 0..total_permissions {
        permissions.push(format!("https://vc.example/resources/r1:p{i}"));
    }

    let mut vc = None;
    for i in 0..max_delegators {
        let delegator = get(&delegators, i)?;
        let credential_id = get(&credential_ids, i)?;
        let delegatee_id = get(&delegator_ids, i + 1)?;

        let (duration, result_vc) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_credential(
                context.clone(), credential_id.clone(), valid_from.clone(), delegatee_id.clone(),
                validity_period.clone(), permissions.clone(), vc.clone()
            ),
            iterations
        )?;
        our_vc_issuance_duration.push(duration);

        let disclosures = match permissions.get(0..disclose) {
            Some(disclosures) => disclosures,
            None => return Err(String::from("Could not get slice from permissions"))
        }.to_vec();

        let (duration, result_vp) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_presentation(
                result_vc.clone(), disclosures.clone()
            ),
            iterations
        )?;
        our_vp_issuance_duration.push(duration);

        our_vps.push(result_vp);

        vc = Some(result_vc);
    }

    let verifier: OurVerifier<E> = OurVerifier::new(accumulator_dlt, verification_dlt)?;

    for (i, vp) in our_vps.iter().enumerate() {
        let presenter_id = get(&delegator_ids, i)?;
        let (duration, _) = Benchmark::benchmark_function(|| verifier.verify_verifiable_presentation(presenter_id.clone(), vp.clone(), true), iterations)?;
        our_vp_verification_duration.push(duration);
    }

    // =============================================================================================
    // ==================================        PJVS        =======================================
    // =============================================================================================
    let mut pjv_vps: Vec<String> = vec![];
    let mut pjv_vc_issuance_duration: Vec<Duration> = vec![];
    let mut pjv_vp_issuance_duration: Vec<Duration> = vec![];
    let mut pjv_vp_verification_duration: Vec<Duration> = vec![];

    let (delegator_ids, credential_ids, delegators, context, valid_from, validity_period, owner, resource_uri) = setup_pjvs(max_delegators)?;

    let mut operations: Vec<String> = vec![];
    for i in 0..total_permissions {
        operations.push(format!("p{i}"));
    }

    let mut vc = None;
    for i in 0..max_delegators {
        let delegator = get(&delegators, i)?;
        let credential_id = get(&credential_ids, i)?;
        let delegatee_id = get(&delegator_ids, i + 1)?;

        let (duration, result_vc) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_credential(
                context.clone(), credential_id.clone(), valid_from.clone(), delegatee_id.clone(),
                validity_period.clone(), owner.clone(), resource_uri.clone(), operations.clone(), vc.clone()
            ),
            iterations
        )?;
        pjv_vc_issuance_duration.push(duration);

        let disclosures = match operations.get(0..disclose) {
            Some(disclosures) => disclosures,
            None => return Err(String::from("Could not get slice from operations"))
        }.to_vec();

        let (duration, result_vp) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_presentation(
                result_vc.clone(), disclosures.clone()
            ),
            iterations
        )?;
        pjv_vp_issuance_duration.push(duration);

        pjv_vps.push(result_vp);

        vc = Some(result_vc);
    }

    let verifier = get(&delegators, 0)?;

    for (i, vp) in pjv_vps.iter().enumerate() {
        let presenter_id = get(&delegator_ids, i)?;
        let (duration, _) = Benchmark::benchmark_function(|| verifier.verify_verifiable_presentation(presenter_id.clone(), vp.clone()), iterations)?;

        pjv_vp_verification_duration.push(duration);
    }

    let our_vc_issuance_ms: Vec<u128> = our_vc_issuance_duration.iter().map(Duration::as_micros).collect();
    let pjv_vc_issuance_ms: Vec<u128> = pjv_vc_issuance_duration.iter().map(Duration::as_micros).collect();
    for vc_issuance_ms in our_vc_issuance_ms.iter().zip(pjv_vc_issuance_ms.iter()) {
        writer.write_record_to_file(&iod_vc_issuance, vc_issuance_ms)?;
    }

    let our_vp_lengths: Vec<usize> = our_vps.iter().map(|v| v.len()).collect();
    let pjv_vp_lengths: Vec<usize> = pjv_vps.iter().map(|v| v.len()).collect();
    for vp_length in our_vp_lengths.iter().zip(pjv_vp_lengths.iter()) {
        writer.write_record_to_file(&iod_vp_length, vp_length)?;
    }

    let our_vp_issuance_ms: Vec<u128> = our_vp_issuance_duration.iter().map(Duration::as_micros).collect();
    let pjv_vp_issuance_ms: Vec<u128> = pjv_vp_issuance_duration.iter().map(Duration::as_micros).collect();
    for vp_issuance_duration in our_vp_issuance_ms.iter().zip(pjv_vp_issuance_ms.iter()) {
        writer.write_record_to_file(&iod_vp_issuance, vp_issuance_duration)?;
    }

    let our_vp_verification_ms: Vec<u128> = our_vp_verification_duration.iter().map(Duration::as_micros).collect();
    let pjv_vp_verification_ms: Vec<u128> = pjv_vp_verification_duration.iter().map(Duration::as_micros).collect();
    for vp_verification_ms in our_vp_verification_ms.iter().zip(pjv_vp_verification_ms.iter()) {
        writer.write_record_to_file(&iod_vp_verification, vp_verification_ms)?;
    }

    Ok(())
}

fn iterate_over_permissions<E: Pairing>(total_delegators: usize, max_permissions: usize, iterations: i8) -> Result<(), String> {

    const IOP_VC_ISSUANCE: &str = "iop_vc_issuance";
    const IOP_VP_LENGTH: &str = "iop_vp_jwt_length";
    const IOP_VP_ISSUANCE: &str = "iop_vp_issuance";
    const IOP_VP_VERIFICATION: &str = "iop_vp_verification";
    let mut writer = CSVWriter::new(vec![String::from("Ours"), String::from("PJVs")])?;
    writer.add_file(&String::from(IOP_VC_ISSUANCE))?;
    writer.add_file(&String::from(IOP_VP_LENGTH))?;
    writer.add_file(&String::from(IOP_VP_ISSUANCE))?;
    writer.add_file(&String::from(IOP_VP_VERIFICATION))?;

    // =============================================================================================
    // ==================================        OURS        =======================================
    // =============================================================================================
    let mut our_vps: Vec<String> = vec![];
    let mut our_vc_issuance_duration: Vec<Duration> = vec![];
    let mut our_vp_issuance_duration: Vec<Duration> = vec![];
    let mut our_vp_verification_duration: Vec<Duration> = vec![];

    let (accumulator_dlt, verification_dlt, delegator_ids, credential_ids, delegators, context, valid_from, validity_period) = setup_ours(total_delegators)?;

    let mut permissions: Vec<String> = vec![];

    for i in 0..max_permissions {
        permissions.push(format!("https://vc.example/resources/r1:p{i}"));

        let mut vc = None;
        for i in 0..total_delegators {
            let delegator = get(&delegators, i)?;
            let credential_id = get(&credential_ids, i)?;
            let delegatee_id = get(&delegator_ids, i + 1)?;

            let (vc_duration, result_vc) = Benchmark::benchmark_function(||
                delegator.issue_delegation_verifiable_credential(
                context.clone(), credential_id.clone(), valid_from.clone(), delegatee_id.clone(),
                validity_period.clone(), permissions.clone(), vc.clone()
            ), iterations)?;

            let (vp_duration, vp) = Benchmark::benchmark_function(
                || delegator.issue_delegation_verifiable_presentation(
                    result_vc.clone(), permissions.clone()
                ),
                iterations
            )?;

            if i == total_delegators - 1 {
                our_vc_issuance_duration.push(vc_duration);
                our_vp_issuance_duration.push(vp_duration);
                our_vps.push(vp);
            }

            vc = Some(result_vc);
        }
    }

    let verifier: OurVerifier<E> = OurVerifier::new(accumulator_dlt, verification_dlt)?;

    for vp in our_vps.iter() {
        let presenter_id = get(&delegator_ids, total_delegators - 1)?;
        let (duration, _) = Benchmark::benchmark_function(|| verifier.verify_verifiable_presentation(presenter_id.clone(), vp.clone(), true), iterations)?;
        our_vp_verification_duration.push(duration);
    }

    // =============================================================================================
    // ==================================        PJVS        =======================================
    // =============================================================================================
    let mut pjv_vps: Vec<String> = vec![];
    let mut pjv_vc_issuance_duration: Vec<Duration> = vec![];
    let mut pjv_vp_issuance_duration: Vec<Duration> = vec![];
    let mut pjv_vp_verification_duration: Vec<Duration> = vec![];

    let (delegator_ids, credential_ids, delegators, context, valid_from, validity_period, owner, resource_uri) = setup_pjvs(total_delegators)?;

    let mut operations: Vec<String> = vec![];

    for i in 0..max_permissions {
        operations.push(format!("p{i}"));

        let mut vc = None;
        for i in 0..total_delegators {
            let delegator = get(&delegators, i)?;
            let credential_id = get(&credential_ids, i)?;
            let delegatee_id = get(&delegator_ids, i + 1)?;

            let (vc_duration, result_vc) = Benchmark::benchmark_function(
                || delegator.issue_delegation_verifiable_credential(
                    context.clone(), credential_id.clone(), valid_from.clone(), delegatee_id.clone(),
                    validity_period.clone(), owner.clone(), resource_uri.clone(), operations.clone(), vc.clone()
                ),
                iterations
            )?;

            let (vp_duration, vp) = Benchmark::benchmark_function(
                ||delegator.issue_delegation_verifiable_presentation(
                    result_vc.clone(), operations.clone()
                ),
                iterations
            )?;

            if i == total_delegators - 1 {
                pjv_vc_issuance_duration.push(vc_duration);
                pjv_vp_issuance_duration.push(vp_duration);
                pjv_vps.push(vp);
            }

            vc = Some(result_vc);
        }
    }

    let verifier = get(&delegators, 0)?;

    for vp in pjv_vps.iter() {
        let presenter_id = get(&delegator_ids, total_delegators - 1)?;
        let (duration, _) = Benchmark::benchmark_function(|| verifier.verify_verifiable_presentation(presenter_id.clone(), vp.clone()), iterations)?;
        pjv_vp_verification_duration.push(duration);
    }

    let our_vc_issuance_ms: Vec<u128> = our_vc_issuance_duration.iter().map(Duration::as_micros).collect();
    let pjv_vc_issuance_ms: Vec<u128> = pjv_vc_issuance_duration.iter().map(Duration::as_micros).collect();
    for vc_issuance_ms in our_vc_issuance_ms.iter().zip(pjv_vc_issuance_ms.iter()) {
        writer.write_record_to_file(&String::from(IOP_VC_ISSUANCE), vc_issuance_ms)?;
    }

    let our_vp_lengths: Vec<usize> = our_vps.iter().map(|v| v.len()).collect();
    let pjv_vp_lengths: Vec<usize> = pjv_vps.iter().map(|v| v.len()).collect();
    for vp_length in our_vp_lengths.iter().zip(pjv_vp_lengths.iter()) {
        writer.write_record_to_file(&String::from(IOP_VP_LENGTH), vp_length)?;
    }

    let our_vp_issuance_ms: Vec<u128> = our_vp_issuance_duration.iter().map(Duration::as_micros).collect();
    let pjv_vp_issuance_ms: Vec<u128> = pjv_vp_issuance_duration.iter().map(Duration::as_micros).collect();
    for vp_issuance_duration in our_vp_issuance_ms.iter().zip(pjv_vp_issuance_ms.iter()) {
        writer.write_record_to_file(&String::from(IOP_VP_ISSUANCE), vp_issuance_duration)?;
    }

    let our_vp_verification_ms: Vec<u128> = our_vp_verification_duration.iter().map(Duration::as_micros).collect();
    let pjv_vp_verification_ms: Vec<u128> = pjv_vp_verification_duration.iter().map(Duration::as_micros).collect();
    for vp_verification_ms in our_vp_verification_ms.iter().zip(pjv_vp_verification_ms.iter()) {
        writer.write_record_to_file(&String::from(IOP_VP_VERIFICATION), vp_verification_ms)?;
    }

    Ok(())
}

fn retain_permissions<E: Pairing>(delegators_size: usize, permissions_size: usize, retain_amount: usize, iterations: i8) -> Result<(), String> {

    let retain_check = permissions_size / delegators_size;
    if retain_check != retain_amount {
        return Err(format!("Retain amount [{retain_amount}] must be equal to Permissions [{permissions_size}] / Delegators [{delegators_size}]"));
    }

    const RP_VC_ISSUANCE: &str = "rp_vc_issuance";
    const RP_VP_LENGTH: &str = "rp_vp_jwt_length";
    const RP_VP_ISSUANCE: &str = "rp_vp_issuance";
    const RP_VP_VERIFICATION: &str = "rp_vp_verification";
    let mut writer = CSVWriter::new(vec![String::from("Ours"), String::from("PJVs")])?;
    writer.add_file(&String::from(RP_VC_ISSUANCE))?;
    writer.add_file(&String::from(RP_VP_LENGTH))?;
    writer.add_file(&String::from(RP_VP_ISSUANCE))?;
    writer.add_file(&String::from(RP_VP_VERIFICATION))?;

    // =============================================================================================
    // ==================================        OURS        =======================================
    // =============================================================================================
    let mut our_vps: Vec<String> = vec![];
    let mut our_vc_issuance_duration: Vec<Duration> = vec![];
    let mut our_vp_issuance_duration: Vec<Duration> = vec![];
    let mut our_vp_verification_duration: Vec<Duration> = vec![];

    let (accumulator_dlt, verification_dlt, delegator_ids, credential_ids, delegators, context, valid_from, validity_period) = setup_ours(delegators_size)?;

    let mut permissions: Vec<String> = vec![];
    for i in 0..permissions_size {
        permissions.push(format!("https://vc.example/resources/r1:p{i}"));
    }

    let mut vc = None;
    for i in 0..delegators_size {
        let delegator = get(&delegators, i)?;
        let credential_id = get(&credential_ids, i)?;
        let delegatee_id = get(&delegator_ids, i + 1)?;

        let range = permissions_size - i * retain_amount;
        let permissions_slice = match permissions.get(0..range) {
            Some(permissions_slice) => permissions_slice,
            None => return Err(String::from("Could not get slice from permissions"))
        }.to_vec();

        let (duration, result_vc) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_credential(
                context.clone(), credential_id.clone(), valid_from.clone(), delegatee_id.clone(),
                validity_period.clone(), permissions_slice.clone(), vc.clone()
            ),
            iterations
        )?;
        our_vc_issuance_duration.push(duration);

        let (duration, result_vp) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_presentation(
                result_vc.clone(), permissions_slice.clone()
            ),
            iterations
        )?;
        our_vp_issuance_duration.push(duration);

        our_vps.push(result_vp);

        vc = Some(result_vc);
    }

    let verifier: OurVerifier<E> = OurVerifier::new(accumulator_dlt, verification_dlt)?;

    for (i, vp) in our_vps.iter().enumerate() {
        let presenter_id = get(&delegator_ids, i)?;
        let (duration, _) = Benchmark::benchmark_function(|| verifier.verify_verifiable_presentation(presenter_id.clone(), vp.clone(), true), iterations)?;
        our_vp_verification_duration.push(duration);
    }

    // =============================================================================================
    // ==================================        PJVS        =======================================
    // =============================================================================================
    let mut pjv_vps: Vec<String> = vec![];
    let mut pjv_vc_issuance_duration: Vec<Duration> = vec![];
    let mut pjv_vp_issuance_duration: Vec<Duration> = vec![];
    let mut pjv_vp_verification_duration: Vec<Duration> = vec![];

    let (delegator_ids, credential_ids, delegators, context, valid_from, validity_period, owner, resource_uri) = setup_pjvs(delegators_size)?;

    let mut operations: Vec<String> = vec![];
    for i in 0..permissions_size {
        operations.push(format!("p{i}"));
    }

    let mut vc = None;
    for i in 0..delegators_size {
        let delegator = get(&delegators, i)?;
        let credential_id = get(&credential_ids, i)?;
        let delegatee_id = get(&delegator_ids, i + 1)?;

        let range = permissions_size - i * retain_amount;
        let operations_slice = match operations.get(0..range) {
            Some(operations_slice) => operations_slice,
            None => return Err(String::from("Could not get slice from operations"))
        }.to_vec();

        let (duration, result_vc) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_credential(
                context.clone(), credential_id.clone(), valid_from.clone(), delegatee_id.clone(),
                validity_period.clone(), owner.clone(), resource_uri.clone(), operations_slice.clone(), vc.clone()),
            iterations
        )?;
        pjv_vc_issuance_duration.push(duration);

        let (duration, result_vp) = Benchmark::benchmark_function(
            || delegator.issue_delegation_verifiable_presentation(
                result_vc.clone(), operations_slice.clone()
            ),
            iterations
        )?;
        pjv_vp_issuance_duration.push(duration);

        pjv_vps.push(result_vp);

        vc = Some(result_vc);
    }

    let verifier = get(&delegators, 0)?;

    for (i, vp) in pjv_vps.iter().enumerate() {
        let presenter_id = get(&delegator_ids, i)?;
        let (duration, _) = Benchmark::benchmark_function(|| verifier.verify_verifiable_presentation(presenter_id.clone(), vp.clone()), iterations)?;
        pjv_vp_verification_duration.push(duration);
    }

    let our_vc_issuance_ms: Vec<u128> = our_vc_issuance_duration.iter().map(Duration::as_micros).collect();
    let pjv_vc_issuance_ms: Vec<u128> = pjv_vc_issuance_duration.iter().map(Duration::as_micros).collect();
    for vc_issuance_ms in our_vc_issuance_ms.iter().zip(pjv_vc_issuance_ms.iter()) {
        writer.write_record_to_file(&String::from(RP_VC_ISSUANCE), vc_issuance_ms)?;
    }

    let our_vp_lengths: Vec<usize> = our_vps.iter().map(|v| v.len()).collect();
    let pjv_vp_lengths: Vec<usize> = pjv_vps.iter().map(|v| v.len()).collect();
    for vp_length in our_vp_lengths.iter().zip(pjv_vp_lengths.iter()) {
        writer.write_record_to_file(&String::from(RP_VP_LENGTH), vp_length)?;
    }

    let our_vp_issuance_ms: Vec<u128> = our_vp_issuance_duration.iter().map(Duration::as_micros).collect();
    let pjv_vp_issuance_ms: Vec<u128> = pjv_vp_issuance_duration.iter().map(Duration::as_micros).collect();
    for vp_issuance_duration in our_vp_issuance_ms.iter().zip(pjv_vp_issuance_ms.iter()) {
        writer.write_record_to_file(&String::from(RP_VP_ISSUANCE), vp_issuance_duration)?;
    }

    let our_vp_verification_ms: Vec<u128> = our_vp_verification_duration.iter().map(Duration::as_micros).collect();
    let pjv_vp_verification_ms: Vec<u128> = pjv_vp_verification_duration.iter().map(Duration::as_micros).collect();
    for vp_verification_ms in our_vp_verification_ms.iter().zip(pjv_vp_verification_ms.iter()) {
        writer.write_record_to_file(&String::from(RP_VP_VERIFICATION), vp_verification_ms)?;
    }

    Ok(())
}

pub fn main() -> Result<(), String> {

    type Curve = Bn254;

    // const DELEGATORS: &str = "DELEGATORS";
    // const PERMISSIONS: &str = "PERMISSIONS";
    // const ITERATIONS: &str = "ITERATIONS";

    // let delegators = fetch_usize_env_variable(DELEGATORS)?;
    // let permissions = fetch_usize_env_variable(PERMISSIONS)?;
    // let iterations = fetch_usize_env_variable(ITERATIONS)? as i8;
    
    let delegators = 10;
    let permissions = 10;
    let iterations = 100;
    let retain_amount = permissions / delegators;

    iterate_over_delegators::<Curve>(delegators, permissions, 1, iterations)?;
    iterate_over_delegators::<Curve>(delegators, permissions, 4, iterations)?;
    iterate_over_delegators::<Curve>(delegators, permissions, 7, iterations)?;
    iterate_over_delegators::<Curve>(delegators, permissions, 10, iterations)?;
    iterate_over_permissions::<Curve>(delegators, permissions, iterations)?;
    retain_permissions::<Curve>(delegators, permissions, retain_amount, iterations)?;
    Ok(())

}