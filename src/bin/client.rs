use ::hpke::Serializable;
use color_eyre::eyre::{eyre, Result};
use ppm_prototype::{
    hpke::Role,
    parameters::{Parameters, PrioField, PrioType, ProtocolParameters},
    trace,
    upload::{EncryptedInputShare, Report},
};
use prio::{
    field::{split, Field64, FieldElement},
    pcp::{prove, types::Boolean, Value},
};
use reqwest::Client;
use std::convert::TryFrom;
use tracing::info;

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let http_client = Client::builder().user_agent(CLIENT_USER_AGENT).build()?;

    let ppm_parameters = Parameters::from_config_file()?;

    let leader_hpke_config = ppm_parameters
        .hpke_config(Role::Leader, &http_client)
        .await?;

    let mut leader_hpke_sender =
        leader_hpke_config.report_sender(&ppm_parameters.task_id, Role::Leader)?;

    let helper_hpke_config = ppm_parameters
        .hpke_config(Role::Helper, &http_client)
        .await?;

    let mut helper_hpke_sender =
        helper_hpke_config.report_sender(&ppm_parameters.task_id, Role::Helper)?;

    // TODO(timg): I don't like partially constructing the Report and then
    // filling in `encrypted_input_shares` later. Maybe impl Default on Report.
    let mut report = Report {
        task_id: ppm_parameters.task_id,
        time: 1001,
        nonce: rand::random(),
        extensions: vec![],
        encrypted_input_shares: vec![],
    };

    let joint_rand = if let ProtocolParameters::Prio {
        ref joint_rand,
        ref field,
        ref prio_type,
    } = ppm_parameters.protocol_parameters
    {
        if joint_rand.len() != 1 {
            return Err(eyre!("unexpected joint rand for boolean field 64"));
        }

        if field != &PrioField::Field64 || prio_type != &PrioType::Boolean {
            return Err(eyre!("only Boolean<Field64> is supported"));
        }

        [Field64::try_from(joint_rand[0].as_slice())?]
    } else {
        return Err(eyre!("only Prio is supported"));
    };

    // Generate a Prio input and proof. The serialized format is input share
    // then proof share.
    let input: Boolean<Field64> = Boolean::new(true);
    let input_shares = split(input.as_slice(), 2)?;

    let proof = prove(&input, &joint_rand)?;
    let proof_shares = split(proof.as_slice(), 2)?;

    let serialized_leader_share = [
        Field64::slice_into_byte_vec(&input_shares[Role::Leader.index()]),
        Field64::slice_into_byte_vec(&proof_shares[Role::Leader.index()]),
    ]
    .concat();

    let serialized_helper_share = [
        Field64::slice_into_byte_vec(&input_shares[Role::Helper.index()]),
        Field64::slice_into_byte_vec(&proof_shares[Role::Helper.index()]),
    ]
    .concat();

    let leader_payload =
        leader_hpke_sender.encrypt_input_share(&report, &serialized_leader_share)?;
    let helper_payload =
        helper_hpke_sender.encrypt_input_share(&report, &serialized_helper_share)?;
    report.encrypted_input_shares = vec![
        EncryptedInputShare {
            config_id: leader_hpke_config.id,
            encapsulated_context: leader_hpke_sender
                .encapped_key
                .to_bytes()
                .as_slice()
                .to_vec(),
            payload: leader_payload,
        },
        EncryptedInputShare {
            config_id: helper_hpke_config.id,
            encapsulated_context: helper_hpke_sender
                .encapped_key
                .to_bytes()
                .as_slice()
                .to_vec(),
            payload: helper_payload,
        },
    ];

    let upload_status = http_client
        .post(ppm_parameters.upload_endpoint()?)
        .json(&report)
        .send()
        .await?
        .status();

    info!(?upload_status, "upload complete");

    Ok(())
}
