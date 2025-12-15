// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use crate::{
    agent_identity::AgentIdentityBuilder,
    crypto::{self},
    device_id,
    error::{Error, Result},
    registrar_client::RegistrarClientBuilder,
    tpm::{self},
};
use base64::{engine::general_purpose, Engine as _};
use log::{error, info, debug, trace};
use openssl::x509::X509;
use tss_esapi::{
    handles::KeyHandle, structures::PublicBuffer, traits::Marshall,
};

#[derive(Debug)]
pub struct AgentRegistrationConfig {
    pub contact_ip: String,
    pub contact_port: u32,
    pub ek_handle: String,
    pub enable_iak_idevid: bool,
    pub registrar_ip: String,
    pub registrar_port: u32,
}

#[derive(Debug)]
pub struct AgentRegistration {
    pub ak: tpm::AKResult,
    pub ek_result: tpm::EKResult,
    pub api_versions: Vec<String>,
    pub agent_registration_config: AgentRegistrationConfig,
    pub agent_uuid: String,
    pub mtls_cert: Option<X509>,
    pub device_id: Option<device_id::DeviceID>,
    pub attest: Option<tss_esapi::structures::Attest>,
    pub signature: Option<tss_esapi::structures::Signature>,
    pub ak_handle: KeyHandle,
}

fn vec_to_byte_string(vec: &[u8]) -> String {
    let mut s = String::from("b\"");
    for &b in vec {
        s.push_str(&format!("\\x{:02x}", b));
    }
    s.push('"');
    s
}

pub async fn register_agent(
    aa: AgentRegistration,
    ctx: &mut tpm::Context<'_>,
) -> Result<()> {
    let iak_pub;
    let idevid_pub;
    let ak_pub = &PublicBuffer::try_from(aa.ak.public)?.marshall()?;
    let ek_pub =
        &PublicBuffer::try_from(aa.ek_result.public.clone())?.marshall()?;

    debug!("I am in register_agent.rs. Line 52\n");
    trace!("The AK public is {:?}\n\n", ak_pub);
    let mut ai_builder = AgentIdentityBuilder::new()
        .ak_pub(ak_pub)
        .ek_pub(ek_pub)
        .enabled_api_versions(
            aa.api_versions.iter().map(|ver| ver.as_ref()).collect(),
        )
        .uuid(&aa.agent_uuid)
        .ip(aa.agent_registration_config.contact_ip.clone())
        .port(aa.agent_registration_config.contact_port);

    if let Some(mtls_cert) = aa.mtls_cert {
        ai_builder = ai_builder.mtls_cert(mtls_cert);
    }

    // If the certificate is not None add it to the builder
    // To Check NO certficate
    if let Some(ekchain) = aa.ek_result.to_pem() {
        ai_builder = ai_builder.ek_cert(ekchain);
    }

    // Set the IAK/IDevID related fields, if enabled
    if aa.agent_registration_config.enable_iak_idevid {
        debug!("I enter in the if case 'Set the IAK/IDevID related fields, if enabled'\n");
        let (Some(dev_id), Some(attest), Some(signature)) =
            (&aa.device_id, aa.attest, aa.signature)
        else {
            error!("IDevID and IAK are enabled but could not be generated");
            return Err(Error::ConfigurationGenericError(
                "IDevID and IAK are enabled but could not be generated"
                    .to_string(),
            ));
        };

        iak_pub =
            PublicBuffer::try_from(dev_id.iak_pubkey.clone())?.marshall()?;
        idevid_pub = PublicBuffer::try_from(dev_id.idevid_pubkey.clone())?
            .marshall()?;
        ai_builder = ai_builder
            .iak_attest(attest.marshall()?)
            .iak_sign(signature.marshall()?)
            .iak_pub(&iak_pub)
            .idevid_pub(&idevid_pub);

        // If the IAK certificate was provided, set it
        if let Some(iak_cert) = dev_id.iak_cert.clone() {
            ai_builder = ai_builder.iak_cert(iak_cert);
        }

        // If the IDevID certificate was provided, set it
        if let Some(idevid_cert) = dev_id.idevid_cert.clone() {
            ai_builder = ai_builder.idevid_cert(idevid_cert);
        }
    }

    // Build the Agent Identity
    let ai = ai_builder.build().await?;

    let ac = &aa.agent_registration_config;
    // Build the registrar client
    // Create a RegistrarClientBuilder and set the parameters
    let mut registrar_client = RegistrarClientBuilder::new()
        .registrar_address(ac.registrar_ip.clone())
        .registrar_port(ac.registrar_port)
        .build()
        .await?;

    info!("Before requesting keyblob material. I.E. Before registrar_client.rs\n\n");
    // Request keyblob material
    info!("The AgentIdentity is: {:?}\n", ai);

    // Guarda https://doc.rust-lang.org/rust-by-example/hello/print.html per vedere l'output formattato in Rust
    // {:x} stampa in esadecimale, ma non funziona in questo caso
    // error[E0277]: the trait bound `[u8]: LowerHex` is not satisfied. the trait `LowerHex` is not implemented for `[u8]`, which is required by `&[u8]: LowerHex`
    info!("The ak_pub is: {:?}\n", ai.ak_pub);
    // info!("The ak_pub is: {:x}\n", ai.ak_pub);       // Avevo provato anche così, ma non funzionava
    let decoded_string = vec_to_byte_string(ai.ak_pub);
    let decoded2_string = hex::decode("48656c6c6f20776f726c6421").unwrap();

    //println!("The ak public key is:\n{}\n\n", decoded_string);

    let ek_string = vec_to_byte_string(ai.ek_pub);
    //println!("The ek public key is:\n{}\n\n", ek_string);

    // println!("{}", String::from_utf8(decoded_string).unwrap());
    //println!("{}\n\n", String::from_utf8(decoded2_string).unwrap());

    // Forse non gli piaceva il match perche facevo prima .unwrap()

    //  match decoded2_string {
    //     Ok(b) => {println!("{}", String::from_utf8(b).unwrap()); println!("{:?}", String::from_utf8(b).unwrap())},
    //     Err(e) => eprintln!("Invalid hex: {}", e),
    // }
    
     
    let keyblob = registrar_client.register_agent(&ai).await?;

    info!("SUCCESS: Agent {} registered", &aa.agent_uuid);

    debug!("Just before Activate Credential");
    let key = ctx.activate_credential(
        keyblob,
        aa.ak_handle,
        aa.ek_result.key_handle,
    )?;
    debug!("Just after Activate Credential");

    // Flush EK if we created it
    if aa.agent_registration_config.ek_handle.is_empty() {
        ctx.flush_context(aa.ek_result.key_handle.into())?;
    }

    debug!("No flush of EK\n");

    let mackey = general_purpose::STANDARD.encode(key.value());
    let auth_tag =
        crypto::compute_hmac(mackey.as_bytes(), aa.agent_uuid.as_bytes())?;
    let auth_tag = hex::encode(&auth_tag);

    registrar_client.activate_agent(&ai, &auth_tag).await?;

    info!("SUCCESS: Agent {} activated", &aa.agent_uuid);
    Ok(())
}
