// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "regex")]
use oak_proto_rust::oak::attestation::v1::Regex;
use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, endorsements, kernel_binary_reference_value, reference_values,
    text_reference_value, AmdSevReferenceValues, BinaryReferenceValue,
    ContainerLayerReferenceValues, Digests, Endorsements, Evidence, InsecureReferenceValues,
    KernelBinaryReferenceValue, KernelDigests, KernelLayerReferenceValues,
    OakContainersEndorsements, OakContainersReferenceValues, ReferenceValues,
    RootLayerEndorsements, RootLayerReferenceValues, SkipVerification, SystemLayerReferenceValues,
    TextReferenceValue,
};
use oak_proto_rust::oak::RawDigest;
use p256::ecdsa::VerifyingKey;
use prost::Message;
use trusted_tvs_types::EvidenceValidator;
use tvs_proto::pcit::tvs::{stage0_measurement, AppraisalPolicies, AppraisalPolicy, Measurement};
#[cfg(feature = "dynamic_attestation")]
use {alloc::collections::BTreeMap, alloc::string::String};

/// Validate measurements against a given appraisal policies.
///
/// The crate takes serialized appraisal policies, decode them
/// and convert them to Oak's ReferenceValue proto.
/// oak_attestation_verification or (_regex) crate is used to validate and
/// check the measurements against the appraisal policies.
/// The crate itself does not use any crate that requires std environment.
/// However, oak_attestation_verification_regex requires std to validate
/// Linux kernel command line arguments against regex reference string.
/// To make the crate fully no_std, turn off *regex* feature flag.
/// This in turn would ignore Linux command line parameter validation.
// PolicyManager struct when dynamic attestation is OFF
#[cfg(not(feature = "dynamic_attestation"))]
#[derive(Clone)]
pub struct PolicyManager {
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
    reference_values: Vec<ReferenceValues>,
}

// PolicyManager struct when dynamic attestation is ON
#[derive(Clone)]
#[cfg(feature = "dynamic_attestation")]
pub struct PolicyManager {
    enable_policy_signature: bool,
    accept_insecure_policies: bool,
    appraisal_policies: Vec<AppraisalPolicy>,
    stage0_binary_store: BTreeMap<String, Vec<u8>>,
}

// PolicyManager when dynamic attestation is OFF
#[cfg(not(feature = "dynamic_attestation"))]
impl PolicyManager {
    /// Create a new policy manager object. The function takes the following
    /// parameters:
    /// enable_policy_signature: whether or not to check signature on the
    /// policies.
    /// accept_insecure_policies: whether or not to accept policies allowing
    /// measurement from non-CVM i.e. self signed reports.
    pub fn new(enable_policy_signature: bool, accept_insecure_policies: bool) -> Self {
        Self {
            enable_policy_signature,
            accept_insecure_policies,
            reference_values: vec![],
        }
    }

    /// Create a new policy manager object with initial appraisal policies.
    /// The function takes the following
    /// parameters:
    /// policies: serialized bytes of `AppraisalPolicies` to validate
    /// measurements against.
    /// enable_policy_signature: whether or not to check signature on the
    /// policies.
    /// accept_insecure_policies: whether or not to accept policies allowing
    /// measurement from non-CVM i.e. self signed reports.
    pub fn new_with_policies(
        policies: &[u8],
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> anyhow::Result<Self> {
        let mut policy_manager = Self::new(enable_policy_signature, accept_insecure_policies);
        policy_manager.update(policies)?;
        Ok(policy_manager)
    }

    /// Update the appraisal policies used to check measurements against.
    pub fn update(&mut self, policies: &[u8]) -> anyhow::Result<()> {
        let appraisal_policies = AppraisalPolicies::decode(policies)
            .map_err(|_| anyhow::anyhow!("Failed to decode (serialize) appraisal policy."))?;
        let reference_values = if self.enable_policy_signature {
            let policy_verifying_key: VerifyingKey = get_policy_public_key()?;
            process_and_validate_policies(
                appraisal_policies,
                &[&policy_verifying_key],
                /*num_pass_required=*/ 1,
                self.accept_insecure_policies,
            )
        } else {
            process_and_validate_policies(
                appraisal_policies,
                &[],
                /*num_pass_required=*/ 0,
                self.accept_insecure_policies,
            )
        }?;
        self.reference_values = reference_values;
        Ok(())
    }
}

// PolicyManager when dynamic attestation is ON
#[cfg(feature = "dynamic_attestation")]
impl PolicyManager {
    /// Create a new policy manager object. The function takes the following
    /// parameters:
    /// enable_policy_signature: whether or not to check signature on the
    /// policies.
    /// accept_insecure_policies: whether or not to accept policies allowing
    /// measurement from non-CVM i.e. self signed reports.
    pub fn new(enable_policy_signature: bool, accept_insecure_policies: bool) -> Self {
        Self {
            enable_policy_signature,
            accept_insecure_policies,
            appraisal_policies: vec![],
            stage0_binary_store: BTreeMap::new(),
        }
    }

    /// Create a new policy manager object with initial appraisal policies.
    /// The function takes the following
    /// parameters:
    /// policies: serialized bytes of `AppraisalPolicies` to validate
    /// measurements against.
    /// enable_policy_signature: whether or not to check signature on the
    /// policies.
    /// accept_insecure_policies: whether or not to accept policies allowing
    /// measurement from non-CVM i.e. self signed reports.
    pub fn new_with_policies(
        policies: &[u8],
        enable_policy_signature: bool,
        accept_insecure_policies: bool,
    ) -> anyhow::Result<Self> {
        let mut policy_manager = Self::new(enable_policy_signature, accept_insecure_policies);
        policy_manager.update(policies)?;
        Ok(policy_manager)
    }

    /// Update the appraisal policies used to check measurements against.
    pub fn update(&mut self, policies: &[u8]) -> anyhow::Result<()> {
        let appraisal_policies = AppraisalPolicies::decode(policies)
            .map_err(|_| anyhow::anyhow!("Failed to decode (serialize) appraisal policy."))?;
        let validated_policies = if self.enable_policy_signature {
            let policy_verifying_key: VerifyingKey = get_policy_public_key()?;
            process_and_validate_policies(
                appraisal_policies.policies,
                &[&policy_verifying_key],
                /*num_pass_required=*/ 1,
            )
        } else {
            process_and_validate_policies(
                appraisal_policies.policies,
                &[],
                /*num_pass_required=*/ 0,
            )
        }?;

        self.appraisal_policies = validated_policies;
        self.stage0_binary_store = appraisal_policies
            .stage0_binary_sha256_to_blob
            .into_iter()
            .collect();
        Ok(())
    }
}

#[cfg(feature = "regex")]
impl EvidenceValidator for PolicyManager {
    /// Check evidence against the appraisal policies.
    /// The function takes the following parameters:
    /// time_milis: the current time to be passed to Oak's attestation
    /// verification library. The time is currently ignored in the verification
    /// library.
    /// evidence: an event log or DICE chain that contains the CVM full stack
    /// measurements.
    /// tee_certificate: certificate issued by the hardware vendor used to
    /// sign the root attestation report. The certificate is used to validate
    /// the root layer signature. The certificate is validated against a cert
    /// chain issued by the vendor.
    #[cfg(not(feature = "dynamic_attestation"))]
    fn check_evidence(
        &self,
        time_milis: i64,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> anyhow::Result<()> {
        let endorsement = create_endorsements(tee_certificate);
        for policy in &self.reference_values {
            match oak_attestation_verification_with_regex::verifier::verify(
                time_milis,
                evidence,
                &endorsement,
                policy,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            };
        }

        if log::log_enabled!(log::Level::Debug) {
            if let Err(err) = debug::suggest_appraisal_policy(evidence) {
                log::debug!(
                    "Failed to suggest appraisal policy based on the provided evidence: {err}"
                );
            }
        }

        Err(anyhow::anyhow!(
            "Failed to verify report. No matching appraisal policy found"
        ))
    }

    // Dynamic Attestation implementation
    #[cfg(feature = "dynamic_attestation")]
    fn check_evidence(
        &self,
        time_milis: i64,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> anyhow::Result<()> {
        dynamic::check_evidence(self, time_milis, evidence, tee_certificate)
    }
}

#[cfg(feature = "dynamic_attestation")]
mod dynamic {
    // imports
    use super::*;
    use {
        anyhow::Context,
        measure::{snp_calc_launch_digest_from_bytes, vcpu_types::CpuType},
        oak_sev_snp_attestation_report::AttestationReport,
        tvs_proto::pcit::tvs::{stage0_measurement::Type, AmdSev, CpuInfo},
        zerocopy::FromBytes,
    };

    // Main logic of check_evidence to perform dynamic computation
    pub fn check_evidence(
        policy_manager: &PolicyManager,
        time_milis: i64,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> anyhow::Result<()> {
        let endorsement = create_endorsements(tee_certificate);

        // turn CVM attestation report/evidence into an AttestationReport object
        let root_layer = evidence
            .root_layer
            .as_ref()
            .context("Evidence is missing root_layer")?;
        let report_bytes = &root_layer.remote_attestation_report;
        let attestation_report = AttestationReport::read_from_bytes(report_bytes).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse attestation report from bytes. Zerocopy error: {:?}",
                e
            )
        })?;

        // Extract measured CPU information:
        let measured_cpu = (
            attestation_report.data.cpuid_fam_id as i32,
            attestation_report.data.cpuid_mod_id,
            attestation_report.data.cpuid_step,
        );
        let (family, model, stepping) = measured_cpu;
        let measured_vcpu_type = CpuType::from_cpuid(family, model.into(), stepping.into())?;

        for policy in &policy_manager.appraisal_policies {
            // Just check that if the policy is not dynamic (e.g. static or insecure), we can skip/ignore.
            let Some(Type::AmdSevDynamic(amd_sev_dynamic)) = policy
                .measurement
                .as_ref()
                .and_then(|m| m.stage0_measurement.as_ref())
                .and_then(|s0| s0.r#type.as_ref())
            else {
                log::debug!("Skipping policy: not an AmdSevDynamic type.");
                continue;
            };

            // check if CPU info is allowed by policy
            if !is_cpu_type_allowed(measured_cpu, &amd_sev_dynamic.cpu_info) {
                log::debug!(
                    "Measured CPU type (family: {}, model: {}, stepping: {}) is not in the policy's allowlist. Skipping policy.",
                    measured_cpu.0, measured_cpu.1, measured_cpu.2
                );
                continue;
            }
            // Loop through the stage0_binary reference hashes in the policy and fetch blob from store
            for stage0_binary_hash in &amd_sev_dynamic.stage0_ovmf_binary_hash {
                let Some(stage0_blob) = policy_manager.stage0_binary_store.get(stage0_binary_hash)
                else {
                    log::debug!(
                        "Stage0 binary content not found for hash: {}. Skipping.",
                        stage0_binary_hash
                    );
                    continue;
                };
                // Check if blob, CPU, and vCPU count together produce valid stage0 measurement
                if stage0_measurement_is_valid(
                    stage0_blob,
                    &attestation_report,
                    &measured_vcpu_type,
                    &amd_sev_dynamic.vcpu_count,
                )? {
                    log::debug!(
                        "Stage0 measurement is VALID for stage0 hash '{}'. Proceeding to full verification.",
                        stage0_binary_hash
                    );
                    // stage0 measurement is valid, set up so Oak verifier can match rest of policy with measured evidence
                    // TODO: b/434016988 directly create reference values from a verified stage0 sha384, without mutable situation
                    let mut final_policy = policy.clone();
                    update_policy_with_final_hash(
                        &mut final_policy,
                        &attestation_report.data.measurement,
                    );

                    // turn final_policy AppraisalPolicy object into a ReferenceValues object for Oak Verifier
                    let final_reference_values = appraisal_policy_to_reference_values(
                        &final_policy,
                        policy_manager.accept_insecure_policies,
                    )?;

                    // Let Oak verifier match this policy
                    if oak_attestation_verification_with_regex::verifier::verify(
                        time_milis,
                        evidence,
                        &endorsement,
                        &final_reference_values,
                    )
                    .is_ok()
                    {
                        return Ok(()); // Found matching policy
                    }
                } else {
                    log::debug!(
                        "Stage0 measurement is INVALID for stage0 hash '{}'. Skipping.",
                        stage0_binary_hash
                    );
                }
            }
        }

        if log::log_enabled!(log::Level::Debug) {
            if let Err(err) = debug::suggest_appraisal_policy(evidence) {
                log::debug!(
                    "Failed to suggest appraisal policy based on the provided evidence: {err}"
                );
            }
        }

        Err(anyhow::anyhow!(
            "Failed to verify report. No matching appraisal policy found"
        ))
    }

    // TODO: b/434016988 The purpose of this method will need to be merged with the ReferenceValues conversion in a later CL.
    fn update_policy_with_final_hash(final_policy: &mut AppraisalPolicy, actual_hash: &[u8]) {
        if let Some(measurement) = final_policy.measurement.as_mut() {
            if let Some(stage0) = measurement.stage0_measurement.as_mut() {
                if let Some(Type::AmdSevDynamic(amd_sev_dynamic)) = stage0.r#type.as_mut() {
                    // replace AmdSevDynamic stage0 measurement to be an AmdSev static one
                    let static_policy = AmdSev {
                        sha384: hex::encode(actual_hash),
                        min_tcb_version: amd_sev_dynamic.min_tcb_version,
                    };
                    stage0.r#type = Some(Type::AmdSev(static_policy));
                }
            }
        }
    }

    /// Checks if a given stage0 binary blob and CPU config can produce the measured hash,
    /// using one of the allowed vCPU counts.
    pub fn stage0_measurement_is_valid(
        stage0_blob: &[u8],
        attestation_report: &AttestationReport,
        measured_cpu_type: &CpuType,
        allowed_vcpu_counts: &[u32],
    ) -> anyhow::Result<bool> {
        let actual_hash = attestation_report.data.measurement.as_slice(); // extract stage0 hash

        // Loop only through the vCPU counts specified in the policy.
        for &vcpu_count in allowed_vcpu_counts {
            // Re-calculate the full launch digest using snp utility function.
            // Note: kernel_path, initrd_path, and append are `None` because the launch
            // digest measurement in the attestation report is calculated before these
            // components are loaded. This ensures the recalculated digest matches the evidence
            let calculated_digest = snp_calc_launch_digest_from_bytes(
                vcpu_count as usize,
                measured_cpu_type.clone(),
                stage0_blob,
                None, // kernel_path
                None, // initrd_path
                None, // append
            )?;
            // Compare measured digest and calculated digest
            if calculated_digest.0.as_slice() == actual_hash {
                log::debug!(
                    "Found a valid stage0 measurement match for vCPU count {}",
                    vcpu_count
                );
                return Ok(true);
            }
        }
        log::debug!("No vCPU count in policy produced a matching stage0 measurement.");
        Ok(false)
    }

    // Checks if measured CPU ID information is permissible by the appraisal policy
    pub fn is_cpu_type_allowed(measured_cpu: (i32, u8, u8), allowed_cpus: &[CpuInfo]) -> bool {
        let (measured_family, measured_model, measured_stepping) = measured_cpu;

        // Cast to u32 to compare with CpuInfo proto fields
        let measured_family = measured_family as u32;
        let measured_model = measured_model as u32;
        let measured_stepping = measured_stepping as u32;

        allowed_cpus.iter().any(|allowed_cpu| {
            allowed_cpu.family == measured_family
                && allowed_cpu.model == measured_model
                && allowed_cpu.stepping == measured_stepping
        })
    }
}

#[cfg(feature = "regex")]
mod debug {
    use alloc::{format, string::String};
    use anyhow::Context;
    use oak_proto_rust::oak::attestation::v1::{
        binary_reference_value, kernel_binary_reference_value, reference_values,
        text_reference_value, BinaryReferenceValue, Evidence, KernelLayerReferenceValues,
        RootLayerReferenceValues,
    };
    use regex::Regex;

    pub(crate) fn suggest_appraisal_policy(evidence: &Evidence) -> anyhow::Result<()> {
        let extracted_evidence =
            oak_attestation_verification_with_regex::extract::extract_evidence(evidence)?;
        let reference_values =
            oak_attestation_verification_with_regex::reference_values_from_evidence(
                extracted_evidence,
            );

        let Some(reference_values::Type::OakContainers(oak_reference_values)) =
            reference_values.r#type
        else {
            anyhow::bail!("Evidence is not of OakContainers type.");
        };

        let Some(root_layer) = &oak_reference_values.root_layer else {
            anyhow::bail!("Evidence does not have root layer.")
        };

        let Some(kernel_layer) = oak_reference_values.kernel_layer else {
            anyhow::bail!("Evidence does not have kernel layer");
        };

        let Some(system_layer) = oak_reference_values.system_layer else {
            anyhow::bail!("Evidence does not have system layer.");
        };

        let Some(container_layer) = oak_reference_values.container_layer else {
            anyhow::bail!("Evidence does not have container layer.");
        };

        let (kernel, setup_data) = kernel_measurements(&kernel_layer)?;

        let kernel_cmd_line = {
            let Some(kernel_cmd_line_text) = kernel_layer.kernel_cmd_line_text else {
                anyhow::bail!("Evidence does not have kernel command line text.")
            };
            let Some(text_reference_value::Type::StringLiterals(kernel_cmd_line)) =
                kernel_cmd_line_text.r#type
            else {
                anyhow::bail!("Evidence does not have kernel command line text.")
            };
            if let Ok(re) = Regex::new(r"--launcher-addr=vsock://2:([0-9])+[^0-9]*") {
                format!(
                    "^{}$",
                    re.replace(
                        &kernel_cmd_line.value.join(""),
                        "--launcher-addr=vsock://2:.*"
                    )
                )
            } else {
                kernel_cmd_line.value.join("")
            }
        };

        log::debug!(
            r#"Maybe try the following appraisal policy:
                policies {{
                  measurement {{
                    stage0_measurement {{
                      {}
                    }}
                    kernel_image_sha256: "{}"
                    kernel_setup_data_sha256: "{}"
                    init_ram_fs_sha256: "{}"
                    memory_map_sha256: "{}"
                    acpi_table_sha256: "{}"
                    kernel_cmd_line_regex: "{}"
                    system_image_sha256: "{}"
                    container_binary_sha256: "{}"
                  }}
                }}"#,
            text_stage0_measurement_from_evidence(root_layer)
                .context("extracting stage0 measurement digest.")?,
            kernel,
            setup_data,
            binary_reference_value_to_hex(kernel_layer.init_ram_fs.as_ref())
                .context("extracting init ram fs digest.")?,
            binary_reference_value_to_hex(kernel_layer.memory_map.as_ref())
                .context("extracting memory map digest.")?,
            binary_reference_value_to_hex(kernel_layer.acpi.as_ref())
                .context("extracting acpi table digest.")?,
            kernel_cmd_line,
            binary_reference_value_to_hex(system_layer.system_image.as_ref())
                .context("extracting system image digest.")?,
            binary_reference_value_to_hex(container_layer.binary.as_ref())
                .context("extracting container binary  digest.")?
        );

        Ok(())
    }

    fn text_stage0_measurement_from_evidence(
        root_layer: &RootLayerReferenceValues,
    ) -> anyhow::Result<String> {
        if let Some(amd_sev) = &root_layer.amd_sev {
            let Some(stage0) = &amd_sev.stage0 else {
                anyhow::bail!("No amd_sev stage0 measurement found.");
            };
            let Some(binary_reference_value::Type::Digests(digests)) = &stage0.r#type else {
                anyhow::bail!("No stage0 digest found.");
            };
            if digests.digests.len() != 1 {
                anyhow::bail!(
                    "stage0 digest size mismatch: want 1, got {}.",
                    digests.digests.len()
                )
            };

            #[allow(deprecated)]
            let tcb_version = amd_sev.min_tcb_version.unwrap_or_default();
            return Ok(format!(
                r#"
                  amd_sev {{
                    sha384: "{}"
                    min_tcb_version {{
                      boot_loader: {}
                      snp: {}
                      microcode: {}
                    }}
                  }}"#,
                hex::encode(&digests.digests[0].sha2_384),
                tcb_version.boot_loader,
                tcb_version.snp,
                tcb_version.microcode
            ));
        };
        if root_layer.insecure.is_some() {
            return Ok(String::from("insecure {}"));
        }
        anyhow::bail!("No stage0 measurement found.");
    }

    fn kernel_measurements(
        kernel_layer: &KernelLayerReferenceValues,
    ) -> anyhow::Result<(String, String)> {
        let Some(ref kernel_measurement) = kernel_layer.kernel else {
            anyhow::bail!("No kernel measurement found.");
        };

        let Some(kernel_binary_reference_value::Type::Digests(ref kernel_digests)) =
            kernel_measurement.r#type
        else {
            anyhow::bail!("No digest in kernel measurement found.");
        };

        let Some(image) = &kernel_digests.image else {
            anyhow::bail!("No image field in kernel digest found.");
        };

        let Some(setup_data) = &kernel_digests.setup_data else {
            anyhow::bail!("No setup_data field in kernel digest found.");
        };

        if image.digests.len() != 1 {
            anyhow::bail!(
                "image digest size mismatch: want 1, got {}.",
                image.digests.len()
            );
        };

        if setup_data.digests.len() != 1 {
            anyhow::bail!(
                "setup_data digest size mismatch: want 1, got {}.",
                setup_data.digests.len()
            );
        }

        Ok((
            hex::encode(&image.digests[0].sha2_256),
            hex::encode(&setup_data.digests[0].sha2_256),
        ))
    }

    fn binary_reference_value_to_hex(
        binary_reference: Option<&BinaryReferenceValue>,
    ) -> anyhow::Result<String> {
        let Some(binary_reference) = binary_reference else {
            anyhow::bail!("No binary reference field found.");
        };
        let Some(binary_reference_value::Type::Digests(digests)) = &binary_reference.r#type else {
            anyhow::bail!("No digest in binary reference found.");
        };
        if digests.digests.len() != 1 {
            anyhow::bail!(
                "digest size mismatch: want 1, got {}.",
                digests.digests.len()
            );
        }
        Ok(hex::encode(&digests.digests[0].sha2_256))
    }
}

#[cfg(not(feature = "regex"))]
impl EvidenceValidator for PolicyManager {
    /// Check evidence against the appraisal policies.
    /// The function takes the following parameters:
    /// time_milis: the current time to be passed to Oak's attestation
    /// verification library. The time is currently ignored in the verification
    /// library.
    /// evidence: an event log or DICE chain that contains the CVM full stack
    /// measurements.
    /// tee_certificate: certificate issued by the hardware vendor used to
    /// sign the root attestation report. The certificate is used to validate
    /// the root layer signature. The certificate is validated against a cert
    /// chain issued by the vendor.
    fn check_evidence(
        &self,
        time_milis: i64,
        evidence: &Evidence,
        tee_certificate: &[u8],
    ) -> anyhow::Result<()> {
        let endorsement = create_endorsements(tee_certificate);
        for policy in &self.reference_values {
            match oak_attestation_verification::verifier::verify(
                time_milis,
                evidence,
                &endorsement,
                policy,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            };
        }
        Err(anyhow::anyhow!(
            "Failed to verify report. No matching appraisal policy found"
        ))
    }
}

// TODO(b/358413924): Actually fetch key
fn get_policy_public_key() -> anyhow::Result<VerifyingKey> {
    let verifying_key = VerifyingKey::from_sec1_bytes(
        &hex::decode("048fa2c25d3d3368b23f7877c9ac84866f440f9dd7a94e7ca5440ef1bc611f77db2940cca2233d06c9cfbf503ee73fdf5cf1f4c637f376bb7daaf637faf05656e4")
        .map_err(|err| anyhow::anyhow!("Failed to decode policy public key hex: {err}"))?
    )
    .map_err(|err| anyhow::anyhow!("Failed to parse policy public key: {err}"))?;
    Ok(verifying_key)
}

fn create_endorsements(tee_certificate: &[u8]) -> Endorsements {
    let root_layer = RootLayerEndorsements {
        tee_certificate: tee_certificate.to_vec(),
        stage0: None,
    };
    let ends = OakContainersEndorsements {
        root_layer: Some(root_layer),
        container_layer: None,
        kernel_layer: None,
        system_layer: None,
    };
    Endorsements {
        r#type: Some(endorsements::Type::OakContainers(ends)),
        events: vec![],
        initial: None,
        platform: None,
    }
}

#[cfg(feature = "dynamic_attestation")]
fn process_and_validate_policies(
    policies: Vec<AppraisalPolicy>,
    verifying_keys: &[&VerifyingKey],
    num_pass_required: u32,
) -> anyhow::Result<Vec<AppraisalPolicy>> {
    policies
        .into_iter()
        .map(|policy| {
            if num_pass_required == 0 {
                Ok(policy)
            } else {
                match policy_signature::verify_policy_signature(
                    &policy,
                    verifying_keys,
                    num_pass_required,
                ) {
                    Ok(_) => Ok(policy),
                    Err(e) => Err(e),
                }
            }
        })
        .collect()
}

#[cfg(not(feature = "dynamic_attestation"))]
fn process_and_validate_policies(
    policies: AppraisalPolicies,
    verifying_keys: &[&VerifyingKey],
    num_pass_required: u32,
    accept_insecure_policies: bool,
) -> anyhow::Result<Vec<ReferenceValues>> {
    policies
        .policies
        .into_iter()
        .map(|policy| {
            if num_pass_required == 0 {
                Ok(policy)
            } else {
                match policy_signature::verify_policy_signature(
                    &policy,
                    verifying_keys,
                    num_pass_required,
                ) {
                    Ok(_) => Ok(policy),
                    Err(e) => Err(e),
                }
            }
        })
        .map(|policy| appraisal_policy_to_reference_values(&policy?, accept_insecure_policies))
        .collect()
}

fn appraisal_policy_to_reference_values(
    policy: &AppraisalPolicy,
    accept_insecure_policies: bool,
) -> anyhow::Result<ReferenceValues> {
    let Some(measurement) = &policy.measurement else {
        anyhow::bail!("Policy does not have measurement field set");
    };

    Ok(ReferenceValues {
        r#type: Some(reference_values::Type::OakContainers(
            OakContainersReferenceValues {
                root_layer: Some(get_root_layer(measurement, accept_insecure_policies)?),
                kernel_layer: Some(get_kernel_layer(measurement)?),
                system_layer: Some(get_system_layer(measurement)?),
                container_layer: Some(get_container_layer(measurement)?),
            },
        )),
    })
}

fn get_root_layer(
    measurement: &Measurement,
    accept_insecure_policies: bool,
) -> anyhow::Result<RootLayerReferenceValues> {
    let Some(stage0_measurement) = &measurement.stage0_measurement else {
        anyhow::bail!("stage0_measurement field is not set");
    };
    match stage0_measurement.r#type.as_ref() {
        Some(stage0_measurement::Type::AmdSev(stage0)) => {
            if stage0.min_tcb_version.is_none() {
                anyhow::bail!("min_tcb_version is not set");
            }
            #[allow(deprecated)]
            Ok(RootLayerReferenceValues {
                amd_sev: Some(AmdSevReferenceValues {
                    allow_debug: false,
                    min_tcb_version: stage0.min_tcb_version,
                    genoa: None,
                    milan: None,
                    turin: None,
                    stage0: Some(BinaryReferenceValue {
                        r#type: Some(binary_reference_value::Type::Digests(Digests {
                            digests: vec![RawDigest {
                                sha2_384: hex::decode(&stage0.sha384).map_err(|err| {
                                    anyhow::anyhow!("failed to decode sha256_hex: {err}")
                                })?,
                                psha2: vec![],
                                sha1: vec![],
                                sha2_256: vec![],
                                sha2_512: vec![],
                                sha3_512: vec![],
                                sha3_384: vec![],
                                sha3_256: vec![],
                                sha3_224: vec![],
                            }],
                        })),
                    }),
                }),
                insecure: None,
                intel_tdx: None,
            })
        }
        Some(stage0_measurement::Type::Insecure(_)) => {
            if !accept_insecure_policies {
                anyhow::bail!("Cannot accept insecure policies.");
            }
            Ok(RootLayerReferenceValues {
                insecure: Some(InsecureReferenceValues {}),
                amd_sev: None,
                intel_tdx: None,
            })
        }
        Some(stage0_measurement::Type::AmdSevDynamic(_)) => {
            //TODO: b/434016988 - to be implemented
            anyhow::bail!("Dynamic appraisal policy is not yet supported")
        }
        None => Err(anyhow::anyhow!("stage0_measurement field is not set")),
    }
}

fn get_kernel_layer(measurement: &Measurement) -> anyhow::Result<KernelLayerReferenceValues> {
    // A number of deprecated field that we have to set, and when we do we get warned.
    // So we suppress the warning.
    #[allow(deprecated)]
    Ok(KernelLayerReferenceValues {
        kernel: Some(KernelBinaryReferenceValue {
            r#type: Some(kernel_binary_reference_value::Type::Digests(
                KernelDigests {
                    image: Some(sha256_hex_to_digest(&measurement.kernel_image_sha256)?),
                    setup_data: Some(sha256_hex_to_digest(&measurement.kernel_setup_data_sha256)?),
                },
            )),
        }),
        #[cfg(feature = "regex")]
        kernel_cmd_line_text: Some(TextReferenceValue {
            r#type: Some(text_reference_value::Type::Regex(Regex {
                value: measurement.kernel_cmd_line_regex.clone(),
            })),
        }),
        #[cfg(not(feature = "regex"))]
        kernel_cmd_line_text: Some(TextReferenceValue {
            r#type: Some(text_reference_value::Type::Skip(SkipVerification {})),
        }),
        init_ram_fs: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.init_ram_fs_sha256,
            )?)),
        }),
        memory_map: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.memory_map_sha256,
            )?)),
        }),
        acpi: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.acpi_table_sha256,
            )?)),
        }),
    })
}

fn get_system_layer(measurement: &Measurement) -> anyhow::Result<SystemLayerReferenceValues> {
    Ok(SystemLayerReferenceValues {
        system_image: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(sha256_hex_to_digest(
                &measurement.system_image_sha256,
            )?)),
        }),
    })
}

fn get_container_layer(measurement: &Measurement) -> anyhow::Result<ContainerLayerReferenceValues> {
    let mut digests_container = Digests::default();
    for hex_string in &measurement.container_binary_sha256 {
        let single_digest_result = single_sha256_to_raw_digest(hex_string)?;
        digests_container.digests.push(single_digest_result);
    }

    Ok(ContainerLayerReferenceValues {
        binary: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Digests(digests_container)),
        }),
        // Skip configuration verification as we are not using it.
        configuration: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(SkipVerification {})),
        }),
    })
}

fn sha256_hex_to_digest(sha256_hex: &str) -> anyhow::Result<Digests> {
    Ok(Digests {
        digests: vec![RawDigest {
            sha2_256: hex::decode(sha256_hex)
                .map_err(|err| anyhow::anyhow!("failed to decode sha256_hex: {err}"))?,
            psha2: vec![],
            sha1: vec![],
            sha2_512: vec![],
            sha3_512: vec![],
            sha3_384: vec![],
            sha3_256: vec![],
            sha3_224: vec![],
            sha2_384: vec![],
        }],
    })
}

fn single_sha256_to_raw_digest(sha256_hex: &str) -> anyhow::Result<RawDigest> {
    Ok(RawDigest {
        sha2_256: hex::decode(sha256_hex)
            .map_err(|err| anyhow::anyhow!("failed to decode sha256_hex: {err}"))?,
        psha2: vec![],
        sha1: vec![],
        sha2_512: vec![],
        sha3_512: vec![],
        sha3_384: vec![],
        sha3_256: vec![],
        sha3_224: vec![],
        sha2_384: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::ToString;
    use alloc::string::String;
    use oak_proto_rust::oak::attestation::v1::TcbVersion;
    use prost::Message;
    use tvs_proto::pcit::tvs::stage0_measurement;

    const NOW_UTC_MILLIS: i64 = 1698829200000;

    fn get_genoa_vcek() -> Vec<u8> {
        include_bytes!("../../../test_data/vcek_genoa.crt").to_vec()
    }

    fn get_evidence_v1_genoa() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../../test_data/evidence_v1_genoa.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    fn get_evidence_v2_genoa() -> oak_proto_rust::oak::attestation::v1::Evidence {
        oak_proto_rust::oak::attestation::v1::Evidence::decode(
            include_bytes!("../../../test_data/evidence_v2_genoa.binarypb").as_slice(),
        )
        .expect("could not decode evidence")
    }

    #[cfg(not(feature = "dynamic_attestation"))]
    mod static_attestation {
        use super::*;
        use tvs_proto::pcit::tvs::{AmdSev, Signature, Stage0Measurement};

        // Static test appraisal policies
        fn default_appraisal_policies() -> Vec<u8> {
            let policies = AppraisalPolicies {
                policies: vec![AppraisalPolicy{
                 description: "Test AMD-SNP measurements".to_string(),
                    measurement: Some(Measurement {
                        stage0_measurement: Some(Stage0Measurement{
                            r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                                sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc".to_string(),
                                min_tcb_version: Some(TcbVersion{
                                    boot_loader: 10,
                                    microcode: 84,
                                    snp: 25,
                                    tee: 0,
                                    fmc: 0,
                                }),
                            })),
                        }),
                        kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                        kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                        init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                        memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                        acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                        kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                        system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                        container_binary_sha256:vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string()],

                    }),
                    signature: vec![Signature{
                        signature: "db07413c03902c54275858269fb19aac96ba5d80f027653bc2664a87c37c277407bffa411e6b06de773cee60fd5bb7a0f7a01eda746fa8a508bbc2bdfd83c3b6".to_string(),
                        signer: "".to_string(),
                        },
                        ],
                }],
                stage0_binary_sha256_to_blob: Default::default(),
            };
            let mut buf: Vec<u8> = Vec::with_capacity(1024);
            policies.encode(&mut buf).unwrap();
            buf
        }

        fn default_appraisal_policies_multiple_container_binaries() -> Vec<u8> {
            let policies = AppraisalPolicies {
                policies: vec![AppraisalPolicy{
                 description: "Test AMD-SNP measurements".to_string(),
                    measurement: Some(Measurement {
                        stage0_measurement: Some(Stage0Measurement{
                            r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                                sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc".to_string(),
                                min_tcb_version: Some(TcbVersion{
                                    boot_loader: 10,
                                    microcode: 84,
                                    snp: 25,
                                    tee: 0,
                                    fmc: 0,
                                }),
                            })),
                        }),
                        kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                        kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                        init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                        memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                        acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                        kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                        system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                        container_binary_sha256:vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()],

                    }),
                    signature: vec![Signature{
                        signature: "253879b00ed106485940dbb0abd0c2b8d08b1cdd0a25b4537265f24c5dca36b5908c87728e0a8e7a3d0c97f534d4d517c029ee2a16fb6dc98801f5b50c618fb3".to_string(),
                        signer: "".to_string(),
                        },
                        ],
                }],
                stage0_binary_sha256_to_blob: Default::default(),
            };
            let mut buf: Vec<u8> = Vec::with_capacity(1024);
            policies.encode(&mut buf).unwrap();
            buf
        }

        // should fail everytime
        fn default_appraisal_policies_no_container_binaries() -> Vec<u8> {
            let policies = AppraisalPolicies {
                policies: vec![AppraisalPolicy{
                 description: "Test AMD-SNP measurements".to_string(),
                    measurement: Some(Measurement {
                        stage0_measurement: Some(Stage0Measurement{
                            r#type: Some(stage0_measurement::Type::AmdSev(AmdSev{
                                sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc".to_string(),
                                min_tcb_version: Some(TcbVersion{
                                    boot_loader: 10,
                                    microcode: 84,
                                    snp: 25,
                                    tee: 0,
                                    fmc: 0,
                                }),
                            })),
                        }),
                        kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                        kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                        init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                        memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                        acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                        kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$".to_string(),
                        system_image_sha256: "b0f34de77126561d911e0687f79eaad808b0948e0a1045f7449274efc2e411c5".to_string(),
                        container_binary_sha256:vec![],

                    }),
                    signature: vec![Signature{
                        signature: "273dd08d4f420e1aeaf7ed1ab3e40c364d33fa59a18119d06500db00de92b3032c0198fa331c4506f29a76545b17ad588f2e27bd3819a5ab040a756b7ee4b21c".to_string(),
                        signer: "".to_string(),
                        },
                        ],
                }],
                stage0_binary_sha256_to_blob: Default::default(),
            };
            let mut buf: Vec<u8> = Vec::with_capacity(1024);
            policies.encode(&mut buf).unwrap();
            buf
        }

        fn insecure_appraisal_policies() -> Vec<u8> {
            let policies = AppraisalPolicies {
                policies: vec![AppraisalPolicy{
                    description: "Test insecure VM measurements".to_string(),
                    measurement: Some(Measurement {
                        stage0_measurement: Some(Stage0Measurement{
                            r#type: Some(stage0_measurement::Type::Insecure(InsecureReferenceValues{})),
                        }),
                        kernel_image_sha256: String::from("442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf"),
                        kernel_setup_data_sha256: String::from("68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9"),
                        init_ram_fs_sha256: String::from("3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae"),
                        memory_map_sha256: String::from("4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28"),
                        acpi_table_sha256: String::from("a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8"),
                        kernel_cmd_line_regex: String::from("^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$"),
                        system_image_sha256: String::from("e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd"),
                        container_binary_sha256:vec![String::from("bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c")],

                    }),
                    signature: vec![Signature{
                        signature: String::from("6870ebf5f55debe04cd66d47ea3b2a878edd436aba59be30b1f52478bb4e12e4d40c223664ee3c0f13ce27e159bc8e7726cce52520f4fb171d6622a26169dcb6"),
                        signer: String::from(""),
                        },
                        ],
                }],
                stage0_binary_sha256_to_blob: Default::default(),
            };
            let mut buf: Vec<u8> = Vec::with_capacity(1024);
            policies.encode(&mut buf).unwrap();
            buf
        }

        #[test]
        fn check_evidence_successful() {
            let policy_manager = PolicyManager::new_with_policies(
                &default_appraisal_policies(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();
            assert!(policy_manager
                .check_evidence(NOW_UTC_MILLIS, &get_evidence_v1_genoa(), &get_genoa_vcek())
                .is_ok());
        }

        #[test]
        fn check_evidence_successful_multiple_container_binaries() {
            let policy_manager = PolicyManager::new_with_policies(
                &default_appraisal_policies_multiple_container_binaries(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();
            assert!(policy_manager
                .check_evidence(NOW_UTC_MILLIS, &get_evidence_v1_genoa(), &get_genoa_vcek())
                .is_ok());
        }

        #[test]
        fn check_evidence_error_no_container_binaries() {
            let policy_manager = PolicyManager::new_with_policies(
                &default_appraisal_policies_no_container_binaries(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();
            match policy_manager.check_evidence(
                NOW_UTC_MILLIS,
                &get_evidence_v2_genoa(),
                &get_genoa_vcek(),
            ) {
                Ok(_) => panic!("check_evidence() should fail."),
                Err(e) => assert_eq!(
                    e.to_string(),
                    "Failed to verify report. No matching appraisal policy found"
                ),
            }
        }

        #[test]
        fn check_evidence_error() {
            let policy_manager = PolicyManager::new_with_policies(
                &default_appraisal_policies(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();
            match policy_manager.check_evidence(
                NOW_UTC_MILLIS,
                &get_evidence_v2_genoa(),
                &get_genoa_vcek(),
            ) {
                Ok(_) => panic!("check_evidence() should fail."),
                Err(e) => assert_eq!(
                    e.to_string(),
                    "Failed to verify report. No matching appraisal policy found"
                ),
            }
        }

        #[test]
        fn policy_manager_creation_error() {
            match PolicyManager::new_with_policies(
                /*policies=*/ &[1, 2, 3],
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            ) {
                Ok(_) => panic!("PolicyManager::new() should fail."),
                Err(e) => assert_eq!(
                    e.to_string(),
                    "Failed to decode (serialize) appraisal policy."
                ),
            }

            match PolicyManager::new_with_policies(
                &insecure_appraisal_policies(),
                /*enable_policy_signature=*/ true,
                /*accept_insecure_policies=*/ false,
            ) {
                Ok(_) => panic!("PolicyManager::new() should fail."),
                Err(e) => assert_eq!(e.to_string(), "Cannot accept insecure policies."),
            }
        }
    }

    #[cfg(feature = "dynamic_attestation")]
    mod dynamic_attestation_tests {
        extern crate std;
        use super::*;
        use measure::{snp_calc_launch_digest_from_bytes, vcpu_types::CpuType};
        use oak_sev_snp_attestation_report::{AttestationReport, AttestationReportData};
        use runfiles::Runfiles;
        use sha2::{Digest, Sha256};
        use std::fs;
        use tvs_proto::pcit::tvs::{
            AmdSevDynamic, AppraisalPolicy, CpuInfo, Measurement, Stage0Measurement,
        };
        use zerocopy::FromZeros;

        fn get_milan_vcek() -> Vec<u8> {
            include_bytes!("../../../test_data/vcek_milan.crt").to_vec()
        }

        fn get_evidence_v1_milan() -> Evidence {
            Evidence::decode(
                include_bytes!("../../../test_data/evidence_v1_milan.binarypb").as_slice(),
            )
            .expect("could not decode evidence")
        }

        fn get_evidence_v2_milan() -> Evidence {
            Evidence::decode(
                include_bytes!("../../../test_data/evidence_v2_milan.binarypb").as_slice(),
            )
            .expect("could not decode evidence")
        }

        fn dynamic_milan_policies(stage0_hash: String, stage0_blob: &[u8]) -> Vec<u8> {
            let policies = AppraisalPolicies {
                policies: vec![AppraisalPolicy {
                    description: "Test against golden dynamic evidence milan".to_string(),
                    measurement: Some(Measurement {
                        stage0_measurement: Some(Stage0Measurement {
                            r#type: Some(stage0_measurement::Type::AmdSevDynamic(AmdSevDynamic {
                                stage0_ovmf_binary_hash: vec![stage0_hash.clone()],
                                min_tcb_version: Some(TcbVersion {
                                    boot_loader: 4,
                                    snp: 22,
                                    microcode: 213,
                                    ..Default::default()
                                }),
                                cpu_info: vec![CpuInfo { family: 25, model: 1, stepping: 1 }],
                                vcpu_count: vec![4],
                            })),
                        }),
                        kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                        kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                        init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                        memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                        acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                        kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                        system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                        container_binary_sha256:vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string()],
                    }),
                    ..Default::default()
                }],
                stage0_binary_sha256_to_blob: BTreeMap::from([(stage0_hash.clone(), stage0_blob.to_vec())]),
            };
            let mut buf = Vec::new();
            policies.encode(&mut buf).unwrap();
            buf
        }

        #[test]
        fn check_evidence_dynamic_success_milan() {
            let _ = env_logger::builder().is_test(true).try_init(); // comment/uncomment for logging

            let r = Runfiles::create().unwrap();
            let stage0_path = r
                .rlocation("_main/google_internal/oak_artifacts/stage0_bin")
                .expect("Failed to find stage0_bin in runfiles");
            let stage0_blob = fs::read(stage0_path).expect("Failed to read stage0_bin");
            let stage0_hash = hex::encode(Sha256::digest(&stage0_blob));

            let serialized_policies = dynamic_milan_policies(stage0_hash.clone(), &stage0_blob);
            let policy_manager = PolicyManager::new_with_policies(
                &serialized_policies,
                /*enable_policy_signature=*/ false,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();

            assert!(policy_manager
                .check_evidence(NOW_UTC_MILLIS, &get_evidence_v1_milan(), &get_milan_vcek())
                .is_ok());
        }

        #[test]
        fn check_evidence_dynamic_error_milan() {
            let _ = env_logger::builder().is_test(true).try_init(); // comment/uncomment for logging

            let r = Runfiles::create().unwrap();
            let stage0_path = r
                .rlocation("_main/google_internal/oak_artifacts/stage0_bin")
                .expect("Failed to find stage0_bin in runfiles");
            let stage0_blob = fs::read(stage0_path).expect("Failed to read stage0_bin");
            let stage0_hash = hex::encode(Sha256::digest(&stage0_blob));

            let serialized_policies = dynamic_milan_policies(stage0_hash.clone(), &stage0_blob);
            let policy_manager = PolicyManager::new_with_policies(
                &serialized_policies,
                /*enable_policy_signature=*/ false,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();

            match policy_manager.check_evidence(
                NOW_UTC_MILLIS,
                &get_evidence_v2_milan(),
                &get_milan_vcek(),
            ) {
                Ok(_) => panic!("check_evidence() should fail."),
                Err(e) => assert_eq!(
                    e.to_string(),
                    "Failed to verify report. No matching appraisal policy found"
                ),
            }
        }

        fn dynamic_genoa_policies(stage0_hash: String, stage0_blob: &[u8]) -> Vec<u8> {
            let policies = AppraisalPolicies {
                policies: vec![AppraisalPolicy {
                    description: "Test against golden dynamic evidence genoa".to_string(),
                    measurement: Some(Measurement {
                        stage0_measurement: Some(Stage0Measurement {
                            r#type: Some(stage0_measurement::Type::AmdSevDynamic(AmdSevDynamic {
                                stage0_ovmf_binary_hash: vec![stage0_hash.clone()],
                                min_tcb_version: Some(TcbVersion {
                                    boot_loader: 10,
                                    microcode: 84,
                                    snp: 25,
                                    ..Default::default()
                                }),
                                cpu_info: vec![CpuInfo { family: 25, model: 17, stepping: 1 }],
                                vcpu_count: vec![4],
                            })),
                        }),
                        kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447".to_string(),
                        kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a".to_string(),
                        init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391".to_string(),
                        memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe".to_string(),
                        acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e".to_string(),
                        kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$".to_string(),
                        system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836".to_string(),
                        container_binary_sha256:vec!["b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899".to_string()],
                    }),
                    ..Default::default()
                }],
                stage0_binary_sha256_to_blob: BTreeMap::from([(stage0_hash.clone(), stage0_blob.to_vec())]),
            };
            let mut buf = Vec::new();
            policies.encode(&mut buf).unwrap();
            buf
        }

        #[test]
        fn check_evidence_dynamic_success_genoa() {
            let _ = env_logger::builder().is_test(true).try_init(); // comment/uncomment for logging

            let r = Runfiles::create().unwrap();
            let stage0_path = r
                .rlocation("_main/google_internal/oak_artifacts/stage0_bin")
                .expect("Failed to find stage0_bin in runfiles");
            let stage0_blob = fs::read(stage0_path).expect("Failed to read stage0_bin");
            let stage0_hash = hex::encode(Sha256::digest(&stage0_blob));

            let serialized_policies = dynamic_genoa_policies(stage0_hash.clone(), &stage0_blob);
            let policy_manager = PolicyManager::new_with_policies(
                &serialized_policies,
                /*enable_policy_signature=*/ false,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();

            assert!(policy_manager
                .check_evidence(NOW_UTC_MILLIS, &get_evidence_v1_genoa(), &get_genoa_vcek())
                .is_ok());
        }

        #[test]
        fn check_evidence_dynamic_error_genoa() {
            let _ = env_logger::builder().is_test(true).try_init(); // comment/uncomment for logging

            let r = Runfiles::create().unwrap();
            let stage0_path = r
                .rlocation("_main/google_internal/oak_artifacts/stage0_bin")
                .expect("Failed to find stage0_bin in runfiles");
            let stage0_blob = fs::read(stage0_path).expect("Failed to read stage0_bin");
            let stage0_hash = hex::encode(Sha256::digest(&stage0_blob));

            let serialized_policies = dynamic_genoa_policies(stage0_hash.clone(), &stage0_blob);
            let policy_manager = PolicyManager::new_with_policies(
                &serialized_policies,
                /*enable_policy_signature=*/ false,
                /*accept_insecure_policies=*/ false,
            )
            .unwrap();

            match policy_manager.check_evidence(
                NOW_UTC_MILLIS,
                &get_evidence_v2_genoa(),
                &get_genoa_vcek(),
            ) {
                Ok(_) => panic!("check_evidence() should fail."),
                Err(e) => assert_eq!(
                    e.to_string(),
                    "Failed to verify report. No matching appraisal policy found"
                ),
            }
        }

        #[test]
        fn test_stage0_measurement_is_valid_success() {
            let r = Runfiles::create().unwrap();
            let stage0_path = r
                .rlocation("_main/google_internal/oak_artifacts/stage0_bin")
                .expect("Failed to find stage0_bin in runfiles");
            let stage0_blob =
                fs::read(stage0_path).expect("Failed to read stage0_bin from runfiles");

            let measured_cpu_type = CpuType::from_cpuid(25, 1, 1).unwrap(); // Milan
            let allowed_vcpu_counts = vec![1, 2, 4, 8];

            let expected_digest = snp_calc_launch_digest_from_bytes(
                4,
                measured_cpu_type.clone(),
                &stage0_blob,
                None,
                None,
                None,
            )
            .unwrap();

            let mut report_data = AttestationReportData::new_zeroed();
            report_data.measurement.copy_from_slice(&expected_digest.0);
            let mut mock_report = AttestationReport::new_zeroed();
            mock_report.data = report_data;

            let result = dynamic::stage0_measurement_is_valid(
                &stage0_blob,
                &mock_report,
                &measured_cpu_type,
                &allowed_vcpu_counts,
            );

            assert!(result.is_ok());
            assert!(result.unwrap());
        }

        #[test]
        fn test_stage0_measurement_is_valid_failure() {
            let r = Runfiles::create().unwrap();
            let stage0_path = r
                .rlocation("_main/google_internal/oak_artifacts/stage0_bin")
                .expect("Failed to find stage0_bin in runfiles");
            let stage0_blob =
                fs::read(stage0_path).expect("Failed to read stage0_bin from runfiles");

            let measured_cpu_type = CpuType::from_cpuid(25, 1, 1).unwrap();
            let allowed_vcpu_counts = vec![1, 2, 4, 8];

            // vCPU count of 5 is not within the appraisal policy
            let non_matching_digest = snp_calc_launch_digest_from_bytes(
                5,
                measured_cpu_type.clone(),
                &stage0_blob,
                None,
                None,
                None,
            )
            .unwrap();

            let mut report_data = AttestationReportData::new_zeroed();
            report_data
                .measurement
                .copy_from_slice(&non_matching_digest.0);
            let mut mock_report = AttestationReport::new_zeroed();
            mock_report.data = report_data;

            let result = dynamic::stage0_measurement_is_valid(
                &stage0_blob,
                &mock_report,
                &measured_cpu_type,
                &allowed_vcpu_counts,
            );

            assert!(result.is_ok());
            assert!(!result.unwrap()); // No match should be found
        }

        #[test]
        fn test_is_cpu_type_allowed() {
            let allowed_cpus = vec![
                // Milan CPU
                CpuInfo {
                    family: 25,
                    model: 1,
                    stepping: 1,
                },
                // Genoa CPU
                CpuInfo {
                    family: 25,
                    model: 17,
                    stepping: 0,
                },
            ];

            // should succeed
            let milan_cpu = (25, 1, 1);
            assert!(dynamic::is_cpu_type_allowed(milan_cpu, &allowed_cpus));
            let genoa_cpu = (25, 17, 0);
            assert!(dynamic::is_cpu_type_allowed(genoa_cpu, &allowed_cpus));

            // should fail
            let rome_cpu = (23, 49, 0);
            assert!(!dynamic::is_cpu_type_allowed(rome_cpu, &allowed_cpus));
            let wrong_stepping_milan = (25, 1, 2);
            assert!(!dynamic::is_cpu_type_allowed(
                wrong_stepping_milan,
                &allowed_cpus
            ));
        }
    }
}
