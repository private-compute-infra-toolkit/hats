// Copyright 2025 Google LLC.
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

use anyhow::anyhow;
use client_proto::pcit::tvs::Secret;
use client_proto::pcit::tvs::VerifyReportResponse;
use mockall::automock;
use oak_proto_rust::oak::attestation::v1::Evidence;
use p256::ecdsa::SigningKey;
use prost::Message;
use secret_sharing::SecretSplit;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::{sync::RwLock, task::JoinHandle, time::Duration};
use tvs_grpc_client::TvsClientInterface;

pub struct TvsSecretManager {
    encoded_report: Arc<RwLock<Vec<u8>>>,
    update_task: Option<JoinHandle<()>>,
}

#[automock]
#[tonic::async_trait]
pub trait TvsSecretManagerInterface: Send + Sync {
    async fn get_encoded_report(&self) -> Result<Vec<u8>, anyhow::Error>;
    fn clone_box(&self) -> Box<dyn TvsSecretManagerInterface>;
}

struct KeyShares<'a> {
    public_key: String,
    shares: Vec<&'a [u8]>,
}

impl TvsSecretManager {
    pub async fn create(
        grpc_clients: Vec<Box<dyn TvsClientInterface>>,
        evidence: &Evidence,
        signing_key: SigningKey,
        secret_split: Option<Box<dyn SecretSplit>>,
        tvs_heartbeat_frequency_seconds: u64,
    ) -> Result<Box<dyn TvsSecretManagerInterface>, anyhow::Error> {
        let encoded_report = get_encoded_report(
            &grpc_clients,
            evidence,
            signing_key.clone(),
            secret_split.as_deref(),
        )
        .await?;

        let cache = Self {
            encoded_report: Arc::new(RwLock::new(encoded_report)),
            update_task: None,
        };

        let update_task = cache.start_update_task(
            grpc_clients,
            evidence.clone(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        );

        Ok(Box::new(Self {
            encoded_report: cache.encoded_report.clone(),
            update_task: Some(update_task),
        }))
    }

    fn start_update_task(
        &self,
        grpc_clients: Vec<Box<dyn TvsClientInterface>>,
        evidence: Evidence,
        signing_key: SigningKey,
        secret_split: Option<Box<dyn SecretSplit>>,
        tvs_heartbeat_frequency_seconds: u64,
    ) -> JoinHandle<()> {
        let cache = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(tvs_heartbeat_frequency_seconds));
            loop {
                interval.tick().await;
                if let Err(err) = cache
                    .update_encoded_report(
                        &grpc_clients,
                        &evidence,
                        signing_key.clone(),
                        secret_split.as_deref(),
                    )
                    .await
                {
                    log::error!("Error updating encoded report: {:?}", err);
                }
            }
        })
    }

    async fn update_encoded_report(
        &self,
        grpc_clients: &[Box<dyn TvsClientInterface>], // Changed to slice
        evidence: &Evidence,
        signing_key: SigningKey,
        secret_split: Option<&dyn SecretSplit>,
    ) -> Result<(), anyhow::Error> {
        let new_encoded_report = get_encoded_report(
            grpc_clients, // No need to call to_vec()
            evidence,
            signing_key.clone(),
            secret_split,
        )
        .await?;
        let mut encoded_report_lock = self.encoded_report.write().await;
        *encoded_report_lock = new_encoded_report;
        Ok(())
    }

    pub async fn get_encoded_report(&self) -> Result<Vec<u8>, anyhow::Error> {
        let encoded_report_lock = self.encoded_report.read().await;
        Ok(encoded_report_lock.clone())
    }
}

impl Clone for TvsSecretManager {
    fn clone(&self) -> Self {
        Self {
            encoded_report: self.encoded_report.clone(),
            update_task: None,
        }
    }
}

#[tonic::async_trait]
impl TvsSecretManagerInterface for TvsSecretManager {
    async fn get_encoded_report(&self) -> Result<Vec<u8>, anyhow::Error> {
        {
            TvsSecretManager::get_encoded_report(self).await
        }
    }
    fn clone_box(&self) -> Box<dyn TvsSecretManagerInterface> {
        Box::new(Self {
            encoded_report: self.encoded_report.clone(),
            update_task: None,
        })
    }
}

impl Drop for TvsSecretManager {
    fn drop(&mut self) {
        if let Some(task) = self.update_task.take() {
            task.abort();
        }
    }
}

async fn get_encoded_report(
    tvs_grpc_clients: &[Box<dyn TvsClientInterface>],
    evidence: &Evidence,
    signing_key: SigningKey,
    secret_split: Option<&dyn SecretSplit>,
) -> anyhow::Result<Vec<u8>> {
    let encoded_report: Vec<u8>;
    if tvs_grpc_clients.len() > 1 {
        let mut response_vec: Vec<VerifyReportResponse> = Vec::new();
        for tvs_grpc_client in tvs_grpc_clients {
            response_vec.push(
                VerifyReportResponse::decode(
                    tvs_grpc_client
                        .send_evidence(evidence.clone(), signing_key.clone())
                        .await
                        .map_err(|error| anyhow!("couldn't fetch split tvs client: {:?}", error))?
                        .as_slice(),
                )
                .map_err(|error| anyhow!("couldn't decode VerifyReportResponse: {:?}", error))?,
            );
        }
        encoded_report = match secret_split {
            Some(secret_split) => recover_secrets(&response_vec, Some(secret_split))?,
            None => recover_secrets(&response_vec, None)?,
        };
    } else {
        encoded_report = tvs_grpc_clients[0]
            .send_evidence(evidence.clone(), signing_key.clone())
            .await
            .map_err(|error: String| anyhow!("couldn't fetch single tvs client: {:?}", error))?
    }
    Ok(encoded_report)
}
pub fn recover_secrets(
    response_vec: &Vec<VerifyReportResponse>,
    secret_split: Option<&dyn SecretSplit>,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut recovered_secrets: Vec<Secret> = Vec::new();
    let mut share_map: HashMap<String, KeyShares> = HashMap::new();
    for response in response_vec {
        for secret in &response.secrets {
            let key_shares = share_map.entry(secret.key_id.clone()).or_insert(KeyShares {
                public_key: (*secret.public_key).to_string(),
                shares: vec![],
            });
            key_shares.shares.push(&secret.private_key);
        }
    }
    for (key_id, key_shares) in share_map {
        recovered_secrets.push(Secret {
            key_id: key_id.clone(),
            public_key: (*key_shares.public_key).to_string(),
            private_key: match secret_split {
                Some(secret_split) => secret_split
                    .recover(&key_shares.shares)
                    .map_err(|err| anyhow::anyhow!("Failed to recover the secret: {err:?}"))?,
                None => key_shares.shares[0].to_vec(),
            },
        });
    }
    let recovered_report = VerifyReportResponse {
        secrets: recovered_secrets,
    };
    let mut encoded_report: Vec<u8> = Vec::new();
    VerifyReportResponse::encode(&recovered_report, &mut encoded_report)?;
    Ok(encoded_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use oak_containers_attestation::generate_instance_keys;
    use tvs_grpc_client::{MockTvsClientInterface, TvsClientInterface};

    fn get_valid_private_key() -> Vec<u8> {
        let kem = bssl_crypto::hpke::Kem::X25519HkdfSha256;
        let (_, private) = kem.generate_keypair();
        private.to_vec()
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_create_single_client() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();

        let mut mock_tvs_client = MockTvsClientInterface::new();
        let private_key_clone = private_key.clone();
        mock_tvs_client
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: private_key_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box = Box::new(mock_tvs_client) as Box<dyn TvsClientInterface>;
        let secret_split: Option<Box<dyn SecretSplit>> = None;
        let tvs_heartbeat_frequency_seconds: u64 = 3600;
        let manager = TvsSecretManager::create(
            vec![mock_tvs_client_box],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report = manager.get_encoded_report().await.unwrap();
        let response = VerifyReportResponse::decode(report.as_slice()).unwrap();
        assert_eq!(response.secrets[0].key_id, "501".to_string());
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_create_multiple_clients_shamir() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();

        let numshares = 3;
        let mut secret_split: Option<Box<dyn SecretSplit>> = Some(Box::new(
            secret_sharing::shamir_sharing::ShamirSharing::new(
                numshares,
                // we set the threshold to be 1 less than number of shares.
                // this is the minimum threshold for recovery.
                numshares - 1,
                secret_sharing::shamir_sharing::get_prime(),
            )
            .unwrap(),
        )
            as Box<dyn SecretSplit>);

        let shares: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key)
            .as_ref()
            .unwrap()
            .to_vec();

        let share1_bytes: Vec<u8> = shares
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes: Vec<u8> = shares
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes: Vec<u8> = shares
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let share1_bytes_clone = share1_bytes.clone();
        let share2_bytes_clone = share2_bytes.clone();
        let share3_bytes_clone = share3_bytes.clone();

        let mut mock_tvs_client1 = MockTvsClientInterface::new();
        mock_tvs_client1
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share1_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box1 = Box::new(mock_tvs_client1) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client2 = MockTvsClientInterface::new();
        mock_tvs_client2
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share2_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box2 = Box::new(mock_tvs_client2) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client3 = MockTvsClientInterface::new();
        mock_tvs_client3
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share3_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box3 = Box::new(mock_tvs_client3) as Box<dyn TvsClientInterface>;

        let private_key_clone = private_key.clone();

        let tvs_heartbeat_frequency_seconds: u64 = 3600;
        let manager = TvsSecretManager::create(
            vec![
                mock_tvs_client_box1,
                mock_tvs_client_box2,
                mock_tvs_client_box3,
            ],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report = manager.get_encoded_report().await.unwrap();
        let response = VerifyReportResponse::decode(report.as_slice()).unwrap();
        assert_eq!(response.secrets[0].key_id, "501".to_string());
        assert_eq!(response.secrets[0].public_key, "test-public-key1");
        assert_eq!(response.secrets[0].private_key, private_key_clone);
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_create_multiple_clients_xor() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();

        let numshares = 3;
        let mut secret_split: Option<Box<dyn SecretSplit>> = Some(Box::new(
            secret_sharing::xor_sharing::XorSharing::new(numshares).unwrap(),
        )
            as Box<dyn SecretSplit>);

        let shares: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key)
            .as_ref()
            .unwrap()
            .to_vec();

        let share1_bytes: Vec<u8> = shares
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes: Vec<u8> = shares
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes: Vec<u8> = shares
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let share1_bytes_clone = share1_bytes.clone();
        let share2_bytes_clone = share2_bytes.clone();
        let share3_bytes_clone = share3_bytes.clone();

        let mut mock_tvs_client1 = MockTvsClientInterface::new();
        mock_tvs_client1
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share1_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box1 = Box::new(mock_tvs_client1) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client2 = MockTvsClientInterface::new();
        mock_tvs_client2
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share2_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box2 = Box::new(mock_tvs_client2) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client3 = MockTvsClientInterface::new();
        mock_tvs_client3
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share3_bytes_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box3 = Box::new(mock_tvs_client3) as Box<dyn TvsClientInterface>;

        let private_key_clone = private_key.clone();

        let tvs_heartbeat_frequency_seconds: u64 = 3600;
        let manager = TvsSecretManager::create(
            vec![
                mock_tvs_client_box1,
                mock_tvs_client_box2,
                mock_tvs_client_box3,
            ],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report = manager.get_encoded_report().await.unwrap();
        let response = VerifyReportResponse::decode(report.as_slice()).unwrap();
        assert_eq!(response.secrets[0].key_id, "501".to_string());
        assert_eq!(response.secrets[0].public_key, "test-public-key1");
        assert_eq!(response.secrets[0].private_key, private_key_clone);
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_update_single_client() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();
        let mut mock_tvs_client = MockTvsClientInterface::new();
        let private_key_clone = private_key.clone();
        mock_tvs_client
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: private_key_clone.clone(),
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box = Box::new(mock_tvs_client) as Box<dyn TvsClientInterface>;
        let secret_split: Option<Box<dyn SecretSplit>> = None;
        let tvs_heartbeat_frequency_seconds: u64 = 1;
        let manager = TvsSecretManager::create(
            vec![mock_tvs_client_box],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report1 = manager.get_encoded_report().await.unwrap();
        // Wait for the update task to run
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let report2 = manager.get_encoded_report().await.unwrap();
        assert_eq!(report1, report2);
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_update_single_client_different_response() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key1 = get_valid_private_key();
        let private_key2 = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();
        let private_key1_clone = private_key1.clone();
        let private_key2_clone = private_key2.clone();
        let mut call_count = 0;
        let mut mock_tvs_client = MockTvsClientInterface::new();
        mock_tvs_client
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count += 1;
                let private_key = if call_count == 1 {
                    private_key1_clone.clone()
                } else {
                    private_key2_clone.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box = Box::new(mock_tvs_client) as Box<dyn TvsClientInterface>;
        let secret_split: Option<Box<dyn SecretSplit>> = None;
        let tvs_heartbeat_frequency_seconds: u64 = 1;
        let manager = TvsSecretManager::create(
            vec![mock_tvs_client_box],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report1 = manager.get_encoded_report().await.unwrap();
        // Wait for the update task to run
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let report2 = manager.get_encoded_report().await.unwrap();
        assert_ne!(report1, report2);
        let response1 = VerifyReportResponse::decode(report1.as_slice()).unwrap();
        let response2 = VerifyReportResponse::decode(report2.as_slice()).unwrap();
        assert_eq!(response1.secrets[0].private_key, private_key1);
        assert_eq!(response2.secrets[0].private_key, private_key2);
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_update_multi_client_shamir() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key1 = get_valid_private_key();
        let private_key2 = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();

        let numshares = 3;
        let mut secret_split: Option<Box<dyn SecretSplit>> = Some(Box::new(
            secret_sharing::shamir_sharing::ShamirSharing::new(
                numshares,
                // we set the threshold to be 1 less than number of shares.
                // this is the minimum threshold for recovery.
                numshares - 1,
                secret_sharing::shamir_sharing::get_prime(),
            )
            .unwrap(),
        )
            as Box<dyn SecretSplit>);

        let shares1: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key1)
            .as_ref()
            .unwrap()
            .to_vec();

        let shares2: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key2)
            .as_ref()
            .unwrap()
            .to_vec();

        let share1_bytes1: Vec<u8> = shares1
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes1: Vec<u8> = shares1
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes1: Vec<u8> = shares1
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let share1_bytes2: Vec<u8> = shares2
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes2: Vec<u8> = shares2
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes2: Vec<u8> = shares2
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let mut call_count_1 = 0;
        let mut call_count_2 = 0;
        let mut call_count_3 = 0;
        let mut mock_tvs_client1 = MockTvsClientInterface::new();
        mock_tvs_client1
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count_1 += 1;
                let share_bytes = if call_count_1 == 1 {
                    share1_bytes1.clone()
                } else {
                    share1_bytes2.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share_bytes,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box1 = Box::new(mock_tvs_client1) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client2 = MockTvsClientInterface::new();
        mock_tvs_client2
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count_2 += 1;
                let share_bytes = if call_count_2 == 1 {
                    share2_bytes1.clone()
                } else {
                    share2_bytes2.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share_bytes,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box2 = Box::new(mock_tvs_client2) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client3 = MockTvsClientInterface::new();
        mock_tvs_client3
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count_3 += 1;
                let share_bytes = if call_count_3 == 1 {
                    share3_bytes1.clone()
                } else {
                    share3_bytes2.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share_bytes,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box3 = Box::new(mock_tvs_client3) as Box<dyn TvsClientInterface>;

        let tvs_heartbeat_frequency_seconds: u64 = 1;
        let manager = TvsSecretManager::create(
            vec![
                mock_tvs_client_box1,
                mock_tvs_client_box2,
                mock_tvs_client_box3,
            ],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report1 = manager.get_encoded_report().await.unwrap();
        // Wait for the update task to run
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let report2 = manager.get_encoded_report().await.unwrap();
        assert_ne!(report1, report2);
        let response1 = VerifyReportResponse::decode(report1.as_slice()).unwrap();
        let response2 = VerifyReportResponse::decode(report2.as_slice()).unwrap();

        assert_eq!(response1.secrets[0].private_key, private_key1);
        assert_eq!(response2.secrets[0].private_key, private_key2);
    }

    #[tokio::test]
    async fn test_tvs_secret_manager_update_multi_client_xor() {
        let (instance_keys, _) = generate_instance_keys();
        let private_key1 = get_valid_private_key();
        let private_key2 = get_valid_private_key();
        let signing_key = instance_keys.signing_key.clone();

        let numshares = 3;
        let mut secret_split: Option<Box<dyn SecretSplit>> = Some(Box::new(
            secret_sharing::xor_sharing::XorSharing::new(numshares).unwrap(),
        )
            as Box<dyn SecretSplit>);

        let shares1: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key1)
            .as_ref()
            .unwrap()
            .to_vec();

        let shares2: Vec<String> = secret_split
            .as_mut()
            .expect("Reason: secret split failed")
            .split(&private_key2)
            .as_ref()
            .unwrap()
            .to_vec();

        let share1_bytes1: Vec<u8> = shares1
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes1: Vec<u8> = shares1
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes1: Vec<u8> = shares1
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let share1_bytes2: Vec<u8> = shares2
            .first()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share2_bytes2: Vec<u8> = shares2
            .get(1)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let share3_bytes2: Vec<u8> = shares2
            .get(2)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();

        let mut call_count_1 = 0;
        let mut call_count_2 = 0;
        let mut call_count_3 = 0;

        let mut mock_tvs_client1 = MockTvsClientInterface::new();
        mock_tvs_client1
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count_1 += 1;
                let share_bytes = if call_count_1 == 1 {
                    share1_bytes1.clone()
                } else {
                    share1_bytes2.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share_bytes,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box1 = Box::new(mock_tvs_client1) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client2 = MockTvsClientInterface::new();
        mock_tvs_client2
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count_2 += 1;
                let share_bytes = if call_count_2 == 1 {
                    share2_bytes1.clone()
                } else {
                    share2_bytes2.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share_bytes,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box2 = Box::new(mock_tvs_client2) as Box<dyn TvsClientInterface>;

        let mut mock_tvs_client3 = MockTvsClientInterface::new();
        mock_tvs_client3
            .expect_send_evidence()
            .with(always(), always())
            .returning(move |_, _| {
                call_count_3 += 1;

                let share_bytes = if call_count_3 == 1 {
                    share3_bytes1.clone()
                } else {
                    share3_bytes2.clone()
                };
                let response = VerifyReportResponse {
                    secrets: vec![Secret {
                        key_id: "501".to_string(),
                        public_key: "test-public-key1".to_string(),
                        private_key: share_bytes,
                    }],
                };
                let mut encoded = Vec::new();
                VerifyReportResponse::encode(&response, &mut encoded).unwrap();
                Ok(encoded)
            });
        let mock_tvs_client_box3 = Box::new(mock_tvs_client3) as Box<dyn TvsClientInterface>;

        let tvs_heartbeat_frequency_seconds: u64 = 1;
        let manager = TvsSecretManager::create(
            vec![
                mock_tvs_client_box1,
                mock_tvs_client_box2,
                mock_tvs_client_box3,
            ],
            &Evidence::default(),
            signing_key,
            secret_split,
            tvs_heartbeat_frequency_seconds,
        )
        .await
        .unwrap();

        let report1 = manager.get_encoded_report().await.unwrap();
        // Wait for the update task to run
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let report2 = manager.get_encoded_report().await.unwrap();
        assert_ne!(report1, report2);
        let response1 = VerifyReportResponse::decode(report1.as_slice()).unwrap();
        let response2 = VerifyReportResponse::decode(report2.as_slice()).unwrap();
        assert_eq!(response1.secrets[0].private_key, private_key1);
        assert_eq!(response2.secrets[0].private_key, private_key2);
    }
}
