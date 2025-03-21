-- Copyright 2024 Google LLC.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- A schema for a database used to store TVS secrets and appraisal policies.

CREATE SEQUENCE DekIdSequence OPTIONS (
  sequence_kind = 'bit_reversed_positive'
);

CREATE SEQUENCE KekIdSequence OPTIONS (
  sequence_kind = 'bit_reversed_positive'
);

CREATE SEQUENCE PolicyIdSequence OPTIONS (
  sequence_kind = 'bit_reversed_positive'
);

CREATE SEQUENCE UserIdSequence OPTIONS (
  sequence_kind = 'bit_reversed_positive'
);

-- Table storing appraisal policies used to validate attestation report
-- against. The table contains the following columns:
-- * PolicyId: a string used to identify the appraisal policy.
-- * AmdSevStage0Digest: sha384 digest of stage0.bin. This column is nullable.
-- * KernelImageDigest: sha256 of the kernel image.
-- * KernelSetupDataDigest: sha256 of the kernel setup data.
-- * InitRamFsDigest: sha256 of the initramfs.
-- * MemoryMapDigest: sha256 of the memory map.
-- * AcpiTableDigest: sha256 of the ACPI tables.
-- * SystemImageDigest: sha256 of the system image.
-- * ApplicationDigest: sha256 of the container binary application bundle.
-- * UpdateTimestamp: timestamp of the last update to the row.
-- * Policy: binary representation of the appraisal policy proto.
CREATE TABLE AppraisalPolicies (
  PolicyId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE PolicyIdSequence)),
  AmdSevStage0Digest BYTES(MAX),
  KernelImageDigest BYTES(MAX) NOT NULL,
  KernelSetupDataDigest BYTES(MAX) NOT NULL,
  InitRamFsDigest BYTES(MAX) NOT NULL,
  MemoryMapDigest BYTES(MAX) NOT NULL,
  AcpiTableDigest BYTES(MAX) NOT NULL,
  SystemImageDigest BYTES(MAX) NOT NULL,
  ApplicationDigest BYTES(MAX) NOT NULL,
  Policy BYTES(MAX) NOT NULL,
  UpdateTimestamp TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY(PolicyId);

-- Non-unique Index ApplicationDigest field to enable efficient retrieval of
-- policies for a certain application.
CREATE INDEX ApplicationDigestIndex ON AppraisalPolicies(ApplicationDigest);

-- Table storing wrapped data encryption keys (DEK)s. DEKs are encrypted with
-- KekId. The table contains the following columns:
-- * DekId: a unique identifier for a DEK.
-- * KekId: specifies the KEK used to wrap the DEK.
-- * Dek: a DEK encrypted with KekId.
CREATE TABLE DataEncryptionKeys (
  DekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE DekIdSequence)),
  KekId INT64 NOT NULL,
  Dek BYTES(MAX) NOT NULL,
) PRIMARY KEY(DekId);

-- Table storing key encryption keys (KEK)s metadata. KEK resides in KMS and
-- never leaves. The table contains the following columns:
-- * KekId: a unique identifier for a KEK.
-- * ResourceName: KMS key resource name in the following format
--   projects/<project_name>/location/<location>/KeyRings/<key_ring_name>/
--   cryptoKeys/<key_name>.
CREATE TABLE KeyEncryptionKeys (
  KekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE KekIdSequence)),
  ResourceName STRING(1024) NOT NULL,
) PRIMARY KEY(KekId);

CREATE UNIQUE INDEX KekResourceNameIndex ON KeyEncryptionKeys(ResourceName);

-- Table storing secrets to be returned to entities passing TVS attestation.
-- Secret could be full or partial HPKE keys or any arbitrary strings. The
-- stored secrets are wrapped with a DEK. The table contains the following
-- columns:
-- * SecretId: a unique identifier for secrets.
-- * UserId: the ID of the user owning the secret.
-- * DekId: specifies the DEK used to wrap the secret.
-- * Secret: a secret wrapped with DekId.
-- * UpdateTimestamp: timestamp of the last update to the row.
CREATE TABLE Secrets (
  SecretId INT64 NOT NULL,
  UserId INT64 NOT NULL,
  DekId INT64 NOT NULL,
  Secret BYTES(MAX) NOT NULL,
  UpdateTimestamp TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY(SecretId, UserId);

-- Table storing wrapped TVS private EC keys. The keys are used in the noise
-- protocol. The table contains the following columns:
-- * KeyId: a string used to identify the TVS key e.g. primary_key.
-- * DekId: specifies the DEK used to wrap the TVS key.
-- * PrivateKey: a TVS private key encrypted with DekId.
-- * UpdateTimestamp: timestamp of the last update to the row.
CREATE TABLE TVSPrivateKeys (
  KeyId STRING(1024),
  DekId INT64 NOT NULL,
  PrivateKey BYTES(MAX) NOT NULL,
  UpdateTimestamp TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY(KeyId);

-- Table storing TVS public keys. The public keys are stored in a separate
-- tables so that we can relax the ACLs on it.
CREATE TABLE TVSPublicKeys (
  KeyId STRING(1024),
  PublicKey STRING(MAX) NOT NULL,
  UpdateTimestamp TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY(KeyId);

-- Table storing public keys used by a particular user. The table contains
-- the following columns:
-- * UserId: the ID of the user owning the private part of the given public
--           key.
-- * PublicKey: the public part of the key that the user uses when
--              authenticating with the TVS.
CREATE TABLE UserAuthenticationKeys (
  UserId INT64 NOT NULL,
  PublicKey BYTES(MAX) NOT NULL,
) PRIMARY KEY(UserId, PublicKey);

-- Table storing public keys of the users.
CREATE TABLE UserPublicKeys (
  SecretId INT64 NOT NULL,
  UserId INT64 NOT NULL,
  PublicKey STRING(1024) NOT NULL,
) PRIMARY KEY(SecretId);

-- Table storing information about the registered users. Registered users
-- are the one allowed to use TVS. The table contains the following columns:
-- * UserId: a unique identifier for the user.
-- * Name: a name to identify the user.
-- * Origin: protocol, hostname, and port (in essence the URL used by the
-- user).
CREATE TABLE Users (
  UserId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE UserIdSequence)),
  Name STRING(1024) NOT NULL,
  Origin STRING(1024),
  LockExpiryTime TIMESTAMP NOT NULL,
) PRIMARY KEY(UserId);

CREATE UNIQUE INDEX UserNameIndex ON Users(Name);
