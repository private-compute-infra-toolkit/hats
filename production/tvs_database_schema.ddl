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

CREATE TABLE AppraisalPolicies (
  PolicyId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE PolicyIdSequence)),
  ApplicationDigest BYTES(MAX) NOT NULL,
  Policy BYTES(MAX) NOT NULL,
  UpdateTimestamp TIMESTAMP NOT NULL,
) PRIMARY KEY(PolicyId);

CREATE INDEX ApplicationDigestIndex ON AppraisalPolicies(ApplicationDigest);

CREATE TABLE DataEncryptionKeys (
  DekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE DekIdSequence)),
  KekId INT64 NOT NULL,
  Dek BYTES(MAX) NOT NULL,
) PRIMARY KEY(DekId);

CREATE TABLE KeyEncryptionKeys (
  KekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE KekIdSequence)),
  ResourceName STRING(1024) NOT NULL,
) PRIMARY KEY(KekId);

CREATE UNIQUE INDEX KekResourceNameIndex ON KeyEncryptionKeys(ResourceName);

CREATE TABLE Secrets (
  SecretId INT64 NOT NULL,
  UserId INT64 NOT NULL,
  DekId INT64 NOT NULL,
  Secret BYTES(MAX) NOT NULL,
  UpdateTimestamp TIMESTAMP NOT NULL,
) PRIMARY KEY(SecretId, UserId);

CREATE TABLE TVSPrivateKeys (
  KeyId STRING(1024),
  DekId INT64 NOT NULL,
  PrivateKey BYTES(MAX) NOT NULL,
) PRIMARY KEY(KeyId);

CREATE TABLE TVSPublicKeys (
  KeyId STRING(1024),
  PublicKey STRING(MAX) NOT NULL,
) PRIMARY KEY(KeyId);

CREATE TABLE UserAuthenticationKeys (
  UserId INT64 NOT NULL,
  PublicKey BYTES(MAX) NOT NULL,
) PRIMARY KEY(UserId, PublicKey);

CREATE TABLE UserPublicKeys (
  SecretId INT64 NOT NULL,
  UserId INT64 NOT NULL,
  PublicKey STRING(1024) NOT NULL,
) PRIMARY KEY(SecretId);

CREATE TABLE Users (
  UserId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE UserIdSequence)),
  Name STRING(1024) NOT NULL,
  Origin STRING(1024),
  LockExpiryTime TIMESTAMP NOT NULL,
) PRIMARY KEY(UserId);

CREATE UNIQUE INDEX UserNameIndex ON Users(Name);
