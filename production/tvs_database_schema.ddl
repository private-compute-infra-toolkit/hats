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

CREATE TABLE AppraisalPolicies (
  PolicyId STRING(1024),
  Policy BYTES(MAX),
) PRIMARY KEY(PolicyId);

CREATE TABLE DataEncryptionKey (
  DekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE DekIdSequence)),
  KekId INT64 NOT NULL,
  Dek BYTES(MAX),
) PRIMARY KEY(DekId);

CREATE TABLE ECKeys (
  KeyId STRING(1024),
  DekId INT64 NOT NULL,
  PrivateKey BYTES(MAX),
) PRIMARY KEY(KeyId);

CREATE TABLE KeyEncryptionKey (
  KekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE KekIdSequence)),
  ResourceName STRING(1024),
) PRIMARY KEY(KekId);

CREATE TABLE Secrets (
  SecretId STRING(1024),
  DekId INT64 NOT NULL,
  Secret BYTES(MAX),
) PRIMARY KEY(SecretId);
