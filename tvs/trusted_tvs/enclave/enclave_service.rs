// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;
use trusted_tvs::request_handler::RequestHandler;
use tvs_enclave::proto::privacy_sandbox::tvs::{
    CreateSessionRequest, CreateSessionResponse, DoCommandRequest, DoCommandResponse,
    TerminateSessionRequest, TvsEnclave,
};
pub struct EnclaveService<'a> {
    service: &'a trusted_tvs::service::Service,
    request_handlers: BTreeMap<Vec<u8>, RequestHandler<'a>>,
}

impl<'a> EnclaveService<'a> {
    pub fn new(service: &'a trusted_tvs::service::Service) -> Self {
        Self {
            service,
            request_handlers: BTreeMap::new(),
        }
    }
}

impl<'a> TvsEnclave for EnclaveService<'a> {
    fn create_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, micro_rpc::Status> {
        // For now, we use a hard-coded time value from the past.
        const NOW_UTC_MILLIS: i64 = 1732062397340;
        let mut request_handler = self
            .service
            .create_request_handler(NOW_UTC_MILLIS, /*user=*/ "");
        let response = request_handler
            .verify_report(&request.binary_message)
            .map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::Internal,
                    format!("failed to initiate a session: {err}"),
                )
            })?;
        let session_id = request_handler.handshake_hash();
        if self.request_handlers.contains_key(&session_id) {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::NotFound,
                "failed to initiate a session.",
            ));
        };
        self.request_handlers
            .insert(session_id.clone(), *request_handler);
        Ok(CreateSessionResponse {
            session_id,
            binary_message: response,
        })
    }

    fn do_command(
        &mut self,
        request: DoCommandRequest,
    ) -> Result<DoCommandResponse, micro_rpc::Status> {
        let Some(request_handler) = self.request_handlers.get_mut(&request.session_id) else {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::NotFound,
                "failed to find the session",
            ));
        };
        let response = request_handler
            .verify_report(&request.binary_message)
            .map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::Internal,
                    format!("failed to process request: {err}"),
                )
            })?;
        Ok(DoCommandResponse {
            binary_message: response,
        })
    }

    fn terminate_session(
        &mut self,
        request: TerminateSessionRequest,
    ) -> Result<(), micro_rpc::Status> {
        if self.request_handlers.remove(&request.session_id).is_none() {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::NotFound,
                "failed to remove session. The session does not exist",
            ));
        }
        Ok(())
    }
}
