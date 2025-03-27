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

use crate::ffi::{CreateSessionResult, Params};
use oak_launcher_utils::channel::ConnectorHandle;
use oak_launcher_utils::launcher::GuestInstance;
use tokio::runtime::Runtime;
use tvs_enclave::proto::privacy_sandbox::tvs::TvsEnclaveAsyncClient;
use tvs_enclave::proto::privacy_sandbox::tvs::{
    CreateSessionRequest, DoCommandRequest, LoadAppraisalPoliciesRequest, ProvisionKeysRequest,
    RegisterOrUpdateUserRequest, TerminateSessionRequest,
};

/// Export API required to run TVS in Oak's restricted kernel to C++ code.
///
/// Provide wrapper around Oak's restricted kernel launcher, and TvsEnclave
/// MicroRpc client so that they can be used in C++ code.

/// Define FFI interface for Launcher and EnclaveClient rust structs to be
/// used in C++.
#[allow(clippy::needless_lifetimes)]
#[cxx::bridge(namespace = "privacy_sandbox::tvs")]
mod ffi {
    #[derive(Debug)]
    pub struct Params {
        pub vmm_binary: String,
        pub bios_binary: String,
        pub kernel: String,
        pub initrd: String,
        pub app_binary: String,
        pub memory_size: String,
    }

    pub struct CreateSessionResult {
        pub session_id: Vec<u8>,
        pub binary_message: Vec<u8>,
    }

    extern "Rust" {
        type Launcher;
        #[cxx_name = "NewLauncher"]
        fn new_launcher(param: &Params) -> Result<Box<Launcher>>;

        #[cxx_name = "Wait"]
        fn wait(self: &mut Launcher) -> Result<()>;

        type EnclaveClient<'a>;

        #[cxx_name = "CreateClient"]
        unsafe fn create_client<'a>(self: &'a Launcher) -> Box<EnclaveClient<'a>>;

        #[cxx_name = "ProvisionKeys"]
        fn provision_keys(self: &mut EnclaveClient, private_key: &[u8]) -> Result<()>;

        #[cxx_name = "LoadAppraisalPolicies"]
        fn load_appraisal_policies(self: &mut EnclaveClient, policies: &[u8]) -> Result<()>;

        #[cxx_name = "RegisterOrUpdateUser"]
        fn register_or_update_user(
            self: &mut EnclaveClient,
            id: &[u8],
            authentication_key: &[u8],
            secret: &[u8],
        ) -> Result<()>;

        #[cxx_name = "CreateSession"]
        fn create_session(
            self: &mut EnclaveClient,
            binary_message: &[u8],
        ) -> Result<CreateSessionResult>;

        #[cxx_name = "DoCommand"]
        fn do_command(
            self: &mut EnclaveClient,
            session_id: &[u8],
            binary_message: &[u8],
        ) -> Result<Vec<u8>>;

        #[cxx_name = "TerminateSession"]
        fn terminate_session(self: &mut EnclaveClient, session_id: &[u8]) -> Result<()>;
    }
}

/// Create a new launcher object.
pub fn new_launcher(params: &Params) -> anyhow::Result<Box<Launcher>> {
    Launcher::launch(params)
}

/// Wrapper around Oak's restricted kernel launcher rust code. The launcher code
/// is `async`. The object here creates a runtime and runs the function inside
/// tokio's runtime.
pub struct Launcher {
    runtime: Runtime,
    instance: Option<Box<dyn GuestInstance>>,
    connector_handle: ConnectorHandle,
}

impl Launcher {
    /// Launch the VMM
    pub fn launch(params: &Params) -> anyhow::Result<Box<Self>> {
        let runtime = tokio::runtime::Runtime::new()?;
        let (instance, connector_handle) = runtime
            .block_on(oak_launcher_utils::launcher::launch(
                oak_launcher_utils::launcher::Params {
                    vmm_binary: params.vmm_binary.clone().into(),
                    bios_binary: params.bios_binary.clone().into(),
                    kernel: params.kernel.clone().into(),
                    initrd: params.initrd.clone().into(),
                    app_binary: Some(params.app_binary.clone().into()),
                    memory_size: Some(params.memory_size.clone()),
                    gdb: None,
                    pci_passthrough: None,
                },
            ))
            .map_err(|err| anyhow::anyhow!("Failed to launch qemu: {err}"))?;

        Ok(Box::new(Self {
            runtime,
            instance: Some(instance),
            connector_handle,
        }))
    }

    /// Wait for the VMM until it terminates.
    pub fn wait(&mut self) -> anyhow::Result<()> {
        let Some(ref mut instance) = self.instance else {
            anyhow::bail!("no VMM instance to wait upon");
        };
        match self.runtime.block_on(instance.wait()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Create a wrapper around TvsEnclaveAsyncClient so that it can be used
    /// in C++ and non-async environment.
    pub fn create_client(&self) -> Box<EnclaveClient> {
        Box::new(EnclaveClient {
            runtime: &self.runtime,
            inner_client: TvsEnclaveAsyncClient::new(self.connector_handle.clone()),
        })
    }
}

/// Implement Drop trait for `Launcher` to kill the VMM process.
/// `oak_launcher_utils::launcher::GuestInstance` provides
/// `kill(self: Box<Self>)`. However, the method takes ownership of the object
/// i.e. moves and rust does not allow moving out struct members.
/// We wrap the GuestInstance into an option and use std::mem::replace() to get
/// the wrapped GuestInstance while replacing it with None, then we call kill.
/// If we do not kill the VMM process, the C++ launcher binary (or integration
/// test) will not terminate.
impl Drop for Launcher {
    fn drop(&mut self) {
        #[allow(clippy::mem_replace_option_with_none)]
        let instance = std::mem::replace(&mut self.instance, None);
        if let Some(instance) = instance {
            let _ = self.runtime.block_on(instance.kill());
        }
    }
}

/// Wrapper around TvsEnclaveAsyncClient to be used in non-async code and in C++.
pub struct EnclaveClient<'a> {
    runtime: &'a Runtime,
    inner_client: TvsEnclaveAsyncClient<ConnectorHandle>,
}

impl<'a> EnclaveClient<'a> {
    pub fn provision_keys(&mut self, private_key: &[u8]) -> anyhow::Result<()> {
        self.runtime
            .block_on(self.inner_client.provision_keys(&ProvisionKeysRequest {
                private_key: private_key.to_vec(),
            }))??;
        Ok(())
    }

    pub fn load_appraisal_policies(&mut self, policies: &[u8]) -> anyhow::Result<()> {
        self.runtime
            .block_on(self.inner_client.load_appraisal_policies(
                &LoadAppraisalPoliciesRequest {
                    policies: policies.to_vec(),
                },
            ))??;
        Ok(())
    }

    pub fn register_or_update_user(
        &mut self,
        id: &[u8],
        authentication_key: &[u8],
        secret: &[u8],
    ) -> anyhow::Result<()> {
        self.runtime
            .block_on(self.inner_client.register_or_update_user(
                &RegisterOrUpdateUserRequest {
                    id: id.to_vec(),
                    authentication_key: authentication_key.to_vec(),
                    secret: secret.to_vec(),
                },
            ))??;
        Ok(())
    }

    pub fn create_session(&mut self, binary_message: &[u8]) -> anyhow::Result<CreateSessionResult> {
        let response =
            self.runtime
                .block_on(self.inner_client.create_session(&CreateSessionRequest {
                    binary_message: binary_message.to_vec(),
                }))??;
        Ok(CreateSessionResult {
            session_id: response.session_id,
            binary_message: response.binary_message,
        })
    }

    pub fn do_command(
        &mut self,
        session_id: &[u8],
        binary_message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let response =
            self.runtime
                .block_on(self.inner_client.do_command(&DoCommandRequest {
                    session_id: session_id.to_vec(),
                    binary_message: binary_message.to_vec(),
                }))??;
        Ok(response.binary_message)
    }

    pub fn terminate_session(&mut self, session_id: &[u8]) -> anyhow::Result<()> {
        self.runtime
            .block_on(
                self.inner_client
                    .terminate_session(&TerminateSessionRequest {
                        session_id: session_id.to_vec(),
                    }),
            )
            .map_err(|err| anyhow::anyhow!("failed to call termiante_session: {err}"))??;
        Ok(())
    }
}
