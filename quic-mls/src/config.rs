use std::sync::{Arc, Mutex};
use quinn_proto::{ConnectError, crypto::UnsupportedVersion};
use crate::keys::{derive_initial_keys};
use crate::session::MlsSession;
use crate::group::ExportSecret;
use quinn_proto::{crypto::{Keys, Session}, ConnectionId, transport_parameters::TransportParameters, Side};
use crate::retry::{compute_retry_tag};
pub struct MlsClientConfig {
    group: Mutex<Option<Box<dyn ExportSecret>>>,
}

impl MlsClientConfig {
    pub fn new(group: Box<dyn ExportSecret>) -> Self {
        Self { group: Mutex::new(Some(group)) }
    }
}

impl quinn_proto::crypto::ClientConfig for MlsClientConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let group = self.group.lock().unwrap().take()
            .expect("MlsClientConfig is single-use: start_session called more than once");
        Ok(Box::new(MlsSession::new(group, Side::Client, *params)))
    }
}

pub struct MlsServerConfig {
    group: Mutex<Option<Box<dyn ExportSecret>>>,
}

impl MlsServerConfig {
    pub fn new(group: Box<dyn ExportSecret>) -> Self {
        Self { group: Mutex::new(Some(group)) }
    }
}

impl quinn_proto::crypto::ServerConfig for MlsServerConfig {
    fn initial_keys(&self, _version: u32, dst_cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        Ok(derive_initial_keys(dst_cid, Side::Server))
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        compute_retry_tag(orig_dst_cid, packet)
    }

    fn start_session(self: Arc<Self>, _version: u32, params: &TransportParameters) -> Box<dyn Session> {
        let group = self.group.lock().unwrap().take()
            .expect("MlsServerConfig is single-use: start_session called more than once");
        Box::new(MlsSession::new(group, Side::Server, *params))
    }
}
