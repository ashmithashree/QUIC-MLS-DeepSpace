use std::sync::{Arc, Mutex};
use quinn_proto::{ConnectError, crypto::UnsupportedVersion};
use crate::keys::{derive_initial_keys};
use crate::session::MlsSession;
use crate::group::ExportSecret;
use quinn_proto::{crypto::{Keys, Session}, ConnectionId, transport_parameters::TransportParameters, Side};
use crate::retry::{compute_retry_tag};
pub struct MlsClientConfig {
    group: Mutex<Option<Box<dyn ExportSecret>>>,
    early_data: bool,
}
// this 0-RTT field is initilised here because the live MlsSession needs to know if it should offer 0-RTT keys derived from the group's current epoch.
impl MlsClientConfig {
    // these are constructors for the MlsClientConfig and MlsServerConfig. The group is wrapped in a Mutex so that it can be safely accessed from multiple threads, and the early_data flag indicates whether 0-RTT keys should be offered.
    //just hardcoded to false for now, but could be set to true if the peer is already known to share that epoch.
    pub fn new(group: Box<dyn ExportSecret>) -> Self {
        Self { group: Mutex::new(Some(group)), early_data: false }
    }

    // Like `new`, but the resulting session offers 0-RTT keys derived from
    // the group's current epoch --- use only when the peer is already known
    // to share that epoch.
    pub fn new_with_early_data(group: Box<dyn ExportSecret>) -> Self {
        Self { group: Mutex::new(Some(group)), early_data: true }
    }
}

impl quinn_proto::crypto::ClientConfig for MlsClientConfig {
    
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        //it gets the group out of the mutex, and takes ownership of it. If the mutex is already empty,
        //it means that start_session has already been called once, and it panics.
        //the group is then used to create a new MlsSession, which is returned as a boxed trait object. 
        //The early_data flag determines whether the session should offer 0-RTT keys.
        let group = self.group.lock().unwrap().take()
            .expect("MlsClientConfig is single-use: start_session called more than once");
        let session = if self.early_data {
            MlsSession::new_with_early_data(group, Side::Client, *params)
        } else {
            MlsSession::new(group, Side::Client, *params)
        };
        Ok(Box::new(session))
    }
}

pub struct MlsServerConfig {
    group: Mutex<Option<Box<dyn ExportSecret>>>,
    early_data: bool,
}

impl MlsServerConfig {
    pub fn new(group: Box<dyn ExportSecret>) -> Self {
        Self { group: Mutex::new(Some(group)), early_data: false }
    }

    // Like `new`, but the resulting session offers 0-RTT keys derived from
    // the group's current epoch --- use only when the peer is already known
    // to share that epoch.
    pub fn new_with_early_data(group: Box<dyn ExportSecret>) -> Self {
        Self { group: Mutex::new(Some(group)), early_data: true }
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
        let session = if self.early_data {
            MlsSession::new_with_early_data(group, Side::Server, *params)
        } else {
            MlsSession::new(group, Side::Server, *params)
        };
        Box::new(session)
    }
}
