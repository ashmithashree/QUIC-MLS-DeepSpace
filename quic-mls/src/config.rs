use std::sync::{Arc, Mutex};
use quinn_proto::{ConnectError, crypto::UnsupportedVersion};
use crate::keys::{derive_initial_keys};
use crate::session::MlsSession;
use crate::group::ExportSecret;
use quinn_proto::{crypto::{Keys, Session}, ConnectionId, transport_parameters::TransportParameters, Side};
use crate::retry::{compute_retry_tag};

pub struct MlsClientConfig {
    group: Mutex<Option<Box<dyn ExportSecret>>>,
    transcript_cap: usize,
}

impl MlsClientConfig {
    // The group is wrapped in a Mutex so that it can be safely accessed from multiple threads.
    // `transcript_cap` is the paper's tunable `tl` -- the byte budget for the
    // commit-transcript TLV this side embeds in its Initial-level handshake
    // data. Bob's window is always empty in this testbed (he never
    // originates commits), so his side of this doesn't matter in practice,
    // but the parameter is symmetric for both configs to avoid special-
    // casing one side of the handshake code.
    pub fn new(group: Box<dyn ExportSecret>, transcript_cap: usize) -> Self {
        Self { group: Mutex::new(Some(group)), transcript_cap }
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
        let group = self.group.lock().unwrap().take()
            .expect("MlsClientConfig is single-use: start_session called more than once");
        // The client never needs to observe this counter externally (Bob's
        // transcript to Alice is always empty in this testbed), so it's a
        // fresh, unshared counter local to this connection.
        let received_epoch = Arc::new(Mutex::new(0u64));
        Ok(Box::new(MlsSession::new(group, Side::Client, *params, received_epoch, self.transcript_cap)))
    }
}

pub struct MlsServerConfig {
    group: Mutex<Option<Box<dyn ExportSecret>>>,
    received_epoch: Arc<Mutex<u64>>,
    transcript_cap: usize,
}

impl MlsServerConfig {
    // `received_epoch` must be the same counter the caller's steady-state
    // control-plane task (testbed-runner's `run_commit_receiver`) shares
    // with this group, so handshake-time catch-up and post-handshake
    // catch-up agree on how far behind the peer is instead of racing.
    pub fn new(group: Box<dyn ExportSecret>, received_epoch: Arc<Mutex<u64>>, transcript_cap: usize) -> Self {
        Self { group: Mutex::new(Some(group)), received_epoch, transcript_cap }
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
        Box::new(MlsSession::new(
            group, Side::Server, *params,
            Arc::clone(&self.received_epoch), self.transcript_cap,
        ))
    }
}
