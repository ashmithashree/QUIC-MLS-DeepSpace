use std::{collections::BTreeMap, sync::{Arc, Mutex}};

pub struct CommitLog<G: ExportSecret> {
    inner: G,
    commit_log: BTreeMap<u64, Vec<u8>>,
    current_epoch: u64,
    checkpoint: u64,

}

pub trait ExportSecret: Send + Sync {
    fn export_secret(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, mls_rs::error::MlsError>;
    fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError>;
    fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError>;
}
// this calls the mls_rs::Group methods to export secrets, process_incoming_message and apply commits.
impl<C: mls_rs::client_builder::MlsConfig> ExportSecret for mls_rs::Group<C> {
    fn export_secret(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        Ok(mls_rs::Group::export_secret(self, label, context, len)?.as_bytes().to_vec())
    }

    // For the side RECEIVING a Commit over the wire/file.// bob need this to see what alice has sent and apply it to his own group state.
    fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError> {
        let message = mls_rs::MlsMessage::from_bytes(commit)?;
        self.process_incoming_message(message)?;
        Ok(())
    }

    // For the side PROPOSING a Commit: create it, apply it locally, and
    // return the serialized bytes so the application can send them to the peer. this is alice who is doing the commit and sending it to bob. she needs to apply it locally so her own state is updated.
    fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        let commit_output = self.commit(vec![])?;
        self.apply_pending_commit()?;
        commit_output.commit_message.to_bytes()
    }
}
//MlsClientConfig::new(Box::new(alice_group)) takes ownership of alice_group gets moved into the config, then into the live connection.  
//Once that happens, test code has no way to reach it again but we need to do for rekey so this 
//nstead of giving the config the Group directly, wrap it in Arc<Mutex<Group<...>>> first. 
//Arc lets to hold multiple owners of the same data; Mutex lets to mutate it safely from multiple places. 
//the config a clone of the Arc so the live MlsSession can call export_secret
// this is outer layer of export_secret that locks the mutex and calls the inner Group's export_secret.
impl<G: ExportSecret> ExportSecret for Arc<Mutex<G>> {
    fn export_secret(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        self.lock().unwrap().export_secret(label, context, len)
    }

    fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError> {
        self.lock().unwrap().apply_commit(commit)
    }

    fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        self.lock().unwrap().create_commit()
    }
}

impl<G: ExportSecret> ExportSecret for CommitLog<G> {
    fn export_secret(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        self.inner.export_secret(label, context, len)
    }
    fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError> {
        self.inner.apply_commit(commit)
    }

    fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        let bytes = self.inner.create_commit()?;
        self.current_epoch += 1;
        self.commit_log.insert(self.current_epoch, bytes.clone());
        Ok(bytes)
    }
    
}
impl<G: ExportSecret> CommitLog<G> {
   pub fn new(inner: G) -> Self {
        CommitLog {
            inner,
            commit_log: BTreeMap::new(),
            current_epoch: 0,
            checkpoint: 0,
        }
    }
    pub fn window_bytes(&self) -> Vec<(u64, Vec<u8>)> {
        self.commit_log
            .iter()
            .filter(|(epoch, _)| **epoch > self.checkpoint)
            .map(|(epoch, bytes)| (*epoch, bytes.clone()))
            .collect()
    }

    pub fn trim(&mut self, reported_k: u64) {
        let k = reported_k.min(self.current_epoch);
        self.checkpoint = self.checkpoint.max(k);
        self.commit_log.retain(|epoch, _| *epoch > self.checkpoint);
    }

    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }
}
/// Returned when the incoming window starts at an epoch the receiver cannot reach —
/// the peer fell off the back of the sender's commit log and cannot catch up without
/// a full resync.
#[derive(Debug)]
pub struct ResyncNeeded;

impl std::fmt::Display for ResyncNeeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fell off the back of the commit window: gap in received epochs")
    }
}

impl std::error::Error for ResyncNeeded {}

/// Processes a received commit window on the receiver side.

/// Guarantees: after a successful return *local_epoch equals the epoch of the
/// last commit in the window.  Stale entries (epoch <= current) are silently
/// skipped.  A gap (epoch > current + 1) is a fatal error: the caller must
/// trigger a full resync.
pub fn apply_commit_window(
    group: &mut dyn ExportSecret,
    window: &[(u64, Vec<u8>)],
    local_epoch: &mut u64,
) -> Result<(), ResyncNeeded> {
    for (epoch, commit_bytes) in window {
        if *epoch <= *local_epoch {
            // Stale commit already applied — skip quietly.
            continue;
        } else if *epoch == *local_epoch + 1 {
            group.apply_commit(commit_bytes).expect("MLS commit application failed");
            *local_epoch += 1;
        } else {
            // Gap: epoch jumped past local_epoch + 1, receiver cannot catch up.
            return Err(ResyncNeeded);
        }
    }
    Ok(())
}



