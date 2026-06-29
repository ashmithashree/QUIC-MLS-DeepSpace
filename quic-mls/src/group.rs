use std::sync::{Arc, Mutex};

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



