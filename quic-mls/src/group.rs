pub trait ExportSecret: Send + Sync {
    fn export_secret(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, mls_rs::error::MlsError>;
    fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError>;
    fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError>;
}

impl<C: mls_rs::client_builder::MlsConfig> ExportSecret for mls_rs::Group<C> {
    fn export_secret(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        Ok(mls_rs::Group::export_secret(self, label, context, len)?.as_bytes().to_vec())
    }

    // For the side RECEIVING a Commit over the wire/file.
    fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError> {
        let message = mls_rs::MlsMessage::from_bytes(commit)?;
        self.process_incoming_message(message)?;
        Ok(())
    }

    // For the side PROPOSING a Commit: create it, apply it locally, and
    // return the serialized bytes so the application can send them to the peer.
    fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        let commit_output = self.commit(vec![])?;
        self.apply_pending_commit()?;
        commit_output.commit_message.to_bytes()
    }
}
