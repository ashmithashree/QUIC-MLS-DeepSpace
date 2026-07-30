//Note:
// Minimal application-level control-message framing for commit propagation
// over a quinn SendStream/RecvStream, deliberately outside MLS's own scope.
// Reference: RFC 9420 section 1 / Delivery Service note — MLS explicitly scopes
//   message delivery/ordering out of the protocol, leaving it to the
//   application (justification for this file's existence and its
//   decoupling from session.rs).
//   https://www.rfc-editor.org/rfc/rfc9420.html
//======================================================================================================================
pub enum ControlMessage{
    Report(u64),
    Hello,
}

fn encode(msg: &ControlMessage) -> Vec<u8>{
    let mut buf = Vec::new();
    match msg {
        ControlMessage::Report(epoch) => {
            buf.push(0x02);
            buf.extend_from_slice(&epoch.to_be_bytes());
        }
        ControlMessage::Hello => {
            buf.push(0x03);
        }
    }
    buf
}
use tokio::io::AsyncReadExt;

//decoding function for ControlMessage
pub async fn read_message(recv: &mut quinn::RecvStream) -> std::io::Result<ControlMessage>{

    let msg_type = recv.read_u8().await?;
    match msg_type {
        0x02 => {
            let epoch = recv.read_u64().await?;
            Ok(ControlMessage::Report(epoch))
        }
        0x03 => Ok(ControlMessage::Hello),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message type")),
    }
}
use tokio::io::AsyncWriteExt;
pub async fn write_message(send: &mut quinn::SendStream, msg: &ControlMessage) -> std::io::Result<usize>{
    let bytes=encode(msg);
    let n = bytes.len();
    send.write_all(&bytes).await?;
    send.flush().await?;
    Ok(n)
}

use crate::group::{CommitLog, ExportSecret};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};


pub async fn run_report_receiver<G: ExportSecret + 'static>(
    commit_log: Arc<Mutex<CommitLog<G>>>,
    mut ctrl_recv: quinn::RecvStream,
) {
    loop {
        match read_message(&mut ctrl_recv).await {
            Ok(ControlMessage::Report(k)) => {
                commit_log.lock().unwrap().trim(k);
            }
            Ok(ControlMessage::Hello) => {}
            Err(_) => break,
        }
    }
}


pub async fn run_report_sender(
    mut ctrl_send: quinn::SendStream,
    mut epoch_rx: tokio::sync::watch::Receiver<u64>,
    should_report: Arc<AtomicBool>,
) {
    loop {
        let epoch = *epoch_rx.borrow_and_update();
        if should_report.load(Ordering::SeqCst)
            && write_message(&mut ctrl_send, &ControlMessage::Report(epoch)).await.is_err()
        {
            break;
        }
        if epoch_rx.changed().await.is_err() {
            break;
        }
    }
}