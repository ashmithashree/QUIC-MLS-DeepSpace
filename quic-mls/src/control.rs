
pub enum ControlMessage{
    CommitWindow(Vec<(u64, Vec<u8>)>) ,
    Report(u64),
}

fn encode(msg: &ControlMessage) -> Vec<u8>{
    let mut buf = Vec::new();
    match msg {
        ControlMessage::CommitWindow(w) => {
            buf.push(0x01);
            buf.extend_from_slice(&(w.len() as u64).to_be_bytes());
            for (epoch, bytes) in w {
                buf.extend_from_slice(&epoch.to_be_bytes());
                buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(bytes);
            }
        }
        ControlMessage::Report(epoch) => {
            buf.push(0x02);
            buf.extend_from_slice(&epoch.to_be_bytes());
        }
    }
    buf
}
use tokio::io::AsyncReadExt;

//decoding function for ControlMessage
pub async fn read_message(recv: &mut quinn::RecvStream) -> std::io::Result<ControlMessage>{
    
    let msg_type = recv.read_u8().await?;
    match msg_type {
        0x01 => {
            let mut w = Vec::new();
            let count = recv.read_u64().await?;
            for _ in 0..count {
                let epoch = recv.read_u64().await?;
                let len = recv.read_u32().await? as usize;
                let mut bytes = vec![0u8; len];
                recv.read_exact(&mut bytes).await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e.to_string()))?;
                w.push((epoch, bytes));
            }
            Ok(ControlMessage::CommitWindow(w))
        }
        0x02 => {
            let epoch = recv.read_u64().await?;
            Ok(ControlMessage::Report(epoch))
        }
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

use crate::group::{CommitLog, ExportSecret, apply_commit_window};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;


pub async fn send_window_and_trim<G: ExportSecret>(
    commit_log: &Arc<Mutex<CommitLog<G>>>,
    ctrl_send: &mut quinn::SendStream,
    ctrl_recv: &mut quinn::RecvStream,
    timeout: Duration,
) -> std::io::Result<usize> {
    let window = commit_log.lock().unwrap().window_bytes();
    if window.is_empty() {
        return Ok(0);
    }
    let bytes_sent = write_message(ctrl_send, &ControlMessage::CommitWindow(window)).await?;
    match tokio::time::timeout(timeout, read_message(ctrl_recv)).await {
        Ok(Ok(ControlMessage::Report(k))) => {
            commit_log.lock().unwrap().trim(k);
        }
        _ => {} // timeout or error: leave untrimmed, will retry next cycle
    }
    Ok(bytes_sent)
}


pub async fn run_commit_receiver<G: ExportSecret + 'static>(
    group: Arc<Mutex<G>>,
    mut ctrl_send: quinn::SendStream,
    mut ctrl_recv: quinn::RecvStream,
    should_report: Arc<AtomicBool>,
    local_epoch: Arc<Mutex<u64>>,
) {
    loop {
        match read_message(&mut ctrl_recv).await {
            Ok(ControlMessage::CommitWindow(w)) => {
                let reported_epoch = {
                    let mut guard = group.lock().unwrap();
                    let mut epoch_guard = local_epoch.lock().unwrap();
                    if apply_commit_window(&mut *guard, &w, &mut *epoch_guard).is_err() {
                        break;
                    }
                    *epoch_guard
                };
                if should_report.load(Ordering::SeqCst) {
                    if write_message(&mut ctrl_send, &ControlMessage::Report(reported_epoch))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            Ok(ControlMessage::Report(_)) => {}
            Err(_) => break,
        }
    }
}