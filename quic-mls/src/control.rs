
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
pub async fn write_message(send: &mut quinn::SendStream, msg: &ControlMessage) -> std::io::Result<()>{ 
    let bytes=encode(msg);
    send.write_all(&bytes).await?;
    send.flush().await?;
    Ok(())
}