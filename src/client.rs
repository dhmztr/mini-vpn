use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::decrypt_message;
use crate::crypto::derive_session_key;
use crate::crypto::encrypt_message;
use crate::crypto::generate_keys;
use crate::types::Errors;
use crate::types::InitialClientMessage;
use crate::types::InitialServerResponse;
use crate::types::KeyType;
use crate::types::Message;
use crate::types::ReplayWindow;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tun2::AsyncDevice;
use tun2::DeviceWriter;
pub async fn connect_to_server(
    ip: &str,
) -> Result<((KeyType, KeyType), UdpSocket, String), Errors> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(ip).await?;
    let my_keys = generate_keys();
    let my_message = InitialClientMessage {
        my_key: *my_keys.1.as_bytes(),
    };
    let my_message_bytes = rmp_serde::to_vec::<InitialClientMessage>(&my_message)?;
    socket.send(&my_message_bytes).await?;
    let mut buf = [0u8; 128];
    let amount = socket.recv(&mut buf).await?;
    if amount == 0 {
        return Err(Errors::Other("Server didnt return anything".into()));
    }
    let server_message = rmp_serde::from_slice::<InitialServerResponse>(&buf[..amount])?;
    let encryption_keys = derive_session_key(my_keys.0, server_message.my_key);
    Ok((encryption_keys, socket, server_message.ip))
}

pub async fn first_message(
    socket: &mut UdpSocket,
    keys: (KeyType, KeyType),
) -> Result<u64, Errors> {
    let (s2c, c2s) = keys;
    let mut counter = 0;
    let encrypted = encrypt_message("hi".as_bytes(), c2s, counter)?;
    let message = Message {
        message: encrypted,
        counter,
    };
    let message_bytes = rmp_serde::to_vec(&message)?;
    socket.send(&message_bytes).await?;
    let mut server_buf = [0u8; 1024];
    let amount = socket.recv(&mut server_buf).await?;
    let returned = rmp_serde::from_slice::<Message>(&server_buf[..amount])?;
    let decrypted = decrypt_message(&returned.message, s2c, returned.counter)?;
    println!("Received response: {}", String::from_utf8_lossy(&decrypted));
    counter += 1;

    Ok(counter)
}

pub async fn client_loop(
    mut socket: UdpSocket,
    keys: (KeyType, KeyType),
    tun: AsyncDevice,
    mut counter: u64,
    ip: SocketAddr,
) -> Result<(), Errors> {
    let handle: Result<(), Errors> = tokio::spawn(async move {
        let mut replay = ReplayWindow::new();
        let (s2c, c2s) = keys;
        let device = Arc::new(tun);
        loop {
            let mut client_buf = [0u8; 1024];
            let mut tun_buf = [0u8; 1024];
            tokio::select! {
            read_value = socket.recv(&mut client_buf) => {
                println!("UDP READ");
                let read_value = read_value?;
                let raw_bytes = &client_buf[..read_value];
                handle_udp_recv(raw_bytes, s2c, device.clone(), &mut replay,ip).await?;
            }
            tun_bytes_read = device.recv(&mut tun_buf) => {
                let tun_bytes_read = tun_bytes_read?;
                handle_tun_read(&tun_buf[..tun_bytes_read], c2s, &mut socket, &mut counter).await?;
            }       }
        }
        Ok(())
    })
    .await?;
    handle
}

async fn handle_udp_recv(
    raw_msg_bytes: &[u8],
    s2c: KeyType,
    writer: Arc<AsyncDevice>,
    replay: &mut ReplayWindow,
    ip: SocketAddr,
) -> Result<(), Errors> {
    let parsed_message = rmp_serde::from_slice::<Message>(raw_msg_bytes)?;
    let data = decrypt_message(&parsed_message.message, s2c, parsed_message.counter)?;
    if !replay.check(parsed_message.counter) {
        return Err(Errors::Replay(ip));
    }
    writer.send(&data).await?;

    Ok(())
}

async fn handle_tun_read(
    raw_msg_bytes: &[u8],
    c2s: KeyType,
    socket: &mut UdpSocket,
    counter: &mut u64,
) -> Result<(), Errors> {
    let encrypted_data = encrypt_message(raw_msg_bytes, c2s, *counter)?;
    let message = Message {
        message: encrypted_data,
        counter: *counter,
    };
    *counter += 1;
    let message_bytes = rmp_serde::to_vec(&message)?;

    socket.send(&message_bytes).await?;
    Ok(())
}
