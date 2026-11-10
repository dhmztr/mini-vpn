use crate::crypto::decrypt_message;
use crate::crypto::derive_session_key;
use crate::crypto::encrypt_message;
use crate::crypto::generate_keys;
use crate::types::Errors;
use crate::types::InitialClientMessage;
use crate::types::InitialServerResponse;
use crate::types::KeyType;
use crate::types::Message;
use tokio::net::UdpSocket;
pub async fn connect_to_server(
    ip: &str,
) -> Result<((KeyType, KeyType), UdpSocket, String), Errors> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
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
