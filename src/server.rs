use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::str::FromStr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::timeout;
use tracing::debug;
use tracing::field::debug;

use crate::crypto::decrypt_message;
use crate::crypto::derive_session_key;
use crate::crypto::encrypt_message;
use crate::crypto::generate_keys;
use crate::types::Cmd;
use crate::types::InitialClientMessage;
use crate::types::InitialServerResponse;
use crate::types::KeyType;
use crate::types::Message;
use crate::types::ReplayWindow;
use crate::{Errors, PORT};
use std::sync::Arc;
pub async fn host_loop() -> Result<(), Errors> {
    let socket: SocketAddrV4 = SocketAddrV4::from_str(format!("127.0.0.1:{PORT}").as_str())?;
    let server = Arc::new(tokio::net::UdpSocket::bind(socket).await?);
    let dispatcher_handle: Result<(), Errors> = tokio::spawn(async move {
        let mut client_map: HashMap<SocketAddr, Sender<Vec<u8>>> = HashMap::new();
        let (end_tx, mut end_rx) = mpsc::channel::<Cmd>(128);
        let loop_server = server.clone();
        let mut ips: Vec<String>= (1..255).into_iter().map(|id| format!("10.0.0.{id}")).collect();
        loop {
                
        
            
            let mut client_data_buf = [0u8; 1024];
            let client_tx = end_tx.clone();
            tokio::select! {
                packet = loop_server.recv_from(&mut client_data_buf) => {
                    let (amount,client) = packet?; 
                    let message = client_data_buf[..amount].to_vec();
                    if let Some(tx) = client_map.get(&client) {
                        if tx.send(message).await.is_err() {
                            client_map.remove(&client);
                        }
                    } else {
                        let allocated = ips.pop();

                        let ip = if let Some(ip) = allocated {
                        ip
                        } else {

                        loop_server.send_to("Connection failed".as_bytes(),client).await;
                        continue;
                            };
                        let (tx,rx) = mpsc::channel::<Vec<u8>>(128);
                        client_map.insert(client, tx);

                         let new_client_server = loop_server.clone();
                        let _ = tokio::spawn( async move {
                            match client_loop(message,(client,ip),rx,client_tx.clone(),new_client_server).await {
                                Ok(_) => {},
                                Err(e) if matches!(e,Errors::CryptographicError(_)) => {
                                    debug!("Critical error aborting!");
                                    return;
                                }
                                Err(e) => debug!("Error with client: {}:{}",client,e)

                            }
                        });

                    }

                },
                to_close = end_rx.recv() => {
                    if let Some(client) = to_close {
                        client_map.remove(&client.0.0);
                        ips.push(client.0.1)
                    }
            }
            }
        }

    })
    .await?;

    Ok(())
}

async fn client_loop(
    initial_bytes: Vec<u8>,
    client: (SocketAddr,String),
    mut rx: Receiver<Vec<u8>>,
    tx: Sender<Cmd>,
    socket: Arc<UdpSocket>,
) -> Result<(), Errors> {
    let mut counter;
    let mut replay_window = ReplayWindow::new();
    let initial = rmp_serde::from_slice::<InitialClientMessage>(&initial_bytes)?;
    let (s2c,c2s)= handle_key_exchange(&client.0,&client.1, initial.my_key, socket.clone()).await?;
    loop {
        let future = rx.recv();
        let time = Duration::from_secs(10);
        match timeout(time, future).await {
            Ok(Some(msg_bytes)) => {
                let result: Result<(), Errors> = {
                    let msg = rmp_serde::from_slice::<Message>(&msg_bytes)?;
                    let decrypted = decrypt_message(&msg.message, c2s, msg.counter)?;
                    if !replay_window.check(msg.counter) {
                        return Err(Errors::Replay(client.0))
                    }
                    debug!("User {}: {}", client.0, String::from_utf8_lossy(&decrypted));
                    counter = msg.counter + 1;
                    let message = encrypt_message("Hi back".as_bytes(), s2c, counter)?;
                    let response = Message { message, counter };
                    let encoded = rmp_serde::to_vec(&response)?;
                    socket.send_to(&encoded, client.0).await?;
                    Ok(())
                };
                if result.is_err() {
                    debug!("Failure on client side ending connection..");
                    break;
                }
            }
            _ => {
                    debug!("Failure on client side ending connection..");
                break;
            }
        }
    }

    tx.send(Cmd(client))
        .await
        .map_err(|e| Errors::Other(e.to_string()))
}
async fn handle_key_exchange(
    client: &SocketAddr,
    ip: &str,
    client_key: KeyType,
    stream: Arc<UdpSocket>,
) -> Result<(KeyType,KeyType), Errors> {
    let my_keys = generate_keys();
    let my_message = InitialServerResponse {
        my_key: my_keys.1.to_bytes(),
        ip:ip.to_owned()
    };
    let my_message_bytes = rmp_serde::to_vec(&my_message)?;
    let amount = stream.send_to(&my_message_bytes, client).await?;
    if amount < my_message_bytes.len() {
        return Err(Errors::Other(
            "Stream has been cut failed to send whole message".into(),
        ));
    }
    
    Ok(derive_session_key(my_keys.0, client_key))
}


