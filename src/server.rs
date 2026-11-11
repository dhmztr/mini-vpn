use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::str::FromStr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::timeout;
use tracing::debug;

use crate::crypto::decrypt_message;
use crate::crypto::derive_session_key;
use crate::crypto::encrypt_message;
use crate::crypto::generate_keys;
use crate::types::Cmd;
use crate::types::InitialClientMessage;
use crate::types::InitialServerResponse;
use crate::types::IntraServerMessageType;
use crate::types::KeyType;
use crate::types::Message;
use crate::types::ReplayWindow;
use crate::types::ServerInterMessage;
use crate::{Errors, PORT};
use std::sync::Arc;
pub async fn host_loop() -> Result<(), Errors> {
    let socket: SocketAddrV4 = SocketAddrV4::from_str(format!("0.0.0.0:{PORT}").as_str())?;
    let server = Arc::new(tokio::net::UdpSocket::bind(socket).await?);
    debug!("Socket bind okay");

    let dispatcher_handle: Result<(), Errors> = tokio::spawn(async move {
        let mut client_map: HashMap<SocketAddr, Sender<ServerInterMessage>> = HashMap::new();
        let mut vpn_socket_map: HashMap<String, SocketAddr> = HashMap::new();
        let (end_tx, mut end_rx) = mpsc::channel::<Cmd>(128);
        let (vpn_tx,mut vpn_rx) = mpsc::channel::<Vec<u8>>(128);
        let loop_server = server.clone();
        let mut ips: Vec<String>= (2..255).into_iter().map(|id| format!("10.0.0.{id}")).collect();

    let mut vpn_config = tun2::Configuration::default();
    vpn_config.address("10.0.0.1").
            netmask("255.255.255.0").up();
    debug!("Config okay");
    let interface = tun2::create_as_async(&vpn_config)?;
    debug!("Interface okay");
    let device  = Arc::new(interface);
    debug!("Split okay");
        loop {
                
        
            
            let mut client_data_buf = [0u8; 1024];
            let mut vpn_buf = [0u8; 1024];
            tokio::select! {
                packet = loop_server.recv_from(&mut client_data_buf) => {
                    let (amount,client) = packet?; 
                    let message = client_data_buf[..amount].to_vec();
                    if let Some(tx) = client_map.get(&client) {
                        let msg = ServerInterMessage {
                            message_type: IntraServerMessageType::UDP,
                            data: message

                    };
                        if tx.send(msg).await.is_err() {
                            client_map.remove(&client);
                        }
                    } else {
                        let client_end_tx = end_tx.clone();
                        let client_vpn_tx = vpn_tx.clone();
                        let allocated = ips.pop();

                        let ip = if let Some(ip) = allocated {
                        ip
                        } else {

                        loop_server.send_to("Connection failed".as_bytes(),client).await;
                        continue;
                            };
                        let (tx,rx) = mpsc::channel::<ServerInterMessage>(128);
                        client_map.insert(client, tx);
                        vpn_socket_map.insert(ip.clone(), client);

                         let new_client_server = loop_server.clone();
                        let _ = tokio::spawn( async move {
                            match single_connection_loop(message,(client,ip),rx,client_vpn_tx.clone(),client_end_tx.clone(),new_client_server).await {
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
            bytes_read = device.recv(&mut vpn_buf) => {
                    let bytes_read  = bytes_read?;
                    let raw_message = vpn_buf[..bytes_read].to_vec();
                    let dest_bytes: [u8; 4] = raw_message[16..20].try_into().unwrap();
                    let dest_ip = std::net::Ipv4Addr::from(dest_bytes).to_string();
                    debug!("VPN read {} bytes, dest_ip={}", bytes_read, dest_ip);
                    let Some(dest_socket) = vpn_socket_map.get(&dest_ip) else {continue;};
                    let Some(tx) = client_map.get(dest_socket) else {
                    vpn_socket_map.remove(&dest_ip);
                    continue;
                };
                    let inter_message = ServerInterMessage {
                            message_type: IntraServerMessageType::VPN,
                            data: raw_message 
                };
                    tx.send(inter_message).await;
                    

                }
            vpn_msg = vpn_rx.recv() => {
                    let Some(vpn_msg) = vpn_msg else {continue;};
                    device.send(&vpn_msg).await?;
                    

                }
            
            }
        }

    })
    .await?;
    dispatcher_handle?;
    Ok(())

}

async fn single_connection_loop(
    initial_bytes: Vec<u8>,
    client: (SocketAddr,String),
    mut rx: Receiver<ServerInterMessage>,
    mut vpn_tx: Sender<Vec<u8>>,
    end_tx: Sender<Cmd>,
    socket: Arc<UdpSocket>,
) -> Result<(), Errors> {
    let mut counter = 1;
    let mut replay_window = ReplayWindow::new();
    let initial = rmp_serde::from_slice::<InitialClientMessage>(&initial_bytes)?;
    let (s2c,c2s)= handle_key_exchange(&client.0,&client.1, initial.my_key, socket.clone()).await?;
    loop {
        let future = rx.recv();
        let time = Duration::from_secs(1000);
        match timeout(time, future).await {
            Ok(Some(inter_message)) => {
                let result: Result<(), Errors> = {
                    match inter_message.message_type {
                        IntraServerMessageType::UDP => {
            handle_udp_message(&inter_message.data, &mut vpn_tx, 
                                &mut replay_window, &mut counter, 
                                client.0, (s2c,c2s)).await

                        }
                        IntraServerMessageType::VPN => {

                    handle_vpn_message(&inter_message.data, socket.clone(),  &mut counter,s2c,client.0).await
                        }

                    }
                };
                if result.is_err() {
                    let _ = result.is_err_and(|e| {
                        debug!("Client error: {}",e); true
                    });
                    break;
                }
            }
            _ => {
                    debug!("Failure on client side ending connection..");
                break;
            }
        }
    }

    end_tx.send(Cmd(client))
        .await
        .map_err(|e| Errors::Other(e.to_string()))
}
async fn handle_udp_message(msg_bytes:&[u8],writer:&mut Sender<Vec<u8>>,replay_window:&mut ReplayWindow,counter:&mut u64,client:SocketAddr,keys:(KeyType,KeyType)) -> Result<(),Errors>  {

                    let msg = rmp_serde::from_slice::<Message>(&msg_bytes)?;
                    let decrypted = decrypt_message(&msg.message, keys.1, msg.counter)?;
                    if !replay_window.check(msg.counter) {
                        return Err(Errors::Replay(client))
                    }
                    debug!("User {}: {}", client, String::from_utf8_lossy(&decrypted));
                    *counter +=  1;
                    writer.send(decrypted).await;
                    Ok(())
}
async fn handle_vpn_message(msg_bytes:&[u8],socket:Arc<UdpSocket>,counter:&mut u64,s2c:KeyType,client:SocketAddr ) -> Result<(),Errors>  {
    let message_encrypted = encrypt_message(msg_bytes, s2c, *counter)?;
    let message= Message {
        message:message_encrypted,
        counter:*counter
    };
    *counter+=1;
    let serialized = rmp_serde::to_vec(&message)?;
    socket.send_to(&serialized, client).await?;
    Ok(())



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


