use crate::client::first_message;
use crate::types::Errors;
use std::env;
use std::net::SocketAddrV4;
use tracing::debug;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
mod client;
mod crypto;
mod server;
mod types;
use crate::client::connect_to_server;
use crate::server::host_loop;

static PORT: u32 = 4232;

#[tokio::main]
async fn main() -> Result<(), Errors> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(Errors::ConfigError(format!(
            "usage: {} connect <ip> | {} listen <port>",
            args[0].rsplit_once("/").unwrap().1,
            args[0].rsplit_once("/").unwrap().1 // bound to exist due to program using / as splitters
        )));
    }
    match args[1].as_str() {
        "connect" => {
            if args.len() != 3 {
                return Err(Errors::ConfigError(
                    "Error you havent provided an ip to connect to!".into(),
                ));
            }
            let server_ip = &args[2];
            server_ip.parse::<SocketAddrV4>()?;
            let (keys, mut socket, vpn_ip) = connect_to_server(server_ip).await?;

            debug!(
                "Server to client key: {:?}\nClient to server key: {:?}",
                keys.0, keys.1
            );
            first_message(&mut socket, keys).await?;
            let mut vpn_config = tun2::Configuration::default();
            vpn_config
                .address(vpn_ip)
                .destination(server_ip)
                .netmask(24)
                .up();
            let interface = tun2::create_as_async(&vpn_config)?;
            Ok(())
        }
        "listen" => host_loop().await,

        _ => Err(Errors::ConfigError(
            "Incorrect argument availible are: listen | connect {port} ".into(),
        )),
    }
}
