use crate::client::client;
use crate::server::server;

mod client;
mod crypto;
mod server;

#[tokio::main]
async fn main() {
    let server_task = tokio::spawn(async {
        server().await.expect("Server error");
    });
    
    let client_task = tokio::spawn(async {
        client().await.expect("Client error");
    });
    
    let _ = tokio::try_join!(server_task, client_task).expect("At least one task failed");
}