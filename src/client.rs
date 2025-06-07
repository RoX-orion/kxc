use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}, select};
use anyhow::Result;
use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub async fn client() -> Result<()> {
    let proxy_addr = "74.48.72.194:9000";
    let key = b"0123456789abcdef0123456789abcdef";
    let nonce = b"12345678abcdefgh";
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:1080").await?;
    println!("SOCKS5 proxy listening on 127.0.0.1:1080");

    loop {
        let (inbound, _) = listener.accept().await?;
        let proxy_addr = proxy_addr.to_string();
        let key = key.clone();
        let nonce = nonce.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5(inbound, &proxy_addr, &key, &nonce).await {
                eprintln!("Error: {e}");
            }
        });
    }
}

async fn handle_socks5(mut inbound: TcpStream, proxy_addr: &str, key: &[u8], nonce: &[u8]) -> Result<()> {
    let mut buf = [0u8; 2];
    inbound.read_exact(&mut buf).await?; // VER, NMETHODS
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    inbound.read_exact(&mut methods).await?;

    // 不认证
    inbound.write_all(&[0x05, 0x00]).await?;

    let mut req_hdr = [0u8; 4];
    inbound.read_exact(&mut req_hdr).await?; // VER CMD RSV ATYP
    if req_hdr[1] != 0x01 {
        return Err(anyhow::anyhow!("Only CONNECT supported"));
    }

    let addr = match req_hdr[3] {
        0x01 => {
            let mut ip_port = [0u8; 6];
            inbound.read_exact(&mut ip_port).await?;
            let target_addr = ip_port.to_vec();
            target_addr
        },
        0x03 => {
            let mut len = [0u8; 1];
            inbound.read_exact(&mut len).await?;
            let len = len[0] as usize;
            let mut domain = vec![0u8; len];
            inbound.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            inbound.read_exact(&mut port).await?;

            let mut target = vec![0x03u8, len as u8];
            target.extend_from_slice(&domain);
            target.extend_from_slice(&port);
            target
        },
        _ => return Err(anyhow::anyhow!("Unsupported ATYP")),
    };
    
    inbound.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let mut outbound = TcpStream::connect(proxy_addr).await?;

    let mut encrypt_cipher = Aes256Ctr::new(key[..].into(), nonce[..].into());
    let mut decrypt_cipher = Aes256Ctr::new(key[..].into(), nonce[..].into());

    let mut send_buf = addr.clone();
    encrypt_cipher.apply_keystream(&mut send_buf);
    outbound.write_all(&send_buf[..1]).await?; // addr_type
    outbound.write_all(&send_buf[1..]).await?;

    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let client_to_server = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = ri.read(&mut buf).await?;
            if n == 0 { break; }
            encrypt_cipher.apply_keystream(&mut buf[..n]);
            wo.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let server_to_client = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = ro.read(&mut buf).await?;
            if n == 0 { break; }
            decrypt_cipher.apply_keystream(&mut buf[..n]);
            wi.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let _ = select! {
        res = client_to_server => res,
        res = server_to_client => res,
    };

    Ok(())
}