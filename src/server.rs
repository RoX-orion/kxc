use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select
};
use anyhow::{Result, Context};
use std::str;
use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use std::sync::Arc;
use tokio::sync::Mutex;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[tokio::main]
async fn main() -> Result<()> {
    let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes AES-256 key
    let nonce = b"12345678abcdefgh"; // 16 bytes nonce

    let listener = TcpListener::bind("0.0.0.0:9000").await?;
    println!("Server listening on 0.0.0.0:9000");

    loop {
        let (stream, addr) = listener.accept().await?;
        let key = key.to_vec();
        let nonce = nonce.to_vec();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &key, &nonce).await {
                eprintln!("Failed to handle connection from {addr}: {e:?}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, key: &[u8], nonce: &[u8]) -> Result<()> {
    let encrypt_cipher = Arc::new(Mutex::new(Aes256Ctr::new(key[..].into(), nonce[..].into())));
    let decrypt_cipher = Arc::new(Mutex::new(Aes256Ctr::new(key[..].into(), nonce[..].into())));

    // ==== 读取客户端发来的目标地址信息 ====
    let mut header = [0u8; 1];
    stream.read_exact(&mut header).await?;
    decrypt_cipher.lock().await.apply_keystream(&mut header);
    let addr_type = header[0];

    let target_addr = match addr_type {
        0x01 => { // IPv4
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            decrypt_cipher.lock().await.apply_keystream(&mut buf);
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            format!("{ip}:{port}")
        }
        0x03 => { // 域名
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            decrypt_cipher.lock().await.apply_keystream(&mut len_buf);
            let domain_len = len_buf[0] as usize;

            let mut domain_buf = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain_buf).await?;
            decrypt_cipher.lock().await.apply_keystream(&mut domain_buf);

            let domain = str::from_utf8(&domain_buf[..domain_len])?;
            let port = u16::from_be_bytes([domain_buf[domain_len], domain_buf[domain_len + 1]]);
            format!("{domain}:{port}")
        }
        _ => anyhow::bail!("Unsupported address type: {addr_type}"),
    };

    let outbound = TcpStream::connect(&target_addr)
        .await
        .with_context(|| format!("Failed to connect to target {target_addr}"))?;

    let (mut ri, mut wi) = tokio::io::split(stream);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let c2s = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = ri.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            decrypt_cipher.lock().await.apply_keystream(&mut buf[..n]);
            wo.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let s2c = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = ro.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            encrypt_cipher.lock().await.apply_keystream(&mut buf[..n]);
            wi.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let _ = select!{
        res = c2s => res,
        res = s2c => res,
    };
    Ok(())
}
