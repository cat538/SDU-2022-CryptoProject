use std::env;
use std::io::{prelude::*, stdin, stdout};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, thread};
use hex::{encode_upper,decode};

use my_server::*;


#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::*;
    use serde::{Deserialize, Serialize};
    use std::fmt::Display;
    use secp256k1::bitcoin_hashes::{sha256, Hash};
    use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature};

    lazy_static! {
        static ref CURVE: Secp256k1<All> = Secp256k1::new();
    }
    
    #[derive(Serialize, Deserialize, Debug)]
    struct Info {
        msg: Vec<u8>,
        sign: Vec<u8>,
        pk: Vec<u8>,
    }
    
    impl Display for Info {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "msg: {}\n", String::from_utf8_lossy(&self.msg))?;
            write!(f, "sig: {}\n", Signature::from_compact(&self.sign).unwrap())?;
            write!(f, "pk : {}\n", PublicKey::from_slice(&self.pk).unwrap())?;
            Ok(())
        }
    }

    #[test]
    fn test_sig() {
        let sk = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let pk = PublicKey::from_secret_key(&CURVE, &sk);
        let dgst = sha256::Hash::hash("Hello world!".as_bytes());
        let message = Message::from(dgst);
        let sig = CURVE.sign(&message, &sk);
        assert!(CURVE.verify(&message, &sig, &pk).is_ok());
    }

    #[test]
    fn test_p256() {
        use p256::elliptic_curve::group::ff::PrimeField;
        use p256::Scalar;
        use p256::SecretKey;
        let b1 = Scalar::from_str("1").unwrap();
        let sk = SecretKey::from_bytes([1u8; 32]);
        let base_point = p256::AffinePoint::default();
    }

    #[test]
    fn test_sm2(){
        use libsm::sm2::signature::{Pubkey, Seckey, Signature, SigCtx};
        use libsm::sm2::encrypt::{DecryptCtx, EncryptCtx};

        let plain_text = "Hello, This is dmhj!".to_string();
        let msg = plain_text.as_bytes();

        // 1. 签名
        let ctx = SigCtx::new();

        let (vrfy_key, sign_key) = ctx.new_keypair().unwrap();
        let (enc_key, dec_key) = ctx.new_keypair().unwrap();
        let signature = ctx.sign(msg, &sign_key, &vrfy_key).unwrap();
        let result: bool = ctx.verify(msg, &vrfy_key, &signature).unwrap();
        assert!(result == true);
        println!("{}", signature.to_string());

        // 2. 加密
        let klen = msg.len();
        
        let encrypt_ctx = EncryptCtx::new(klen, enc_key);
        let cipher = encrypt_ctx.encrypt(msg).unwrap();

        let decrypt_ctx = DecryptCtx::new(klen, dec_key);
        let plain_recover = decrypt_ctx.decrypt(&cipher).unwrap();
        println!("cipher: {:?}", String::from_utf8_lossy(&cipher));
        println!("plain:  {:?}", String::from_utf8(plain_recover).unwrap());

    }
    #[test]
    fn test_server() {
        let server =
            thread::spawn(|| server_new("127.0.0.1:8080", Arc::new(|stream| handle_http(stream))));

        server.join().unwrap();
    }

    #[test]
    fn test_client() {
        let message = "This is DMhj";
        let sk = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let pk = PublicKey::from_secret_key(&CURVE, &sk);
        let dgst = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
        let sig = CURVE.sign(&dgst, &sk);

        let content = Info {
            msg: message.as_bytes().to_vec(),
            sign: Vec::from(sig.serialize_compact()),
            pk: Vec::from(pk.serialize()),
        };

        let content_str = serde_json::to_string(&content).unwrap();
        println!("{}", content);

        match TcpStream::connect("localhost:8080") {
            Ok(mut stream) => {
                println!("Successfully connected to server in port 8080");

                stream.write(content_str.as_bytes()).unwrap();
                println!("Sent content, awaiting reply...");

                let mut data = [0u8; 1024]; // using 6 byte buffer
                stream.read(&mut data).unwrap();
                println!("{}", String::from_utf8_lossy(&data));
            }
            Err(e) => {
                println!("Failed to connect: {}", e)
            }
        }
        println!("Terminated.");
    }

}

#[derive(Debug)]
struct NetError(String);

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "There is an error: {}", self.0)
    }
}
impl std::error::Error for NetError {}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage\n\n\t[EXE] [IP] [PORT]\n Start a server at specified socket\n\t\
        and establish connection to it");
        return Err(Box::new(NetError("Filed to start the server\n".into())));
    }

    let server_addr = args[1].clone() + ":" + args[2].as_str();
    let server_addr = SocketAddr::from_str(&server_addr).unwrap();

    // let server = thread::spawn(move || {

    //     server_new(
    //         server_addr,
    //         Arc::new(|mut stream| {
    //             let mut recv_data = [0u8; 1024];
    //             let read_len = stream.read(&mut recv_data).unwrap();

    //             stream.write(&recv_data[0..read_len]).unwrap();
    //             stream.flush().unwrap();
    //         }),
    //     )
    // });

    let server = thread::spawn(move ||{
        sm2_server(server_addr, Arc::new(|mut stream|{}));
    });
    
    use libsm::sm2::encrypt::{DecryptCtx, EncryptCtx};
    use libsm::sm2::signature::{Pubkey, Seckey, SigCtx, Signature};

    let ctx = SigCtx::new();

    let (vrfy_key, sign_key) = ctx.new_keypair().unwrap();
    let (enc_key, dec_key) = ctx.new_keypair().unwrap();

    let info = Agreement { 
        header: HEADER, 
        enc_key:encode_upper(&ctx.serialize_pubkey(&enc_key, true).unwrap()), 
        vrfy_key:encode_upper(&ctx.serialize_pubkey(&vrfy_key, true).unwrap()) 
    };

    let client = thread::spawn(move || {
        let stdin = stdin();
        let mut recv_data = [0u8; 1024];
        thread::sleep(std::time::Duration::from_millis(1000));
        loop {
            let mut send_buff = String::new();
            let mut stream = TcpStream::connect(server_addr).unwrap();
            
            // 密钥协商
            let agree_info = serde_json::to_string(&info).expect("Failed to serde");
            println!("{}", agree_info);
            stream.write(agree_info.as_bytes()).expect("Failed to write on strem");
            stream.flush().expect("Failed to write on strem");

            let mut key_info = [0u8; 1024];
            let read_size = stream.read(&mut key_info).unwrap();
            let key_str = std::str::from_utf8(&key_info[..read_size]).unwrap();
            match serde_json::from_str::<Agreement>(key_str) {
                Ok(info) =>{
                    let (enc_key_server, vrfy_key_server) = info.parse();
                    println!("INFO: {:?}", info);

                    // 打印提示符
                    print!("🦀 ");
                    stdout().flush().unwrap();

                    // stdin 读取输入, 加密后传输到server
                    stdin.read_line(&mut send_buff).unwrap();

                    stream.write(send_buff.as_bytes()).unwrap();
                    stream.flush().unwrap();

                    // 阻塞，直到收到回复
                    let read_len = stream.read(&mut recv_data).unwrap();
                    println!(
                        "🐋 {}",
                        String::from_utf8_lossy(&recv_data[0..read_len])
                    );
                },
                Err(e) =>{eprint!("Failed to parse: {}", e.to_string())}
            }
        }
    });

    server.join().unwrap();
    client.join().unwrap();
    Ok(())
}
