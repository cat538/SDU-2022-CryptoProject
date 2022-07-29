use std::fs;
use std::io::prelude::*;
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use hex::{encode_upper,decode};
use libsm::sm2::signature::{Pubkey, Seckey, SigCtx};
use serde::{Serialize,Deserialize};
use serde_json;
// use lazy_static::*;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Sender<Message>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

enum Message {
    NewJob(Job),
    Terminate,
}

impl ThreadPool {
    /// Create a new ThreadPool.
    ///
    /// The size is the number of threads in the pool.
    /// # Panics
    /// The `new` function will panic if the size is zero.
    pub fn new(size: usize) -> ThreadPool {
        assert!(size > 0);
        let (sender, receiver) = channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }
        ThreadPool { workers, sender }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.send(Message::NewJob(job)).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        println!("Sending terminate message to all workers.");

        for _ in &self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }

        println!("Shutting down all workers.");

        for worker in &mut self.workers {
            println!("Shutting down worker {}", worker.id);

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    /// receiver 接收传入worker线程的闭包job或终止信息
    fn new(id: usize, receiver: Arc<Mutex<Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv().unwrap();
            match message {
                Message::NewJob(job) => {
                    // eprintln!("[server]: Worker {} got a job; executing.", id);
                    job();
                }
                Message::Terminate => {
                    // eprintln!("[server]: Worker {} was told to terminate.", id);
                    break;
                }
            }
        });
        Worker {
            id,
            thread: Some(thread),
        }
    }
}

pub fn handle_echo(mut stream: TcpStream) {
    let mut data = [0 as u8; 512];
    while match stream.read(&mut data) {
        Ok(size) => {
            stream.write(&data[0..size]).unwrap();
            true
        }
        Err(_) => {
            eprintln!(
                "An error occurred, terminating connection with {}",
                stream.peer_addr().unwrap()
            );
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

pub fn handle_http(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    let get = b"GET / HTTP/1.1\r\n";
    let sleep = b"GET /sleep HTTP/1.1\r\n";

    let (status_line, filename) = if buffer.starts_with(get) {
        ("HTTP/1.1 200 OK", "resp.html")
    } else if buffer.starts_with(sleep) {
        thread::sleep(Duration::from_secs(5));
        ("HTTP/1.1 200 OK", "resp.html")
    } else {
        ("HTTP/1.1 404 NOT FOUND", "404.html")
    };

    let contents = fs::read_to_string(filename).unwrap();

    let response = format!(
        "{}\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        contents.len(),
        contents
    );

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}

// 与此服务器交互的内容使用铭文传输
pub fn server_new(
    sock_addr: impl ToSocketAddrs,
    handle_client: Arc<dyn Fn(TcpStream) + Send + Sync>,
) {
    let listener = TcpListener::bind(sock_addr).unwrap();
    println!(
        "Server listening on port {}",
        listener.local_addr().unwrap().port()
    );
    let pool = ThreadPool::new(4);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // println!("[server]: New connection: {}", stream.peer_addr().unwrap());
                let call_back = Arc::clone(&handle_client);
                pool.execute(move || call_back(stream));
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    println!("Shutting down!");
}

pub const HEADER: &str = "KEY_AGREEMENT";

#[derive(Serialize, Deserialize, Debug)]
pub struct Agreement<'a> {
    pub header: &'a str,
    pub enc_key: String,
    pub vrfy_key: String
}

impl<'a> Agreement<'a>{
    pub fn parse(&self) -> (Pubkey, Pubkey){
        let ctx = SigCtx::new();

        let enc_key_client = decode(&self.enc_key).unwrap();
        let enc_key_client = ctx.load_pubkey(&enc_key_client).unwrap();

        let vrfy_key_client = decode(&self.vrfy_key).unwrap();
        let vrfy_key_client = ctx.load_pubkey(&vrfy_key_client).unwrap();
        (enc_key_client,vrfy_key_client)
    }
}
/// 与此服务器交互的每条消息均被sm2签名，加密
///
/// FIRST MESSAGE:
/// ```
/// HEADER
/// <SENDER'S ENC_KEY>
/// <SENDER'S VRFY_KEY>
/// ```
///
/// RESPONSE MESSAGE:
/// ```
/// HEADER
/// <RECIEVER'S ENC_KEY>
/// <RECIEVER'S VRFY_KEY>
/// ```
pub fn sm2_server(
    sock_addr: impl ToSocketAddrs,
    handle_client: Arc<dyn Fn(TcpStream) + Send + Sync>,
) {
    use libsm::sm2::encrypt::{DecryptCtx, EncryptCtx};
    use libsm::sm2::signature::{Pubkey, Seckey, SigCtx, Signature};

    let ctx = SigCtx::new();

    let (vrfy_key, sign_key) = ctx.new_keypair().unwrap();
    let (enc_key, dec_key) = ctx.new_keypair().unwrap();

    let listener = TcpListener::bind(sock_addr).unwrap();
    println!(
        "Server listening on port {}",
        listener.local_addr().unwrap().port()
    );
    let pool = ThreadPool::new(4);

    println!("{}\n{}\n{}", 
        "SERVER KEY:", 
        encode_upper(&ctx.serialize_pubkey(&enc_key, true).unwrap()), 
        encode_upper(&ctx.serialize_pubkey(&vrfy_key, true).unwrap())
    );
    
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // println!("[server]: New connection: {}", stream.peer_addr().unwrap());
                let mut buff = [0u8; 1024];
                let read_size = stream.read(&mut buff).unwrap();
                let first_str = std::str::from_utf8(&buff[..read_size]).unwrap();
                match serde_json::from_str::<Agreement>(first_str) {
                    Ok(info) =>{
                        // 1. 读取对方的公钥
                        let (enc_key_client, vrfy_key_client) = info.parse();

                        // 2. 回复自己的公钥
                        let info = Agreement { 
                            header: HEADER, 
                            enc_key:encode_upper(&ctx.serialize_pubkey(&enc_key, true).unwrap()), 
                            vrfy_key:encode_upper(&ctx.serialize_pubkey(&vrfy_key, true).unwrap()) 
                        };
                        let resp = serde_json::to_string(&info).unwrap();
                        stream.write(resp.as_bytes()).unwrap();
                        
                        // 阻塞，直到收到message
                        let recv_len = stream.read(&mut buff).unwrap();

                        let echo_msg = &buff[0..recv_len];
                        stream.write(echo_msg).unwrap();
                        
                        // let call_back = Arc::clone(&handle_client);
                        // pool.execute(move || call_back(stream));
                    },
                    Err(e) => {eprint!("Failed to parse: {}", e.to_string())}
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    println!("Shutting down!");

    // let signature = ctx.sign(msg, &sign_key, &vrfy_key).unwrap();
    // let result: bool = ctx.verify(msg, &vrfy_key, &signature).unwrap();

    // // 2. 加密
    // let klen = msg.len();

    // let encrypt_ctx = EncryptCtx::new(klen, enc_key);
    // let cipher = encrypt_ctx.encrypt(msg).unwrap();

    // let decrypt_ctx = DecryptCtx::new(klen, dec_key);
    // let plain_recover = decrypt_ctx.decrypt(&cipher).unwrap();
    // println!("cipher: {:?}", String::from_utf8_lossy(&cipher));
    // println!("plain:  {:?}", String::from_utf8(plain_recover).unwrap());
}
