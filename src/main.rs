use concrete_lib::*;
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use std::io::{BufRead, BufReader};
use std::time;
use serde::{Serialize, Deserialize};
use rand::*;
use core::ptr::null;
use itertools::Itertools;
use ndarray::Array;
use std::time::Duration;

// Message-code struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteMessageCode {
    code : i32
}

// Ciphertext message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteCiphertext {
    message : VectorLWE
}

// Secret Key message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteSecretKey {
    secret_key : LWESecretKey
}

// Key Switching message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteKSK {
    change_key : LWEKSK
}

fn create_and_save_keys(){
    println!("Generating keys...");
    // Create keys
    let my_public_key = LWESecretKey::new(&LWE128_1024);
    let my_private_key = LWESecretKey::new(&LWE128_1024);
    let my_change_key = crypto_api::LWEKSK::new(&my_public_key, &my_private_key, 9, 3);
    println!("Saving keys...");
    // Save keys
    my_public_key.save("my_public_key.json").unwrap();
    my_private_key.save("my_private_key.json").unwrap();
    my_change_key.save("my_change_key.json").unwrap();
    println!("Keys saved!");
}

fn load_secret_key() -> LWESecretKey{
    // Load from disk
    return LWESecretKey::load("my_private_key.json").unwrap();
}

fn load_key_switching_key() -> LWEKSK{
    // Load from disk
    return LWEKSK::load("my_change_key.json").unwrap();
}

fn load_public_key() -> LWESecretKey{
    // Load from disk
    return LWESecretKey::load("my_public_key.json").unwrap();
}

fn send_ciphertext(mut stream : &TcpStream, ciphertext : VectorLWE, code_in : i32){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : code_in
    };
    stream.write(serde_json::to_string(&msg_code).unwrap().as_bytes()).unwrap();
    stream.write(b"\n").unwrap(); // Necessary in order to Stop reading or receiving data from

    // Prepare and send ciphertext
    let ciphertext_msg = ConcreteCiphertext {
        message : ciphertext
    };
    stream.write(serde_json::to_string(&ciphertext_msg).unwrap().as_bytes()).unwrap();
    stream.write(b"\n").unwrap(); // Necessary in order to Stop reading or receiving data from
}

fn encode_and_encrypt_message(message : &Vec<f64>, public_key : &LWESecretKey) -> VectorLWE{
    // Generate encoder
    let encoder = Encoder::new(40., 120., 8, 0).unwrap();
    // Encrypt message
    let ciphertext = VectorLWE::encode_encrypt(public_key, message, &encoder).unwrap();
    return ciphertext;
}

fn generate_and_send_message(stream : &TcpStream, public_key : &LWESecretKey){
    let random_vector = generate_random_message();
    let ciphertext = encode_and_encrypt_message(&random_vector, public_key);
    send_ciphertext(stream, ciphertext, 0);
    println!("Message sent!");
}

fn generate_random_message() -> Vec<f64>{
    let mut rng = rand::thread_rng();
    let constants: Vec<f64> = (0..3).map(|_| rng.gen_range(40., 120.)).collect();
    return constants;
}

fn send_info_loop(stream : &TcpStream){
    let public_key = load_public_key();
    loop{
        generate_and_send_message(stream, &public_key);
        thread::sleep(Duration::from_millis(5000));
    }
}

fn sending_thread(){
    // Connect to server - Regular TCP connection
    match TcpStream::connect("127.0.0.1:3333") {
        Ok(stream) => {
            println!("Successfully connected to server!");
            send_info_loop(&stream);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}

fn receiving_thread(){
    let listener = TcpListener::bind("0.0.0.0:4444").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 4444");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection from: {}", stream.peer_addr().unwrap().ip().to_string());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
}

fn main() {
    // Create and save keys
    create_and_save_keys();

    // Create new thread
    thread::spawn(|| {
        sending_thread();
    });

    // Create new thread
    thread::spawn(|| {
        receiving_thread();
    });

}
