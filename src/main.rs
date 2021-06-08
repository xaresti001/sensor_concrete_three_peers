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

fn send_secret_key(mut stream : &TcpStream){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : 4 // VERIFY THIS CODE
    };
    stream.write(serde_json::to_string(&msg_code).unwrap().as_bytes()).unwrap();
    stream.write(b"\n").unwrap(); // Necessary in order to Stop reading or receiving data from

    // Prepare and send Secret Key
    let secret_key_msg = ConcreteSecretKey{
        secret_key : load_secret_key()
    };
    stream.write(serde_json::to_string(&secret_key_msg).unwrap().as_bytes()).unwrap();
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
    println!("Sending thread terminated.");
}

fn receive_ciphertext(stream : &TcpStream) -> VectorLWE{
    // RECEIVING MODULE
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    buffer.clear();
    let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

    if read_bytes == 0 { // If there is no incoming data
        return VectorLWE::zero(0, 0).unwrap();
    }

    // Deserialize
    let ciphertext : ConcreteCiphertext = serde_json::from_slice(&buffer).unwrap();

    // let stream : &TcpStream = reader.get_ref();
    // save_ciphertext(stream, &ciphertext.message);
    return ciphertext.message;
}

fn verify_ciphertext(ciphertext : VectorLWE) -> VectorLWE{
    // Load KSK
    let key_switching_key = load_key_switching_key();
    // Perform Key Switch
    let verified_ciphertext = ciphertext.keyswitch(&key_switching_key).unwrap();
    return verified_ciphertext;
}

fn received_code_3(stream : &TcpStream){
    println!("\n\n// SECRET KEY REQUEST //");
    // Load and send Secret Key (SK2)
    println!("Loading secret key...");
    send_secret_key(stream);
    println!("Secret key sent!");
}

fn received_code_5(stream : &TcpStream){
    println!("\n\n// CIPHERTEXT VERIFICATION //");
    // Verify received ciphertext
    // Receive ciphertext
    println!("Receiving ciphertext...");
    let ciphertext = receive_ciphertext(stream);
    // Verify ciphertext
    println!("Verifying ciphertext...");
    let verified_ciphertext = verify_ciphertext(ciphertext);
    // Send verified ciphertext
    println!("Sending verified ciphertext...");
    send_ciphertext(stream, verified_ciphertext, 6);
    println!("Verified ciphertext sent!");
}

fn handle_client(stream: TcpStream){
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    loop{
        buffer.clear(); // Flush remaining buffer content
        println!("\n\nWaiting client message...");
        let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

        if read_bytes == 0 { // If there is no incoming data
            return ();
        }

        let msg_code : ConcreteMessageCode = serde_json::from_slice(&buffer).unwrap();
        println!("Received message-code: {:?}", msg_code.code);

        let stream_ref = reader.get_ref();

        match msg_code.code {
            3 => received_code_3(stream_ref),
            5 => received_code_5(stream_ref),
            _ => println!("Incorrect code received!!"),
        }
    }
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
    let handler1 = thread::spawn(move || {
        sending_thread();
    });

    // Create new thread
    let handler2 = thread::spawn(move || {
        receiving_thread();
    });

    handler1.join().unwrap();
    handler2.join().unwrap();
}
