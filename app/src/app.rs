// Contains all the background stuff 
use std::{self , fs::{File , self} , str};
use crate::cli;
use aes_gcm::{
    Aes256Gcm,
    Key,
    Nonce,
    aead::{Aead, KeyInit}
};
use argon2::Argon2 ;
use rand::Rng;

pub fn run(){
    println!("Welcome to aes-gcm encryptor");
    let _file = match File::open("Key.txt"){
        Ok(_file) => {
            runner(fs::read_to_string("Key.txt").expect("Failed to read file"));
        } ,
        Err(_) => {first_run();}
    };

}
pub fn first_run(){
    println!("It seems that this is your first run");
    println!("Please keep the password safe as it cannot be reset if the key.txt file is lost , all the files encrypted using it cannot be decrypted");
    println!("Please enter a password to generate a key");
    let password = cli::password_input();
    let salt : [u8; 16] = rand::rng().random();
    let salt = salt.to_vec();
    let key = key_gen(&password , &salt);  
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes: [u8; 12] = rand::rng().random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let test = cipher.encrypt(&nonce , "test".as_bytes().as_ref()).expect("Failed to encrypt");

    let encrypted = format!(
        "{}:{}:{}" ,
        hex::encode(&test),
        hex::encode(&salt) ,
        hex::encode(&nonce)
    );
    File::create("Key.txt").expect("Failed to create key");
    let _ = fs::write("Key.txt" , encrypted);

}
pub fn key_gen(password : &str , salt : &Vec<u8>) -> Key<Aes256Gcm>{
    let argon2 = Argon2::default();
    let mut key = [0u8 ; 32];
    let _ = argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut key
    );
    Key::<Aes256Gcm>::from_slice(&key).clone()    
}

pub fn runner(file : String){
    let password = cli::password_input();
    let file : Vec<&str> = file.split(":").collect();
    if file.len() != 3 {
        panic!("Invalid key file shutting down program");
    }
    let test = hex::decode(file[0]).expect("Failed to decode test");
    let salt = hex::decode(file[1]).expect("Failed to decode salt");
    let nonce = hex::decode(file[2]).expect("Failed to decode nonce");
    let key = key_gen(&password , &salt);
    let cipher = Aes256Gcm::new(&key);
    let password_test = cipher.decrypt(Nonce::from_slice(&nonce) , test.as_ref());
    if password_test.is_err() {
        panic!("Incorrect password shutting down program");
    }
    loop{
        let option = cli::option_input();
        let option = option.trim();
        match option {
            "1" => {note_creation(cipher.clone());},
            "2" => {note_open(&password , &salt);},
            "3" => {file_encryption(cipher.clone());},
            "4" => {break;}
            &_ => {println!("Invalid option");}
        }
    }
}
pub fn note_creation(cipher : Aes256Gcm){
    let note_name = cli::note_name();
    let note = cli::note_input();
    let nonce : [u8 ; 12] = rand::rng().random();
    let nonce = Nonce::from_slice(&nonce);
    File::create(&note_name).expect("Failed to create note file");
    let cyphertext = cipher.encrypt(&nonce , note.as_bytes().as_ref()).expect("Failed to encrypt");
    let encrypted = format!("{}:{}" , hex::encode(cyphertext) , hex::encode(nonce));
    fs::write(&note_name , encrypted).expect("Failed to write note");
}
pub fn note_open(password : &str , salt : &Vec<u8> ){
    let key = key_gen(password , salt);
    let cipher = Aes256Gcm::new(&key);
    let note_name = cli::note_name();
    let file = fs::read_to_string(&note_name).expect("Failed to read note");
    let file : Vec<&str> = file.split(":").collect();
    if file.len() != 2 {
        panic!("Invalid note file shutting down program ")
    }
    let cyphertext = hex::decode(file[0]).expect("Failed to decode cyphertext");
    let nonce = hex::decode(file[1]).expect("Failed to decode nonce");
    let decrypted_data =  cipher.decrypt(Nonce::from_slice(&nonce) , cyphertext.as_ref()).expect("Failed to decrypt");
    println!("{}" , String::from_utf8(decrypted_data).expect("Failed to convert to string"))
    
}
pub fn file_encryption(cipher : Aes256Gcm){
    let nonce : [u8 ; 12] = rand::rng().random();
    let nonce = Nonce::from_slice(&nonce);
    let file_path = cli::note_name();
    let target = cli::note_name();
    let file = fs::read_to_string(file_path).expect("Failed to read file");
    let cyphertext = cipher.encrypt(&nonce , file.as_bytes().as_ref()).expect("Failed to encrypt");
    let encrypted = format!("{}:{}" , hex::encode(cyphertext) , hex::encode(nonce));
    let _ = File::create(&target).expect("Failed to create target file");
    fs::write(&target , encrypted).expect("Failed to write file");
}