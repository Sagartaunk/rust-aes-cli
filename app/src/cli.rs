// Handles the Cli interface of the app
use std::io;
use rpassword::read_password;
pub fn password_input() -> String{
    println!("Enter your password :");
    let password = read_password().expect("Unable to read password");
    let password = password.trim().to_string();
    password
}
pub fn note_input() -> String{
    println!("Enter text that you want to encrypt :");
    let mut note = String::new();
    io::stdin().read_line(&mut note).expect("Failed to read note");
    note
}
pub fn option_input() -> String{
    let mut option = String::new();
    println!("Please choose one of the following options : ");
    println!("1. Encrypt a String");
    println!("2. Decrypt a File");
    println!("3. Encrypt a file");
    println!("4. Exit");
    io::stdin().read_line(&mut option).expect("Failed to read input");
    option.trim().to_string()
}
pub fn note_name() -> String {
    println!("Enter the name of the file : ");
    let mut name = String::new();
    io::stdin().read_line(&mut name).expect("Failed to read input");
    let name = name.trim().to_string();
    name
}
