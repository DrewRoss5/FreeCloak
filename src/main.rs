use std::{env::args, io::{stdout, Write}, path::Path, process::exit};
use rpassword::read_password;

pub mod cryptoutils;

// prints the help text
fn print_help(){
    let commands = [("encrypt", "[infile] [outfile OPTIONAL]", "Encrypts the infile with a password and saves the ciphertext to the outfile, if no outfile is provided, infile will be encrypted in place"), 
                                             ("decrypt", "[infile] [outfile OPTIONAL]", "Decrypts the infile with a provided password, and saves the plaintext to the outfile, if no outfile is provided, the infile will decrypted in place"), 
                                             ("help", "", "Displays the help dialogue")];
    println!("Available Commands:\n\t{0:10}{1:30}{2}", "Command:", "Arguments:", "Description:");
    for i in commands{
        println!("\t{0:10}{1:30}{2}", i.0, i.1, i.2);
    }
}

// returns the name of the file to read from and write to, given the arg list 
fn get_filenames(args_list: &Vec<String>) -> (&String, &String){
    let file_path = &args_list[2];
    let new_path: &String;
    if args_list.len() == 3{
        new_path = file_path
    }
    else{
        new_path = &args_list[3]
    }
    // ensure the provided file exists
    if !Path::new(file_path).is_file(){
        println!("Error - No input file with the provided name");
        exit(0)
    }
    (file_path, new_path)
}
fn main() {
    let args_list: Vec<String> = args().collect();
    // validate the length of the provided arguments
    if args_list.len() < 2{
        println!("This program takes at least one argument");
        print_help();
        exit(0);
    }   
    // run the user's command
    match args_list[1].as_str(){
        "encrypt" => {
            // validate the count of arguments
            if args_list.len() < 3{
                println!("This command takes at least one paramater");
                exit(1)
            }
            // get the paths to read from and write to
            let paths = get_filenames(&args_list);
            // get the password
            print!("Set a file password: ");
            stdout().flush().unwrap();
            let password = read_password().unwrap();
            print!("Confirm: ");
            stdout().flush().unwrap();
            let password_conf = read_password().unwrap();
            if password != password_conf{
                println!("Password does match confirmation");
                exit(0)
            }
            // attempt to encrypt the file
            match cryptoutils::crypto_utils::encrypt_file(&password, paths.0, paths.1){
                Ok(_) => {println!("File encrypted successfully")}
                Err(e) => {println!("{}", e.to_string())}
            }
        }
        "decrypt" => {
            // validate the count of arguments
            if args_list.len() < 3{
                println!("This command takes at least one paramater");
                exit(1)
            }
            // get the paths to read from and write to
            let paths = get_filenames(&args_list);
            // get the password
            print!("File Password: ");
            stdout().flush().unwrap();
            let password = read_password().unwrap();
            // attempt to decrypt the file
            match cryptoutils::crypto_utils::decrypt_file(&password, paths.0, paths.1){
                Ok(_) => {println!("File decrypted successfully")}
                Err(e) => {println!("{}", e.to_string())}
            }
        }
        "help" => {print_help()}
        _ => {
            println!("Unrecognized command: {}", args_list[1]);
            print_help()
        }
    }
}
