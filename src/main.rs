use std::{env::args, fs, io::{stdin, stdout, Write}, path, process::exit};
use rpassword::read_password;

use crate::cryptoutils::crypto_utils;

pub mod cryptoutils;

// prints the help text
fn print_help(){
    let commands = [("encrypt", "[file(s)]", "Encrypts the provided file(s) with in place with a provided password"), 
                    ("decrypt", "[file(s)]", "Decrypts the provided file(s) with in place with a provided password"), 
                    ("export-key", "[infile] [key file]", "Exports the raw encryption key for infile to the provided key file. USE WITH CAUTION!"),
                    ("recover", "[infile] [key file]", "Recovers the encrypted infile with the key stored in the key file, and re-encrypts it with a new password"),
                    ("reset-pw", "[infile]", "Changes the password of an encrypted file"),
                    ("help", "", "Displays the help dialogue")
                   ];
    println!("Available Commands:\n\t{0:15}{1:30}{2}", "Command:", "Arguments:", "Description:");
    for i in commands{
        println!("\t{0:15}{1:30}{2}", i.0, i.1, i.2);
    }
}

// returns the name of the file to read from and write to, given the arg list 
fn get_filenames(args_list: &Vec<String>) -> Result<Vec<String>, std::io::Error>{
    let mut paths: Vec<String> = Vec::new();
    for i in &args_list[2..]{
        if path::Path::new(i).is_file(){
            paths.push(i.to_string());
        }
        else{
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("The file path \"{}\" is invalid", i.as_str())));
        }
    }
    Ok(paths)
}


// prints a prompt and recieves a password from the command line 
fn get_password(prompt: &str) -> String{
    print!("{}: ", prompt);
    stdout().flush().unwrap();
    read_password().unwrap()
}

fn main() {
    let args_list: Vec<String> = args().collect();
    // validate the length of the provided arguments
    if args_list.len() < 2{
        println!("This program takes at least one parameter");
        print_help();
        exit(0);
    }   
    // run the user's command
    match args_list[1].as_str(){
        "encrypt" => {
            // validate the count of arguments
            if args_list.len() < 3{
                println!("This command takes at least one parameter");
                exit(0)
            }
            // get the paths to read from and write to
            let paths: Vec<String>;
            match  get_filenames(&args_list){
                Ok(paths_vec) => {paths = paths_vec}
                Err(e) => {
                    println!("{}", e.to_string());
                    exit(0)
                
                }
            }
            // attempt to encrypt the file
            for i in paths{
                let password = get_password(format!("Set a password for {}", i).as_str()).to_string();
                let password_conf  = get_password("Confirm");
                if password != password_conf{
                    println!("Password does match confirmation");
                    exit(0)
                }
                match crypto_utils::encrypt_file(&password, &i, &i){
                    Ok(_) => {println!("\"{}\" was encrypted successfully", i, password)}
                    Err(e) => {println!("Failed to encrypt {} - {}", i, e.to_string())}
                }
            }
        }
        "decrypt" => {
            // get the paths to read from and write to
            let paths: Vec<String>;
            match  get_filenames(&args_list){
                Ok(paths_vec) => {paths = paths_vec}
                Err(e) => {
                    println!("{}", e.to_string());
                    exit(0)
                }
            }
            // give user five attempts to decrypt the data
      
                for i in &paths{
                    let mut tries = 5;
                    while tries > 0{
                        let password = get_password(&format!("File Password for {}", i));
                        // attempt to decrypt the file
                        match crypto_utils::decrypt_file(&password, &i, &i){
                            Ok(_) => {
                                tries = 0; // end the lopp
                                println!("{} decrypted successfully", i)
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::InvalidInput{
                                    tries -= 1;
                                    if tries > 1{
                                        println!("{}\n{} attempts remaining", e.to_string(), tries);
                                    }
                                    else{
                                        match tries{
                                            1 => {println!("{}\n1 attempt remaining!\nWARNING: IF YOU INPUT AN INCORRECT PASSWORD AGAIN, THE FILE WILL BE DESTROYED", e.to_string())}
                                            0 => {
                                                fs::remove_file(i).expect("Failed to delete the file");
                                                println!("File erased!")
                                            }
                                            _ => {} // tries will never be anything other than one or zero. This is here to stop the complier from complaining
                                        }
                                    }
                                }
                                else{
                                    println!("{}", e.to_string());
                                }
                        }
                    }
                }
            }            
        }
        "export-key" => {
            // validate the count of arguments
            if args_list.len() != 4{
                println!("This command takes exactly two parameters");
                exit(0)
            }
            // ensure the user is sure they want to export the file's key
            println!("This will store the encryption key for \"{}\" to \"{}\".\nIT IS HIGHLY IMPORTANT TO STORE THIS KEY SECURELY! Are you sure you'd like to export the key? (y/n)", args_list[2], args_list[3]);
            let mut response: String = String::new();
            stdin().read_line(&mut response).expect("Failed to read the response");
            if response.trim().to_lowercase() != "y".to_string(){
                exit(0)
            }
            let password = get_password("File Password");
            // attempt to run the opperation
            match crypto_utils::export_key(&password, &args_list[2], &args_list[3]){
                Ok(_) => {println!("Key was exported succesfully")}
                Err(e) => {println!("{}", e.to_string())}
            }
        }
        "recover" => {
            // validate the count of arguments
            if args_list.len() != 4{
                println!("This command takes exactly two parameters");
                exit(0)
            }
            let password = get_password("Set a new password for the file");
            let password_conf = get_password("Confirm");
            if password != password_conf{
                println!("Password does not match confirmation");
                exit(0);
            }
            // attempt to recover the file
            match crypto_utils::recover_file(&args_list[2], &args_list[3], &password){
                Ok(_) => {println!("Success! The file has been recovered and re-encrypted with your new password.")}
                Err(e) => {println!("{}", e)}
            }
        }
        "reset-pw" => {
            // validate the count of arguments
            if args_list.len() != 3{
                println!("This command takes exactly one parameter");
                exit(0)
            }
            let mut tries = 5;
            let new_password = get_password("New file password");
            let conf = get_password("Confirm new password");
            if new_password != conf{
                println!("New password does match confirmation");
                exit(0)
            }
            while tries > 0{
                let password = get_password("Current file password");
                // attempt to update the password
                match crypto_utils::change_password(&password, &new_password, &args_list[2]){
                    Ok(_) => {println!("File password changed successfully")}
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::InvalidInput{
                            tries -= 1;
                            if tries > 1{
                                println!("{}\n{} attempts remaining", e.to_string(), tries);
                            }
                            else{
                                match tries{
                                    1 => {println!("{}\n1 attempt remaining!\nWARNING: IF YOU INPUT AN INCORRECT PASSWORD AGAIN, THE FILE WILL BE DESTROYED", e.to_string())}
                                    0 => {
                                        fs::remove_file(&args_list[2]).expect("Failed to delete the file");
                                        println!("File erased!")
                                    }
                                    _ => {} // tries will never be anything other than one or zero. This is here to stop the complier from complaining
                                }
                            }
                        }
                        else{
                            println!("{}", e.to_string());
                            exit(0)
                        }
                    }
                }
            }
        }
        "help" => {print_help()}
        _ => {
            println!("Unrecognized command: {}", args_list[1]);
            print_help()
        }
    }
}

