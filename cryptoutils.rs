pub mod crypto_utils{
    use std::{fs, io::ErrorKind, path};
    use aes_gcm::{aead::{rand_core::RngCore, Aead, OsRng}, AeadCore, Aes256Gcm, Key, KeyInit};
    use sha2::{Sha256, Digest};

    // constant sizes
    const HASH_SIZE: usize = 32;
    const KEY_SIZE: usize = 32;
    const SALT_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const HEADER_SIZE: usize = SALT_SIZE + HASH_SIZE + NONCE_SIZE;

    // constant indexes 
    const SALT_POS: usize = 0;
    const CHECKSUM_POS: usize = 1;
    const NONCE_POS: usize = 2;
    const CIPHERTEXT_POS: usize = 3; 

    // validates and reads an encrypted file, returning the salt, checksum, nonce and ciphertext
    fn parse_encrypted_file(file_path: &String) -> Result<[Vec<u8>; 4], std::io::Error>{
        // ensure the provided file path exists 
        if !path::Path::new(file_path).is_file(){
            return Err(std::io::Error::new(ErrorKind::NotFound, "Input file not found"));
        }
        // read the file and verify it's the correct length
        let contents = fs::read(file_path)?;
        if contents.len() < HEADER_SIZE + 1{
            return Err(std::io::Error::new(ErrorKind::Other, "Invalid Input File"));
        }
        // parse the file into its components and return them
        Ok([contents[..SALT_SIZE].to_vec(), contents[SALT_SIZE..SALT_SIZE+HASH_SIZE].to_vec(), contents[SALT_SIZE+HASH_SIZE..HEADER_SIZE].to_vec(), contents[HEADER_SIZE..].to_vec()])
        
    }

    // validates a password given a key checksum and returns the key if the password is correct, otherwise returns an error
    fn get_key(password: &String, salt: &Vec<u8>, checksum: &Vec<u8>) ->  Result<Vec<u8>, std::io::Error>{
        // generate a key from the password and salt
        let mut key_hash = Sha256::new();
        key_hash.update(password);
        key_hash.update(salt);
        let key_bytes = key_hash.finalize().to_vec();
        // create a hash to check against from that key
        let mut checksum_hash = Sha256::new();
        checksum_hash.update(&key_bytes);
        // validate the checksum
        if checksum_hash.finalize().as_slice() != checksum{
            Err(std::io::Error::new(ErrorKind::InvalidInput, "Incorrect Password"))
        }
        else{
            Ok(key_bytes)
        }
    }

    pub fn encrypt_file(password: &String, file_path: &String, new_path: &String) -> Result<(), std::io::Error>{
        // generate a random salt
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        // create a key from the salt and password
        let mut key_hash: Sha256 = Sha256::new();
        key_hash.update(password.clone());
        key_hash.update(&salt);
        let key_bytes = key_hash.finalize().to_vec();
        // create the cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        // read the file
        let contents = fs::read(file_path)?;
        // encrypt the contents
        Aes256Gcm::generate_nonce(OsRng);
        let mut ciphertext: Vec<u8>;
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        match aes_cipher.encrypt(&nonce, contents.as_slice()){
            Ok(cipher) => {ciphertext = cipher}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to encrypt the file"))}
        }
        // create a hash of the key
        let mut checksum = Sha256::new();
        checksum.update(key_bytes);
        // create a vector for the new contents of the file
        let mut cipher_contents: Vec<u8> = Vec::new();
        cipher_contents.append(&mut salt.to_vec());
        cipher_contents.append(&mut checksum.finalize().to_vec());
        cipher_contents.append(&mut nonce.to_vec());
        cipher_contents.append(&mut ciphertext);
        // write the encrypted contents
        fs::write(new_path, &cipher_contents)?;
        Ok(())
    }

    pub fn decrypt_file(password: &String, file_path: &String, new_path: &String) -> Result<(), std::io::Error>{
        let contents = parse_encrypted_file(&file_path)?;
        // validate the provided password and get the key
        let key_bytes = get_key(password, &contents[SALT_POS], &contents[CHECKSUM_POS])?;
        // create the cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        // attempt to decrypt the file
        let plaintext: Vec<u8>;
        match aes_cipher.decrypt(contents[NONCE_POS].as_slice().into(), contents[CIPHERTEXT_POS].as_slice()){
            Ok(plain) => {plaintext = plain}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to decrypt ciphertext"))}
        }
        fs::write(new_path, plaintext)?;
        Ok(())
    }

    // exports the key of a file to a predetermined path
    pub fn export_key(password: &String, file_path: &String, key_path: &String) -> Result<(), std::io::Error>{
        // ensure the file path exists
        if !path::Path::new(file_path).is_file(){
            return Err(std::io::Error::new(ErrorKind::InvalidInput, "Invalid file path"))
        }
        let contents = parse_encrypted_file(&file_path)?;
        // validate the password and write the key to the file if its valid
        let key_bytes = get_key(password, &contents[SALT_POS], &contents[CHECKSUM_POS])?;
        fs::write(key_path, key_bytes)?;
        Ok(())
    }

    // recovers an encrypted file with the recovery key file, and re-encrypts it with a new password
    pub fn recover_file(infile: &String, key_file: &String, new_password: &String) -> Result<(), std::io::Error>{
        let tmp_path = &"tmp__".to_string();
        // load the key file
        let key_bytes: Vec<u8>;
        match fs::read(key_file) {
            Ok(key) => {key_bytes = key}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to read the key file"))}
        }
        // validate the size of the key
        if key_bytes.len() != KEY_SIZE{
            return Err(std::io::Error::new(ErrorKind::InvalidData, "The key file is invalid"))
        }
        // create an AES cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        // read the file
        let contents = parse_encrypted_file(infile)?;
        let plaintext: Vec<u8>;
        match aes_cipher.decrypt(contents[NONCE_POS].as_slice().into(), contents[CIPHERTEXT_POS].as_slice()){
            Ok(plain) => {plaintext = plain}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to recover the file..."))}
        }
        // write the plaintext to a temporary file 
        fs::write(tmp_path, plaintext)?;
        // re-encrypt the original file with a new password
        encrypt_file(&new_password, &tmp_path, infile)?;
        // securely erase the tmp file by overwriting it with zeroes
        let plaintext_len = fs::read(tmp_path)?.len();
        fs::write(tmp_path,vec![0; plaintext_len + 1024])?;
        fs::remove_file(tmp_path)?;
        Ok(())
    }

    pub fn change_password(password: &String, new_password: &String, infile: &String) -> Result<(), std::io::Error>{
        let tmp_path = &"tmp__".to_string();
        // attmept to decrypt the file and save the plaintext to a temp file
        decrypt_file(password, infile, tmp_path)?;
        // re-encrypt the file with a new password
        encrypt_file(new_password, tmp_path, infile)?;
        // securely erase the tmp file by overwriting it with zeroes
        let plaintext_len = fs::read(tmp_path)?.len();
        fs::write(tmp_path,vec![0; plaintext_len + 1024])?;
        fs::remove_file(tmp_path)?;
        Ok(())

    }
}
