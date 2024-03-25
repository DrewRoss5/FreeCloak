pub mod crypto_utils{
    use std::{fs, io::ErrorKind, path};
    use aes_gcm::{aead::{rand_core::RngCore, Aead, OsRng}, AeadCore, Aes256Gcm, Key, KeyInit};
    use sha2::{Sha256, Digest};

    // constant sizes
    const HASH_SIZE: usize = 32;
    const SALT_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const HEADER_SIZE: usize = SALT_SIZE + HASH_SIZE + NONCE_SIZE;

    // validates a password given a key checksum and returns the key if the password is correct, otherwise returns an error
    fn get_key(password: &String, salt: &[u8], checksum: &[u8]) ->  Result<Vec<u8>, std::io::Error>{
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
        let contents = fs::read(file_path)?;
        // seperate the file into its components
        let salt = &contents[..SALT_SIZE];
        let checksum = &contents[SALT_SIZE..HASH_SIZE+SALT_SIZE];
        let nonce = &contents[SALT_SIZE+HASH_SIZE..HEADER_SIZE];
        let ciphertext = &contents[HEADER_SIZE..];
        // validate the provided password and get the key
        let key_bytes = get_key(password, salt, checksum)?;
        // create the cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        // attempt to decrypt the file
        let plaintext: Vec<u8>;
        match aes_cipher.decrypt(nonce.into(), ciphertext){
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
        // read the file's key checksum and salt (the nonce is irrelevant for this function)
        let contents = fs::read(file_path)?;
        let salt = &contents[..SALT_SIZE];
        let checksum = &contents[SALT_SIZE..HASH_SIZE+SALT_SIZE];
        // validate the password and write the key to the file if its valid
        let key_bytes = get_key(password, salt, checksum)?;
        fs::write(key_path, key_bytes)?;
        Ok(())
    }
}