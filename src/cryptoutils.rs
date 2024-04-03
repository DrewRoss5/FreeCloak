pub mod crypto_utils{
    use std::{fs, io::ErrorKind, path};
    use aes_gcm::{aead::{rand_core::RngCore, Aead, OsRng}, AeadCore, Aes256Gcm, Key, KeyInit};
    use sha2::{Sha256, Digest};

    // constant sizes
    const KEY_SIZE: usize = 32;
    const SALT_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const HEADER_SIZE: usize = SALT_SIZE + NONCE_SIZE;

    // constant indexes 
    const SALT_POS: usize = 0;
    const NONCE_POS: usize = 1;
    const CIPHERTEXT_POS: usize = 2; 

    // validates and reads an encrypted file, returning the salt, nonce and ciphertext
    fn parse_encrypted_file(ciphertext_path: &String) -> Result<[Vec<u8>; 3], std::io::Error>{
        // ensure the provided file path exists 
        if !path::Path::new(ciphertext_path).is_file(){
            return Err(std::io::Error::new(ErrorKind::NotFound, "Input file not found"));
        }
        // read the file and verify it's the correct length
        let contents = fs::read(ciphertext_path)?;
        if contents.len() < HEADER_SIZE + 16{
            return Err(std::io::Error::new(ErrorKind::Other, "Invalid Input File"));
        }
        // parse the file into its components and return them
        Ok([contents[..SALT_SIZE].to_vec(), contents[SALT_SIZE..HEADER_SIZE].to_vec(), contents[HEADER_SIZE..].to_vec()])
    }

    // generates a key by hashing a password with a salt
    fn get_key(password: &String, salt: &Vec<u8>) -> Vec<u8>{
        // generate a key from the password and salt
        let mut key_hash = Sha256::new();
        key_hash.update(password);
        key_hash.update(salt);
        key_hash.finalize().to_vec()
    }

    // generates a securely random 256-bit key
    pub fn generate_key_file(key_path: &String) -> Result<(), std::io::Error>{
        let mut key_bytes: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut key_bytes);
        fs::write(key_path, key_bytes)
    }

    pub fn encrypt_file(password: &String, ciphertext_path: &String, plaintext_path: &String) -> Result<(), std::io::Error>{
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
        let contents = fs::read(plaintext_path)?;
        // encrypt the contents
        Aes256Gcm::generate_nonce(OsRng);
        let mut ciphertext: Vec<u8>;
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        match aes_cipher.encrypt(&nonce, contents.as_slice()){
            Ok(cipher) => {ciphertext = cipher}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to encrypt the file"))}
        }
        // create a vector for the new contents of the file
        let mut cipher_contents: Vec<u8> = Vec::new();
        cipher_contents.append(&mut salt.to_vec());
        cipher_contents.append(&mut nonce.to_vec());
        cipher_contents.append(&mut ciphertext);
        // write the encrypted contents
        fs::write(ciphertext_path, &cipher_contents)?;
        Ok(())
    }

    // encrypt a file with a key stored in a keyfile as opposed to with a password
    pub fn encrypt_with_key(plaintext_path: &String, ciphertext_path: &String, key_path: &String) -> Result<(), std::io::Error>{
        // load the plaintext
        let plaintext = fs::read(plaintext_path)?;
        // load and validate the key
        let key_bytes = fs::read(key_path)?;
        if key_bytes.len() != 32{
            return Err(std::io::Error::new(ErrorKind::InvalidInput, "Invalid Key File"))
        }
        // generate a nonce
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        // create a cipher and encrypt the plaintext
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        let mut ciphertext: Vec<u8>;
        match aes_cipher.encrypt(&nonce, plaintext.as_slice()){
            Ok(cipher) => {ciphertext = cipher}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to encrypt the file"))}
        }
        // generate random bytes to hold the place of a salt (this looks indistinguishable from a real salt to attackets)
        let mut salt_placeholder: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut salt_placeholder);
        // create a vector for the new contents of the file
        let mut cipher_contents: Vec<u8> = Vec::new();
        cipher_contents.append(&mut salt_placeholder.to_vec());
        cipher_contents.append(&mut nonce.to_vec());
        cipher_contents.append(&mut ciphertext);
        // save the ciphertext
        fs::write(ciphertext_path, cipher_contents)
    }   

    pub fn decrypt_file(password: &String, ciphertext_path: &String, plaintext_path: &String) -> Result<(), std::io::Error>{
        let contents = parse_encrypted_file(&ciphertext_path)?;
        // validate the provided password and get the key
        let key_bytes = get_key(password, &contents[SALT_POS]);
        // create the cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        // attempt to decrypt the file
        let plaintext: Vec<u8>;
        match aes_cipher.decrypt(contents[NONCE_POS].as_slice().into(), contents[CIPHERTEXT_POS].as_slice()){
            Ok(plain) => {plaintext = plain}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::InvalidInput, "Incorrect Password"))}
        }
        fs::write(plaintext_path, plaintext)
    }

    // decrypt a file with a key stored in a keyfile as opposed to with a password
    pub fn decrypt_with_key(ciphertext_path: &String, plaintext_path: &String, key_path: &String) -> Result<(), std::io::Error>{
        let contents = parse_encrypted_file(ciphertext_path)?;
        // load and validate the key
        let key_bytes = fs::read(key_path)?;
        if key_bytes.len() != 32{
            return Err(std::io::Error::new(ErrorKind::InvalidInput, "Invalid Key File"))
        }
        // create the cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key); 
        // attempt to decrypt the ciphertext
        let plaintext: Vec<u8>;
        match aes_cipher.decrypt(contents[NONCE_POS].as_slice().into(), contents[CIPHERTEXT_POS].as_slice()){
            Ok(plain) => {plaintext = plain}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::InvalidInput, "Incorrect Key File"))}
        }      
        fs::write(plaintext_path, plaintext)
    }

    // exports the key of a file to a predetermined path
    pub fn export_key(password: &String, ciphertext_path: &String, key_path: &String) -> Result<(), std::io::Error>{
        let contents = parse_encrypted_file(&ciphertext_path)?;
        let key_bytes = get_key(password, &contents[SALT_POS]);
        // create the cipher
        let aes_key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let aes_cipher = Aes256Gcm::new(aes_key);
        // ensure the key is valid by attempting to decrypt the ciphertext with it
        match aes_cipher.decrypt(contents[NONCE_POS].as_slice().into(), contents[CIPHERTEXT_POS].as_slice()){
            Ok(_) => {fs::write(key_path, key_bytes)?;}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::InvalidInput, "Invalid Password"))}
        }
        Ok(())
    }

    // recovers an encrypted file with the recovery key file, and re-encrypts it with a new password
    pub fn recover_file(ciphertext_path: &String, key_file: &String, new_password: &String) -> Result<(), std::io::Error>{
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
        let contents = parse_encrypted_file(ciphertext_path)?;
        let plaintext: Vec<u8>;
        match aes_cipher.decrypt(contents[NONCE_POS].as_slice().into(), contents[CIPHERTEXT_POS].as_slice()){
            Ok(plain) => {plaintext = plain}
            Err(_) => {return Err(std::io::Error::new(ErrorKind::Other, "Failed to recover the file..."))}
        }
        // write the plaintext to a temporary file 
        fs::write(tmp_path, plaintext)?;
        // re-encrypt the original file with a new password
        encrypt_file(&new_password, &tmp_path, ciphertext_path)?;
        // securely erase the tmp file by overwriting it with zeroes
        let plaintext_len = fs::read(tmp_path)?.len();
        fs::write(tmp_path,vec![0; plaintext_len + 1024])?;
        fs::remove_file(tmp_path)?;
        Ok(())
    }

    pub fn change_password(password: &String, new_password: &String, ciphertext_path: &String) -> Result<(), std::io::Error>{
        let tmp_path = &"tmp__".to_string();
        // attmept to decrypt the file and save the plaintext to a temp file
        decrypt_file(password, ciphertext_path, tmp_path)?;
        // re-encrypt the file with a new password
        encrypt_file(new_password, tmp_path, ciphertext_path)?;
        // securely erase the tmp file by overwriting it with zeroes
        let plaintext_len = fs::read(tmp_path)?.len();
        fs::write(tmp_path,vec![0; plaintext_len + 1024])?;
        fs::remove_file(tmp_path)?;
        Ok(())
    }
}
