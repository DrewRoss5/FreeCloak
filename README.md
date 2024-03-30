# FreeCloak
A FOSS File Encryption Utility

## About
FreeCloak is a simple, Free and Open Source encryption utility written in rust. It encrypts files by using a SHA256 hash of a provided password as an AES256-GCM key. It is cross platform and was designed to be easy to use.
### ⚠️WARNING⚠️
While this tool uses AES256-GCM encryption, and cryptographically secure random numbers, it has not been professionally audited for security. **USE WITH CAUTION**

## Usage
To run the program, clone this repo and use the `cargo build` or `cargo run` command. This will also create a standalone executable at the path `target/debug/cloak` (`cloak.exe` on Windows systems)
### Commands:
<dl>
  <dt>help</dt>
  <dd>Displays the help dialogue.</dd>
  <dt>encrypt [infile]]</dt>
  <dd>Encrypts the provided file(s) in place with user-provided password(s).</dd>
  <dt>decrypt [infile]</dt>
  <dd>Decrypts the provided file(s) in place with user-provided password(s).</dd>
  <dt>export-key [infile] [key-file]</dt>
  <dd>
    Exports the raw encryption key for infile to the provided key file path. This is done to give the user a an option to recover their data if they forget the password to a file, however, it is of the utmost importance to store the key securely as it's stored in the key file as plaintext.<br><b>Example:</b><br><code>cloak export-key secrets.txt secret_key</code>
  </dd>
  <dt>recover [infile] [key file]</dt>
  <dd>Attempts to recover a file by using a key file created with <code>export-key</code>, and prompts the user to set a new password to encrypt the file with. This command is the only method of data recovery in the event a user forgets their password, as such it may be advisable to create a key backup after intially encrypting a file.<br><b>Example:</b><br><code>cloak recover secrets.txt secretkey</code> will try to recover the
      contents of <code>secrets.txt</code> with the key contained in the file <code>secretkey</code> and allow the user to set a new password for the file.<br><b>Note:</b><br>Because changing a file's password generates an entirely new key, the existing keyfile will no longer work, and the key will need to be re-exported. 
  </dd>
  <dt>reset-pw [infile]</dt>
  <dd>Changes the password of the encrypted infile. This differs from the recover command, as it doesn't use a key file, and requires to user to know a file's password.</dd>
</dl>
