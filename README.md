# FreeCloak
A FOSS File Encryption Utility

## About
FreeCloak is a simple, Free and Open Source encryption utility written in rust. It encrypts files by using a SHA256 hash of a provided password as an AES256-GCM key. It is cross platform and was designed to be easy to use.
### ⚠️WARNING⚠️
While this tool uses AES256-GCM encryption, and cryptographically secure random numbers, it has not been professionally audited for security. **USE WITH CAUTION**

## Roadmap/ToDo
<ul>
  <li>Add the ability to encrypt/decrypt multiple files at once</li>
  <li>Make files automatically delete after five failed decryption attempts</li>
  <li>Allow users to change file passwords without using the recover command</li>
</ul>

## Usage
To run the program, clone this repo and use the `cargo build` or `cargo run` command. This will also create a standalone executable at the path `target/debug/cloak` (`cloak.exe` on Windows systems)
### Commands:
<dl>
  <dt>help</dt>
  <dd>Displays the help dialogue.</dd>
  <dt>encrypt [infile] [outfile OPTIONAL]</dt>
  <dd>Prompts the user to create a password and encrypts the infile with it, if an outfile is provided, the ciphertext will be saved there, otherwise, the infile will be overwritten with the ciphertext<br><b>Example:</b><br><code>cloak encrypt secrets.txt</code> will encrypt <code>secrets.txt</code> in place.</dd>
  <dt>decrypt [infile] [outfile OPTIONAL]</dt>
  <dd>Prompts the user for a password and attmpts to decrypt the infile with it, if an outfile is provided, the plaintext will be saved there, otherwise, the infile will be overwritten with the plaintext<br><b>Example:</b><br><code>cloak decrypt secrets.txt plaintext.txt</code> will decrypt <code>secrets.txt</code> and save the plaintext to <code>plaintext.txt</code>.</dd>
  <dt>export-key [infile] [key-file]</dt>
  <dd>
    Exports the raw encryption key for infile to the provided key file path. This is done to give the user a an option to recover their data if they forget the password to a file, however, it is of the utmost importance to store the key securely as it's stored in the key file as plaintext.<br><b>Example:</b><br><code>cloak export-key secrets.txt secret_key</code>
  </dd>
  <dt>recover [infile] [key file]</dt>
  <dd>Attempts to recover a file by using a key file created with <code>export-key</code>, and prompts the user to set a new password to encrypt the file with. This command is the only method of data recovery in the event a user forgets their password, as such it may be advisable to create a key backup after intially encrypting a file.<br><b>Example:</b><br><code>cloak recover secrets.txt secretkey</code> will try to recover the
      contents of <code>secrets.txt</code> with the key contained in the file <code>secretkey</code> and allow the user to set a new password for the file.<br><b>Note:</b><br>Because changing a file's password generates an entirely new key, the existing keyfile will no longer work, and the key will need to be re-exported. 
  </dd>
</dl>
