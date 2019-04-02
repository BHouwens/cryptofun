use utils::primes;
use rand::{ Rng, OsRng };
use crypto::aes_gcm::AesGcm;
use crypto::{ aes, symmetriccipher };
use crypto::aead::{ AeadEncryptor, AeadDecryptor };
use crypto::symmetriccipher::{ Encryptor, Decryptor };
use crypto::buffer::{ RefWriteBuffer, RefReadBuffer, WriteBuffer, ReadBuffer, BufferResult };

/**
 * AAD is an identifier value and is used in GCM mode only, thus
 * necessitating an Option type.
 * 
 * The "history_bytes" value is used to keep track of the number 
 * of bytes that have been encrypted with the current key. 
 */

pub struct AES {
    mode: AESMode,
    pub key: Vec<u8>,
    key_size: aes::KeySize,
    aad: Option<Vec<u8>>,
    pub initialization_vector: Vec<u8>,
    history_bytes: usize // number of bytes encrypted with one key
}

pub enum AESMode {
    Counter,
    GCM
}

/*---- IMPLEMENTATIONS ----*/

impl AES {

    /**
     * AES symmetric block cipher. This implementation is a module
     * wrapper over the AES cipher provided in the rust-crypto crate 
     * found here: https://github.com/DaGenix/rust-crypto. 
     * 
     * TODO: Inspect the TLS AES source code and see whether it improves
     * 
     * `key_size` - Cipher key size
     * `mode` - AES block mode, either Counter or GCM
     * `gcm_aad` - AAD for GCM mode. None for Counter
     */

    pub fn new(key_size: aes::KeySize, mode: AESMode, gcm_aad: Option<Vec<u8>>) -> Self {
        let mut rng = OsRng::new().unwrap();
        let mut key = primes::generate_random_biguint(&mut rng, &256).to_bytes_le();
        let mut iv = primes::generate_random_biguint(&mut rng, &128).to_bytes_le();

        AES {
            mode: mode,
            key: key,
            history_bytes: 0,
            key_size: key_size,
            aad: gcm_aad,
            initialization_vector: iv
        }
    }
    

    /**
     * Encrypts a block of data provided and returns the ciphertext
     * 
     * `data` - Data to encrypt
     */

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        match self.mode {
            AESMode::GCM => {
                let mut output_buffer = self.fill_vec_to_length(data.len());
                let mut tag = [0; 16];
                let aad = self.aad.clone().unwrap();

                let mut encryptor = AesGcm::new(self.key_size, &[0; 32], &[0; 12], &aad);
                encryptor.encrypt(data, &mut output_buffer, &mut tag);

                Ok(output_buffer)
            },

            AESMode::Counter => {
                let mut buffer_base = [0; 4096];
                let mut read_buffer = RefReadBuffer::new(data);
                let mut output_buffer = RefWriteBuffer::new(&mut buffer_base);
                let mut encryptor = aes::ctr(self.key_size, &self.key.as_slice(), &self.initialization_vector.as_slice());

                let mut final_clone = Vec::new();

                loop {
                    let result = try!(encryptor.encrypt(&mut read_buffer, &mut output_buffer, false));
                    final_clone.extend(output_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

                    match result {
                        BufferResult::BufferUnderflow => break,
                        BufferResult::BufferOverflow => { }
                    }
                }

                self.history_bytes += final_clone.len();

                Ok(final_clone)
            }
        }
    }


    /**
     * Decrypts a block of data and returns the plain text
     * 
     * `ciphertext` - Ciphertext to decrypt
     */

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        match self.mode {
            AESMode::GCM => {
                let mut output_buffer = self.fill_vec_to_length(ciphertext.len());
                let tag = [0; 16];
                let aad = self.aad.clone().unwrap();

                let mut decryptor = AesGcm::new(self.key_size, &[0; 32], &[0; 12], &aad);
                decryptor.decrypt(ciphertext, &mut output_buffer, &tag);

                Ok(output_buffer)
            },

            AESMode::Counter => {
                let mut buffer_base = [0; 4096];
                let mut read_buffer = RefReadBuffer::new(ciphertext);
                let mut output_buffer = RefWriteBuffer::new(&mut buffer_base);
                let mut decryptor = aes::ctr(self.key_size, &self.key.as_slice(), &self.initialization_vector.as_slice());

                let mut final_clone = Vec::new();

                loop {
                    let result = try!(decryptor.decrypt(&mut read_buffer, &mut output_buffer, false));
                    final_clone.extend(output_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

                    match result {
                        BufferResult::BufferUnderflow => break,
                        BufferResult::BufferOverflow => { }
                    }
                }

                Ok(final_clone)
            }
        }
    }


    /**
     * Fills a vector with zeros based on the provided length.
     * The reason for this is that slices in Rust require a constant
     * value length, which is not guaranteed because of the variable 
     * nature of input data
     * 
     * `length` - Length to fill up to
     */

    fn fill_vec_to_length(&self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);

        for i in 0..length {
            output.push(0);
        }

        output
    }

}


/*----- TESTS -----*/

#[cfg(test)]
mod aes_test {

    use crypto::aes::KeySize;
    use cryptopunk::encryption::aes::{ AES, AESMode };

    #[test]
    fn counter_mode_encryption() {
        let data = b"Hello World";
        let mut aes_cipher = AES::new(KeySize::KeySize256, AESMode::Counter, None);

        let cipher = aes_cipher.encrypt(data).ok().unwrap();
        let plain = aes_cipher.decrypt(&cipher).ok().unwrap();

        assert_eq!(plain, data.to_vec());
    }

    #[test]
    fn gcm_mode_encryption() {
        let data = b"Hello World";
        let aad = Some([3u8; 10].to_vec());
        let mut aes_cipher = AES::new(KeySize::KeySize256, AESMode::GCM, aad);

        let cipher = aes_cipher.encrypt(data).ok().unwrap();
    }
}