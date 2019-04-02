use rand::OsRng;

pub mod rsa;
pub mod aes;
// pub mod ring_lwe;

pub trait AsymmetricEncryptor<AsymmetricKeyMode> {
    fn encrypt(&mut self, data: &Vec<u8>, mode: AsymmetricKeyMode, generator: &mut OsRng) -> Vec<u8>;
    fn decrypt(&mut self, ciphertext: &Vec<u8>, mode: AsymmetricKeyMode, generator: &mut OsRng) -> Vec<u8>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AsymmetricKeyMode {
    Private,
    Public,
}