use digest::Digest;
use sha3;
use blake2;
use tiny_keccak::Keccak;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HashAlgorithm {
    Blake2b,
    Blake2s,
    Sha3_256,
    Sha3_512,
    Keccak256,
    Keccak512
}


/** 
 * Hash a completely available message
 *
 * `message` - Message to sign
 * `protocol` - Hash protocol to use
 */

pub fn hash_message(message: &[u8], protocol: HashAlgorithm) -> Vec<u8> {
    let result = match protocol {
        HashAlgorithm::Blake2b => blake2::Blake2b::digest(message).to_vec(),
        HashAlgorithm::Blake2s => blake2::Blake2s::digest(message).to_vec(),
        HashAlgorithm::Sha3_256 => sha3::Sha3_256::digest(message).to_vec(),
        HashAlgorithm::Sha3_512 => sha3::Sha3_512::digest(message).to_vec(),
        HashAlgorithm::Keccak256 => {
            let mut keccak = Keccak::new_keccak256();
            let mut res: [u8; 32] = [0; 32];

            keccak.update(&message);
            keccak.finalize(&mut res);

            return res.to_vec();
        },
        HashAlgorithm::Keccak512 => {
            let mut keccak = Keccak::new_keccak512();
            let mut res: [u8; 64] = [0; 64];

            keccak.update(&message);
            keccak.finalize(&mut res);

            return res.to_vec();
        }
    };

    result
}


/*----- TESTS -----*/

#[cfg(test)]
mod hash_test {

    use cryptopunk::hash::crypto::{ hash_message, HashAlgorithm };

    const M: &'static [u8; 11] = b"Hello World";
    const BLAKE_2S: &'static str = "[77 6 af 1 91 48 84 9e 51 6f 95 ba 63 3 7 a2 1 8b b7 bf 3 80 3e ca 5e d7 ed 2c 3c 1 35 13]";
    const BLAKE_2B: &'static str = "[43 86 a0 8a 26 51 11 c9 89 6f 56 45 6e 2c b6 1a 64 23 91 15 c4 78 4c f4 38 e3 6c c8 51 22 19 72 da 3f b0 11 5f 73 cd 2 48 62 54 0 1f 87 8a b1 fd 12 6a ac 69 84 4e f1 c1 ca 15 23 79 d0 a9 bd]";
    const SHA3_256: &'static str = "[e1 67 f6 8d 65 63 d7 5b b2 5f 3a a4 9c 29 ef 61 2d 41 35 2d c0 6 6 de 7c bd 63 b b2 66 5f 51]";
    const SHA3_512: &'static str = "[3d 58 a7 19 c6 86 6b 2 14 f9 6b a 67 b3 7e 51 a9 1e 23 3c e0 be 12 6a 8 f3 5f df 4c 4 3c 61 26 f4 1 39 bf bc 33 8d 44 eb 2a 3 de 9f 7b b8 ef f0 ac 26 b 36 29 81 1e 38 9a 5f be e8 a8 94]";
    const KECCAK256: &'static str = "[59 2f a7 43 88 9f c7 f9 2a c2 a3 7b b1 f5 ba 1d af 2a 5c 84 74 1c a0 e0 6 1d 24 3a 2e 67 7 ba]";
    const KECCAK512: &'static str = "[3c 52 db aa 2d 99 2 c3 5b cf 80 16 9c 17 e5 ab 4e df b2 8b 78 be 5b 22 57 69 7d b9 5e e5 8f 33 6c 42 6d b1 2a 9c 19 a1 bb 61 a8 9b 7e 53 4f ca 88 55 5e eb e8 11 b0 1e d8 28 c0 d5 a4 68 7b 3e]";

    #[test]
    fn basic_blake2s() {
        assert_eq!(format!("{:x}", hash_message(M, HashAlgorithm::Blake2s).as_hex()), BLAKE_2S);
    }

    #[test]
    fn basic_sha3_512() {
        assert_eq!(format!("{:x}", hash_message(M, HashAlgorithm::Sha3_512).as_hex()), SHA3_512);
    }

    #[test]
    fn basic_sha3_256() {
        assert_eq!(format!("{:x}", hash_message(M, HashAlgorithm::Sha3_256).as_hex()), SHA3_256);
    }

    #[test]
    fn basic_blake2b() {
        assert_eq!(format!("{:x}", hash_message(M, HashAlgorithm::Blake2b).as_hex()), BLAKE_2B);
    }

    #[test]
    fn basic_keccak256() {
        assert_eq!(format!("{:x}", hash_message(M, HashAlgorithm::Keccak256).as_hex()), KECCAK256);
    }

    #[test]
    fn basic_keccak512() {
        assert_eq!(format!("{:x}", hash_message(M, HashAlgorithm::Keccak512).as_hex()), KECCAK512);
    }
    
}