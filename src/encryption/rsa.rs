use std::ops::Rem;
use num_integer::gcd;
use rand::{ OsRng, Rng };
use num_bigint::{ BigUint, RandBigInt };
use num_traits::{ FromPrimitive, One, Zero };

use utils::{ primes, transform };
use cryptopunk::hash::crypto::HashAlgorithm;
use cryptopunk::encryption::AsymmetricKeyMode;


/*---- STRUCTS ----*/

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RSA {
    pub n: BigUint,                // public modulus
    pub e: BigUint,                // public exponent
    d: BigUint,                    // private exponent
    p: BigUint,                    // first prime factor
    q: BigUint,                    // second prime factor
    dp: BigUint,                   // D % (P - 1)
    dq: BigUint,                   // D % (Q - 1)
    qp: BigUint,                   // 1 / (Q % P)
    v_i: BigUint,                  // Blinding value
    v_f: BigUint,                  // Un-blinding value
    use_crt: bool,                 // whether to use Chinese Remainder Theorem for operations
    pub size_n: usize,             // size of n in characters
    hash_algorithm: HashAlgorithm, // Only used for OAEP/PSS
}


/*---- CONSTANTS ----*/

const RSA_BLINDING_LENGTH: usize = 28;
const RSA_CHUNK: usize = 30;


/*---- IMPLEMENTATIONS ----*/

impl RSA {

    /// RSA public key cryptosystem. This implementation is a Rust translation
    /// of the TLS RSA library written in C, found here: https://tls.mbed.org/rsa-source-code.
    /// Padding is restricted to PKCS#1 v2.1, as v1.5 support has been dropped by TLS and is
    /// widely considered insecure
    /// 
    /// ### Arguments
    /// 
    /// * `hash_algorithm` - Hashing algorithm for padding
    /// * `use_crt` - Whether or not to use the Chinese Remainder Theorem
    pub fn new(hash_algorithm: HashAlgorithm, use_crt: bool) -> Self {
        RSA {
            n: BigUint::zero(),
            e: BigUint::zero(),
            d: BigUint::zero(),
            p: BigUint::zero(),
            q: BigUint::zero(),
            dp: BigUint::zero(),
            dq: BigUint::zero(),
            qp: BigUint::zero(),
            v_i: BigUint::zero(),
            v_f: BigUint::zero(),
            size_n: 0,
            use_crt: use_crt,
            hash_algorithm: hash_algorithm,
        }
    }

    /// Encrypts the input data using RSA. The input must be as large as the size
    /// of "self.size_n" (eg. 128 bytes if RSA-1024 is used), and as such the input
    /// is encrypted in chunks before returning
    ///
    /// TODO: Handle input padding
    /// 
    /// ### Arguments
    /// 
    /// * `data` - Data to encrypt
    /// * `mode` - Either Private or Public
    /// * `generator` - Random number generator
    pub fn encrypt(&mut self, data: &Vec<u8>, mode: AsymmetricKeyMode, mut generator: &mut OsRng) -> Vec<u8> {
        let mut encrypted = Vec::new();

        for chunk in data.chunks(RSA_CHUNK) {
            let chunk_as_bigint = BigUint::from_bytes_le(&chunk);
            let mut encrypted_chunk = BigUint::zero();
            let mut encrypted_as_vec = Vec::new();

            match mode {
                AsymmetricKeyMode::Private => {
                    encrypted_chunk = self.use_private_key(&chunk_as_bigint, &mut generator);
                }
                AsymmetricKeyMode::Public => {
                    encrypted_chunk = self.use_public_key(&chunk_as_bigint);
                }
            }

            encrypted_as_vec = encrypted_chunk.to_bytes_le();

            // pad out if less than "size_n" because
            // decryption will break otherwise
            while encrypted_as_vec.len() < self.size_n {
                encrypted_as_vec.push(0);
            }

            encrypted.append(&mut encrypted_as_vec);
        }

        encrypted
    }

    /// Decrypts the input data using RSA. The Chunk struct is inconsistent
    /// in its slicing, and thus a custom chunking function is used to split
    /// the ciphertext
    ///
    /// TODO: Handle padding
    /// 
    /// ### Arguments
    /// 
    /// * `ciphertext` - Ciphertext to decrypt
    /// * `mode` - Either Private or Public
    /// * `generator` - Random number generator
    pub fn decrypt(&mut self, ciphertext: &Vec<u8>, mode: AsymmetricKeyMode, mut generator: &mut OsRng) -> Vec<u8> {
        let mut iter_counter = 0;
        let mut decrypted = Vec::new();
        let chunked_ciphertext = transform::get_exact_chunks(ciphertext, &self.size_n);
        let iter_length = chunked_ciphertext.len();

        for chunk in chunked_ciphertext {
            let chunk_as_bigint = BigUint::from_bytes_le(&chunk);
            let mut decrypted_chunk = BigUint::zero();
            let mut decrypted_as_vec = Vec::new();

            match mode {
                AsymmetricKeyMode::Private => {
                    decrypted_chunk = self.use_private_key(&chunk_as_bigint, &mut generator);
                }
                AsymmetricKeyMode::Public => {
                    decrypted_chunk = self.use_public_key(&chunk_as_bigint);
                }
            }

            decrypted_as_vec = decrypted_chunk.to_bytes_le();

            // Handle padding out when decrypted value
            // is less than the original chunk size
            if iter_counter < iter_length - 1 {
                while decrypted_as_vec.len() < RSA_CHUNK {
                    decrypted_as_vec.push(0);
                }

                iter_counter += 1;
            }

            decrypted.append(&mut decrypted_as_vec);
        }

        decrypted
    }

    /// Generates an RSA keypair.
    /// 
    /// ### Arguments
    /// 
    /// * `bitlength` - Bit length public key size
    /// * `exponent` - Public exponent (eg. 65537)
    pub fn generate_keypair(mut self, bitlength: usize, exponent: &BigUint) -> RSA {
        self.check_input_params(&bitlength, &exponent);

        let (p, q, totient) = self.get_totient_values(&bitlength, exponent.clone());

        self.e = exponent.clone();
        self.p = p.clone();
        self.q = q.clone();
        self.n = &p * &q;

        self.d = primes::modular_inverse(exponent, &totient);
        self.dp = &self.d % (&self.p - BigUint::one());
        self.dq = &self.d % (&self.q - BigUint::one());
        self.qp = primes::modular_inverse(&q, &p);

        self.size_n = (&self.n + &BigUint::from_u8(7).unwrap()).bits() >> 3;

        self
    }

    /// Generates an RSA keypair from peer
    /// 
    /// ### Arguments
    /// 
    /// * `bitlength` - Bit length public key size
    /// * `exponent` - Public exponent
    /// * `modulus` - Public modulus
    pub fn generate_keypair_from_peer(
        mut self, 
        bitlength: usize, 
        exponent: &BigUint, 
        modulus: &BigUint
    ) -> RSA 
    {
        self.check_input_params(&bitlength, &exponent);

        let (_p, _q, totient) = self.get_totient_values(&bitlength, exponent.clone());

        self.e = exponent.clone();
        self.n = modulus.clone();
        self.d = primes::modular_inverse(exponent, &totient);
        self.size_n = (&self.n + &BigUint::from_u8(7).unwrap()).bits() >> 3;

        self
    }

    /// Exports public exponent and modulus
    pub fn export_public_values(&self) -> (BigUint, BigUint) {
        (self.n.clone(), self.e.clone())
    }

    /// Generate or update blinding values, see section 10 of:
    /// KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
    /// DSS, and other systems. In: Advances in Cryptology-CRYPTO'96. Springer
    /// Berlin Heidelberg, 1996. p. 104-113.
    /// 
    /// ### Arguments
    ///
    /// * `generator` - Random number generator
    fn prepare_blinding(&mut self, generator: &mut OsRng) -> () {
        let mut count = 0;

        if self.v_f != BigUint::zero() {
            self.v_i = &self.v_i * &self.v_i;
            self.v_i = &self.v_i % &self.n;

            self.v_f = &self.v_f * &self.v_f;
            self.v_f = &self.v_f % &self.n;
        } else {
            while self.v_i != BigUint::one() {
                if count == 10 {
                    panic!("RNG failed for RSA blinding");
                }

                self.v_f = generator.gen_biguint(self.size_n - 1);
                self.v_i = gcd(self.v_f.clone(), self.n.clone());

                count += 1;
            }

            self.v_i = primes::modular_inverse(&self.v_f, &self.n);
            self.v_i = self.v_i.modpow(&self.e, &self.n);
        }
    }

    /// Perform a private key operation. Since the Chinese Remainder Theorem
    /// will be used for more efficient computation, values DP and DQ serve as the base
    /// for "m = c ^ d % n". More info on CRT for RSA can be found at:
    /// https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
    /// 
    /// ### Arguments
    /// 
    /// * `input` - Input data to operate on
    /// * `generator` - Random number generator
    fn use_private_key(&mut self, input: &BigUint, mut generator: &mut OsRng) -> BigUint {
        // Input Blinding
        self.prepare_blinding(&mut generator);
        let mut t = (input * &self.v_i).rem(&self.n);

        // Exponent Blinding
        let p1 = &self.p - &BigUint::one();
        let q1 = &self.q - &BigUint::one();

        // If using Chinese Remainder Theorem
        if self.use_crt {
            let mut rand_holder: [u8; RSA_BLINDING_LENGTH] = [0; RSA_BLINDING_LENGTH];

            // DP Blinding = ( P - 1 ) * R + DP
            generator.fill_bytes(&mut rand_holder);
            let mut r = BigUint::from_bytes_le(&rand_holder);
            let dp_blind = &p1 * &r + &self.dp;

            self.dp = dp_blind;

            // DQ Blinding = ( Q - 1 ) * R + DQ
            generator.fill_bytes(&mut rand_holder);
            r = BigUint::from_bytes_le(&rand_holder);
            let dq_blind = &q1 * &r + &self.dq;

            self.dq = dq_blind;

            // T1 = input ^ dP mod P
            // T2 = input ^ dQ mod Q
            let mut t1 = t.modpow(&self.dp, &self.p);
            let t2 = t.modpow(&self.dq, &self.q);

            // T = (T1 - T2) * (Q^-1 mod P) mod P
            // T = T2 + T * Q
            t = &t1 - &t2;
            t1 = &t * &self.qp;
            t = t1.rem(&self.p);
            t1 = &t * &self.q;
            t = &t1 + &t2;
        } else {
            t = t.modpow(&self.d, &self.n);
        }

        // Unblind
        // T = T * Vf mod N
        t = (&t * &self.v_f).rem(&self.n);

        t
    }

    /// Perform a public key operation
    /// 
    /// ### Arguments
    /// 
    /// * `input` - Input value to operate on
    fn use_public_key(&self, input: &BigUint) -> BigUint {
        input.modpow(&self.e, &self.n)
    }

    /// Checks pub/priv keypair for validity
    pub fn check_keypair(&self) -> () {
        let public_check = self.check_public_key();
        let private_check = self.check_private_key();

        if !public_check.0 {
            panic!(public_check.1);
        }

        if !private_check.0 {
            panic!(private_check.1);
        }
    }

    /// Checks that public key is valid
    fn check_public_key(&self) -> (bool, &'static str) {
        if self.n < BigUint::from_u64(128).unwrap() {
            return (false, "The 'n' value of RSA keypair is too small");
        }

        if self.e < BigUint::from_u8(2).unwrap() || self.e >= self.n {
            return (false, "The RSA exponent is either too small or too large");
        }

        (true, "")
    }

    /// Checks that private key is valid
    fn check_private_key(&self) -> (bool, &'static str) {
        let pq = &self.p * &self.q;
        let p1 = &self.p - &BigUint::one();
        let q1 = &self.q - &BigUint::one();
        let totient = &p1 * &q1;
        let g = gcd(self.e.clone(), totient.clone());
        let dp = &self.d % &p1;
        let dq = &self.d % &q1;
        let qp = primes::modular_inverse(&self.q, &self.p);

        if pq != self.n || dp != self.dp || dq != self.dq || qp != self.qp || g != BigUint::one() {
            return (false, "RSA private key failure");
        }

        (true, "")
    }

    /// Ensures input parameters are valid for operation
    /// 
    /// ### Arguments
    /// 
    /// * `bitlength` - Bit length of primes
    /// * `exponent` - Exponent for calculation
    fn check_input_params(&self, bitlength: &usize, exponent: &BigUint) -> () {
        if bitlength < &128 {
            panic!("Bit length provided for RSA is either too small or not even");
        }

        if exponent < &BigUint::from_u8(3).unwrap() {
            panic!("Exponent provided for RSA is too small");
        }
    }

    /// Generates "p", "q" and totient values that fulfill Euler's totient function,
    /// where GCD( e, (p-1) * (q-1) ) == 1 and q < p.
    /// 
    /// ### Arguments
    /// 
    /// * `bitlength` - Bit length of primes
    /// * `exponent` - Exponent for calculation
    fn get_totient_values(&mut self, bitlength: &usize, exponent: BigUint) -> (BigUint, BigUint, BigUint) {
        let mut co_primality = BigUint::zero();
        let mut p = BigUint::zero();
        let mut q = BigUint::zero();
        let mut totient = BigUint::zero();
        let rs_bitlength = bitlength.clone() >> 1;

        while co_primality != BigUint::one() {
            let first = primes::generate(&rs_bitlength); // change this to safe primes
            let second = primes::generate(&rs_bitlength); // change this to safe primes

            if first == second {
                continue;
            }

            if first < second {
                p = second;
                q = first;
            } else {
                p = first;
                q = second;
            }

            if (&p * &q).bits() != bitlength.clone() {
                continue;
            }

            totient = (&p - BigUint::one()) * (&q - BigUint::one());
            co_primality = gcd(exponent.clone(), totient.clone());
        }

        (p, q, totient)
    }
}


/*----- TESTS -----*/

#[cfg(test)]
mod rsa_test {

    use rand::OsRng;
    use num_traits::FromPrimitive;
    use num_bigint::{BigUint, ToBigUint};
    use cryptopunk::hash::crypto::HashAlgorithm;
    use cryptopunk::encryption::rsa::{AsymmetricKeyMode, RSA};

    #[test]
    fn keypair_generation() {
        let mut generator = OsRng::new().unwrap();
        let exponent = BigUint::from_u32(65537).unwrap();
        let mut new_rsa = RSA::new(HashAlgorithm::Blake2s, true).generate_keypair(256, &exponent);

        new_rsa.check_keypair();
    }

    #[test]
    fn blinding_generation() {
        let mut generator = OsRng::new().unwrap();
        let exponent = BigUint::from_u32(65537).unwrap();
        let mut new_rsa = RSA::new(HashAlgorithm::Blake2s, true).generate_keypair(256, &exponent);

        new_rsa.prepare_blinding(&mut generator);
    }

    #[test]
    fn public_private_encryption_without_crt() {
        let mut generator = OsRng::new().unwrap();
        let exponent = BigUint::from_u32(65537).unwrap();
        let mut new_rsa = RSA::new(HashAlgorithm::Blake2s, false).generate_keypair(256, &exponent);

        let test: BigUint = 12345.to_biguint().unwrap();
        let byte_length = test.bits() / 8;
        let ciphertext = new_rsa.encrypt(&test, byte_length, AsymmetricKeyMode::Public, &mut generator);
        let returned = new_rsa.decrypt(&ciphertext, AsymmetricKeyMode::Private, &mut generator);

        assert_eq!(test, returned);
    }

    #[test]
    fn private_public_encryption_without_crt() {
        let mut generator = OsRng::new().unwrap();
        let exponent = BigUint::from_u32(65537).unwrap();
        let mut new_rsa = RSA::new(HashAlgorithm::Blake2s, false).generate_keypair(256, &exponent);

        let test: BigUint = 12345.to_biguint().unwrap();
        let byte_length = test.bits() / 8;
        let ciphertext = new_rsa.encrypt(&test, byte_length, AsymmetricKeyMode::Private, &mut generator);
        let returned = new_rsa.decrypt(&ciphertext, AsymmetricKeyMode::Public, &mut generator);

        assert_eq!(test, returned);
    }

}
