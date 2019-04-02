use rand::OsRng;
use num_bigint::BigUint;
use crate::utils::primes;
use num_bigint::ToBigUint;
use std::ops::{ Rem, Shr };
use num_traits::{ One, Zero };

/// Diffie Hellman 
pub struct DiffieHellman {
    pub p: BigUint,         // prime modulus
    pub g: BigUint,         // generator
    pub gx: BigUint,        // self = G^X mod P
    x: BigUint,             // private value
    px: BigUint,            // previous X
    v_i: BigUint,           // Blinding value
    v_f: BigUint,           // Unblinding value
    gy: BigUint,            // peer = G^Y mod P
    pub shared_key: BigUint // key = GY^X mod P
}

impl DiffieHellman {

    /// Diffie-Hellman key agreement protocol. This implementation is a 
    /// Rust appropriation of the TLS Diffie-Hellman source code written
    /// in C, found at: https://github.com/ARMmbed/mbedtls/blob/master/library/dhm.c.
    pub fn new() -> Self {
        DiffieHellman { 
            p: BigUint::zero(), 
            g: BigUint::zero(), 
            x: BigUint::zero(),
            gx: BigUint::zero(),
            gy: BigUint::zero(),
            v_i: BigUint::zero(),
            v_f: BigUint::zero(),
            px: BigUint::zero(),
            shared_key: BigUint::zero()
        }
    }

    /// Generate self based on peer values.
    /// 
    /// ### Arguments
    /// 
    /// * `peer_p` - Peer's public P modulus value
    /// * `peer_g` - Peer's public G value
    /// * `peer_gx` - Peer's public GX value
    pub fn new_from_peer(peer_p: &BigUint, peer_g: &BigUint, peer_gx: &BigUint) -> Self {
        DiffieHellman {
            p: peer_p.clone(),
            g: peer_g.clone(),
            x: BigUint::zero(),
            gy: peer_gx.clone(),
            gx: BigUint::zero(),
            v_i: BigUint::zero(),
            v_f: BigUint::zero(),
            px: BigUint::zero(),
            shared_key: BigUint::zero()
        }
    }

    /// Sets up internal values. This is a separate method 
    /// from "new" because internal method referencing is not technically 
    /// possible in constructors. As such, it should chained with the "new" 
    /// command in practical use (see tests below for an example).
    /// 
    /// ### Arguments
    /// 
    /// * `bitlength` - Bit length of primes
    pub fn setup(mut self, bitlength: usize) -> DiffieHellman {
        // check for peer value
        if self.g == BigUint::zero() {
            self.g = primes::generate_discrete_log_prime(&bitlength);
        }

        // check for peer value
        if self.p == BigUint::zero() {
            self.p = primes::generate_discrete_log_prime(&bitlength);
        }

        // check for peer value
        if self.gy == BigUint::zero() {
            let mut gy = BigUint::zero();

            while !self.check_range(&gy) {
                gy = primes::generate_discrete_log_prime(&bitlength);
            }
            
            self.gy = gy;
        }
        
        self.x = self.generate_private_x(&bitlength);

        // check for peer value
        self.gx = self.g.modpow(&self.x, &self.p);

        if !self.check_range(&self.gx) {
            println!("GX needs to be less than modulus P");

            while !self.check_range(&self.gx) {
                self.gx = primes::generate_discrete_log_prime(&bitlength);
            }
        }

        self
    }

    /// Generate a private X value that is as large as possible ( < P )
    /// 
    /// ### Arguments
    ///  
    /// * `bitlength` - Bit length of X
    fn generate_private_x(&mut self, bitlength: &usize) -> BigUint {
        let mut x = BigUint::zero();

        while !self.check_range(&x) {
            x = primes::generate_discrete_log_prime(bitlength);

            while &x >= &self.p {
                x = x.clone().shr(1);
            }
        }

        x.clone()
    }

    /// Verify sanity of parameter in relation to P modulus.
    /// Parameter should be: 2 <= parameter <= P - 2
    /// 
    /// For more information on the attack, see:
    /// http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
    /// http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
    /// 
    /// ### Arguments
    /// 
    /// * `parameter` - Parameter to check
    fn check_range(&self, parameter: &BigUint) -> bool {
        parameter >= &2.to_biguint().unwrap() && 
        parameter <= &(&self.p - &2.to_biguint().unwrap())
    }

    /// Update blinding values. Use the blinding method and optimisation 
    /// suggested in section 10 of: KOCHER, Paul C. Timing attacks on 
    /// implementations of Diffie-Hellman, RSA, DSS, and other systems. In:
    /// Advances in Cryptology-CRYPTO'96. Springer Berlin Heidelberg, 1996. p. 104-113.
    /// 
    /// ### Arguments
    /// 
    /// * `generator` - Random number generator
    fn update_blinding(&mut self, mut generator: &mut OsRng) -> () {

        // Don't use any blinding the first time a particular X is used,
        // but remember it to use blinding next time.
        if &self.px != &self.x {
            self.px = self.x.clone();
            self.v_i = BigUint::one();
            self.v_f = BigUint::one();
        }

        // We need blinding. Can we re-use existing values?
        // If yes, just update them by squaring them.
        else if self.v_i != BigUint::one() {
            self.v_i = self.v_i.modpow(&self.v_i, &self.p);
            self.v_f = self.v_i.modpow(&self.v_f, &self.p);
        }

        // We need to generate blinding values from scratch
        else {
            let mut count = 0;

            // Vi = random( 2, P-1 )
            while &self.v_i <= &BigUint::one() {
                self.v_i = primes::generate_random_biguint(&mut generator, &self.p.bits());

                while &self.v_i >= &self.p {
                    self.v_i = self.v_i.clone().shr(1);
                }

                count += 1;

                if count > 10 {
                    break;
                }
            }

            // Vf = Vi^-X mod P
            self.v_f = primes::modular_inverse(&self.v_i, &self.p);
            self.v_f = self.v_f.modpow(&self.x, &self.p);
        }

    }
 
    /// Derive and export the shared secret (G^Y)^X mod P.
    /// Random number generator is used to blind the input as a
    /// countermeasure against timing attacks. Blinding is
    /// automatically used if and only if our secret value X is
    /// re-used and costs nothing otherwise.
    /// 
    /// ### Arguments
    ///  
    /// * `generator` - Random number generator
    /// * `peer_gx` - Peer's GY value
    pub fn generate_shared_key(&mut self, mut generator: &mut OsRng, peer_gx: &BigUint) -> BigUint {
        let mut key = BigUint::zero();

        // Perform necessary blinding
        self.update_blinding(&mut generator);
        key = (peer_gx * &self.v_i).rem(&self.p);

        // Modular exponentiation and then unblind
        self.shared_key = key.clone().modpow(&self.x, &self.p);
        self.shared_key = (&self.shared_key * &self.v_f).rem(&self.p);

        self.shared_key.clone()
    }

}


/*----- TESTS -----*/

#[cfg(test)]
mod dh_test {

    use rand::OsRng;
    use cryptopunk::key_exchange::diffie_hellman::DiffieHellman;

    #[test]
    fn successful_shared_secret() {
        let mut generator = OsRng::new().unwrap();
        let mut dh = DiffieHellman::new().setup(16);

        let (p, g, peer_gx) = (dh.p.clone(), dh.g.clone(), dh.gx.clone());

        let mut dh2 = DiffieHellman::new_from_peer(&p, &g, &peer_gx).setup(16);

        let check_from_first = dh.generate_shared_key(&mut generator, &dh2.gx);
        let check_from_second = dh2.generate_shared_key(&mut generator, &dh.gx);

        assert_eq!(check_from_first, check_from_second);
    }
    
}