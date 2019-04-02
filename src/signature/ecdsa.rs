use rand::OsRng;
use std::ops::Rem;
use num_traits::{One, Zero};
use num_bigint::{BigInt, BigUint, ToBigInt};

use utils::primes;
use utils::ecc::ECPKeypair;
use utils::encoding::from_plaintext;
use utils::ecc_curves::{ECPPoint, ECPSupportedCurves};


pub struct ECDSA {
    keypair: ECPKeypair
}

pub struct ECDSASignature {
    r: BigInt,
    s: BigInt
}

impl ECDSA {
    pub fn new(curve: ECPSupportedCurves, rng: &mut OsRng) -> Self {
        ECDSA {
            keypair: ECPKeypair::new(curve).setup(rng)
        }
    }

    pub fn sign(&mut self, message: &Vec<u8>, rng: &mut OsRng) -> ECDSASignature {
        let mut r = BigInt::zero();
        let mut s = BigInt::zero();
        let mut t = BigInt::zero();

        let g_clone = self.keypair.group.g.clone();
        let n_clone = self.keypair.group.n.clone();

        let n_int = n_clone.to_bigint().unwrap();
        let mut k = self.keypair.get_valid_private_value();
        k = k.rem(n_clone.clone());

        let p_1 = self.keypair.multiply_point(&g_clone, &k);
        r = p_1.x;

        if r == BigInt::zero() {
            panic!("Whoops on R");
        }

        let e = BigUint::from_bytes_le(message).to_bigint().unwrap();
        s = primes::modular_inverse(&k, &n_clone).to_bigint().unwrap();
        t = self.keypair.d.to_bigint().unwrap() * r.clone();
        t = (e + t).rem(n_int.clone());
        s = (s * t).rem(n_int);

        if s == BigInt::zero() {
            panic!("Whoops on s");
        }

        ECDSASignature {
            s: s,
            r: r
        }
    }

    pub fn verify(&mut self, message: &Vec<u8>, signature: &ECDSASignature) {
        let n_int = self.keypair.group.n.to_bigint().unwrap();

        /*
         * Step 1: make sure r and s are in range 1..n-1
         */
        if signature.r < BigInt::one() 
        || signature.r >= n_int 
        || signature.s < BigInt::one() 
        || signature.s >= n_int {
            panic!("R or S values are either too small or too large");
        }

        /*
         * Step 3: derive int from hashed message
         */
        let e = BigUint::from_bytes_le(message).to_bigint().unwrap();

        /*
         * Step 4: u1 = e / s mod n, u2 = r / s mod n
         */
        let s_inverse = primes::modular_inverse_int(&signature.s, &n_int);
        let u_1 = (e * s_inverse.clone()) % n_int.clone();
        let u_2 = (signature.r.clone() * s_inverse) % n_int.clone();

        /*
         * Step 5: R = u1 G + u2 Q
         */
        let g_clone = self.keypair.group.g.clone();
        let q_clone = self.keypair.q.clone();

        let P = self.keypair.multiply_point(&g_clone, &u_1.to_biguint().unwrap());
        let S = self.keypair.multiply_point(&q_clone, &u_2.to_biguint().unwrap());
        let R = self.keypair.add_points(&P, &S);


        /*
         * Step 6: convert xR to an integer (no-op)
         * Step 7: reduce xR mod n (gives v)
         */
        let v = R.x % n_int;

        println!("v: {}", v);
        println!("r: {}", signature.r);

        /*
         * Step 8: check if v (that is, R.X) is equal to r
         */
        if v != signature.r {
            panic!("Verification failed: V != r");
        }
    }
}
