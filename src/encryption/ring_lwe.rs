use num_bigint::BigUint;
use num_traits::Zero;

use utils::knuth_yao;

/*---- Structs ----*/

pub struct RingLWE {
    a: BigUint,
    p: BigUint,
    r_2: BigUint
}

/*---- Implementation ----*/

impl RingLWE {

    /**
     * Post-quantum cryptographic cipher. This implementation is a
     * Rust translation of the C version found here:
     * https://github.com/ruandc/Ring-LWE-Encryption
     * 
     * The C version is an implementation of "Efficient Software 
     * Implementation of Ring-LWE Encryption", found here:
     * https://eprint.iacr.org/2014/725.pdf
     */

    pub fn new() -> Self {
        RingLWE {
            a: BigUint::zero(),
            p: BigUint::zero(),
            r_2: BigUint::zero()
        }
    }


    /**
     * Setup function to be used in conjunction with "new" above.
     * For an example of implementation, view the test at the bottom 
     * of this file
     */

    pub fn setup(mut self) -> RingLWE {
        let a = self.generate_a();
        let p = self.generate_p();
        // let r_2 = self.generate_r_2();

        self
    }


    /**
     * Generates an "a" value
     */

    fn generate_a(&self) -> Vec<u32> {
        let mut new_a = Vec::with_capacity(knuth_yao::M as usize);

        for i in 0..knuth_yao::M / 2 {
            let i_usize = i as usize;
            let rand = 0; // replace with random u32

            new_a[2 * i_usize] = self.lwe_mod( &((rand & 65535) as u32) );
            new_a[2 * i_usize + 1] = self.lwe_mod( &((rand >> 16) as u32) );
        }

        new_a
    } 


    /**
     * Generates a "p" value
     */

    fn generate_p(&self) -> Vec<u32> {
        let mut new_p = Vec::with_capacity(knuth_yao::M as usize);

        // knuth_yao::shuffle(&mut new_p);
        // ntt::forward_multiply(&mut new_p);

        new_p
    }


    /**
     * Mod function for LWE. This function does NOT require -q<x<q
     * 
     * `x` - Value to apply mod to
     */

    fn lwe_mod(&self, x: &u32) -> u32 {
        let mut return_x = x % knuth_yao::MODULUS;

        while return_x > knuth_yao::MODULUS {
            return_x -= knuth_yao::MODULUS;
        }

        return_x
    }
}