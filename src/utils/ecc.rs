use rand::OsRng;
use std::ops::Shr;

use num_bigint::{ BigUint, ToBigInt, BigInt };
use num_traits::{ One, Zero };

use utils::{ primes, comb_method, montgomery_ladder, jacobian_coords };
use utils::encoding::{ EndianOrdering, biguint_to_bitvec, bitvec_to_biguint };
use utils::ecc_curves::{ ECPPoint, ECPGroup, ECPSupportedCurves, ECPCurveShape };


/*---- STRUCTS ----*/

/// A simple ECC key pair
/// 
/// All values in the ECPKeypair are public because the 
/// assumption is that ECC is not used in isolation, but 
/// rather used as a mathematical base for other crypto 
/// processes.
#[derive(Clone)]
pub struct ECPKeypair {
    pub group: ECPGroup,    // elliptic curve and base point
    pub d: BigUint,         // private value
    pub q: ECPPoint         // public value
}


/*---- CONSTANTS ----*/

/// Max bit size of groups
const MAX_BIT_SIZE: usize = 521;
const MAX_BYTE_SIZE: usize = ( ( 521 + 7 ) / 8 );
const MAX_POINT_LEN: usize = ( 2 * 521 + 1 );


/*---- IMPLEMENTATIONS ----*/

impl ECPKeypair {

    /// Elliptic curve cryptosystem. This is a Rust translation of 
    /// the TLS ECC source code, written in C, and serves as the mathematical
    /// base for all ECC related cryptographic code. Original source code 
    /// found here: https://github.com/ARMmbed/mbedtls/blob/master/library/ecp.c
    /// 
    /// ### Arguments
    /// 
    /// * `curve` - Curve group to use
    pub fn new(curve: ECPSupportedCurves) -> Self {
        ECPKeypair {
            group: ECPGroup::new(curve),
            d: BigUint::zero(),
            q: ECPPoint::new( &BigInt::zero(), Some(BigInt::zero()) )
        }
    }

    /// Set up new ECP keypair values. This is a separate method 
    /// from "new" because internal method referencing is not technically 
    /// possible in constructors. As such, it should chained with the "new" 
    /// command in practical use (see tests below for an example).
    /// 
    /// ### Arguments
    /// 
    /// * `rng` - Random number generator
    pub fn setup(mut self, mut rng: &mut OsRng) -> ECPKeypair {
        self.d = self.get_valid_private_value();
        self.q = self.multiply(&mut rng);
        
        // Perform sanity checks
        self.check_public_private_keys(&self.q);

        self
    }

    /// Multiplication R = m * P. In this case "P" is the generator
    /// point of the group and "m" is the private "d" value
    /// 
    /// ### Arguments
    /// 
    /// * `rng` - Random number generator
    pub fn multiply(&mut self, rng: &mut OsRng) -> ECPPoint {
        let curve_shape = self.group.get_curve_shape();
        let p_point = self.group.g.clone();

        match curve_shape {
            ECPCurveShape::Montgomery => montgomery_ladder::multiply(&self.group, &self.d, &p_point),
            ECPCurveShape::ShortWeierstrass => comb_method::multiply(&mut self.group, &self.d, &p_point, rng)
        }
    }

    /// Multiplies supplied point with supplied scalar
    /// 
    /// ### Arguments
    ///  
    /// * `p` - Point to multiply
    /// * `m` - Scalar to multiply with
    pub fn multiply_point(&mut self, p: &ECPPoint, m: &BigUint) -> ECPPoint {
        let curve_shape = self.group.get_curve_shape();
        let mut rng = OsRng::new().unwrap();

        match curve_shape {
            ECPCurveShape::Montgomery => montgomery_ladder::multiply(&self.group, m, p),
            ECPCurveShape::ShortWeierstrass => comb_method::core_multiplication(&mut self.group, p, m, &mut rng)
        }
    }

    /// Adds two points
    /// 
    /// ### Arguments
    /// 
    /// * `p` - First point
    /// * `r` - Second point
    pub fn add_points(&mut self, p: &ECPPoint, r: &ECPPoint) -> ECPPoint {
        let curve_shape = self.group.get_curve_shape();
        let gx = self.group.clone().g.x;
        let mut r_clone = r.clone();

        match curve_shape {
            ECPCurveShape::Montgomery => montgomery_ladder::add_points(&self.group, p, r, &gx),
            ECPCurveShape::ShortWeierstrass => jacobian_coords::add(&self.group, p, &mut r_clone)
        }
    }

    /// Checks both public and private keys provided
    /// 
    /// ### Arguments
    /// 
    /// * `public` - Public point to check
    fn check_public_private_keys(&self, point: &ECPPoint) -> () {
        let private_key_check = self.check_private_key();
        let public_key_check = self.check_public_key(point);

        if !private_key_check.0 {
            panic!(private_key_check.1);
        }

        if !public_key_check.0 {
            panic!(public_key_check.1);
        }
    }

    /// Check that the D value is valid as a private key
    fn check_private_key(&self) -> (bool, &'static str) {
        let curve_shape = self.group.get_curve_shape();

        if curve_shape == ECPCurveShape::Montgomery {
            let d_bit_vec = biguint_to_bitvec(&self.d, EndianOrdering::Little);

            if d_bit_vec.get(0).unwrap() ||
               d_bit_vec.get(1).unwrap() ||
               d_bit_vec.get(2).unwrap() ||
               self.d.bits() != self.group.nbits 
            {
                return (false, "Least significant bits need to be 0 for private value D");
            }

        } else {
            if self.d < BigUint::one() {
                return (false, "Private value D needs to be larger than 1");
            }

            if self.d >= self.group.n {
                return (false, "Private value D needs to be less than the group order N");
            }
        }

        (true, "")
    }

    /// Check that a point is a valid public key
    /// 
    /// ### Arguments
    /// 
    /// * `point` - Point to check
    pub fn check_public_key(&self, point: &ECPPoint) -> (bool, &'static str) {
        // Must use affine coordinates
        if point.z != BigInt::one() {
            return (false, "Coordinates for public key point are not affine (Z coordinate != 1)");
        }

        let curve_shape = self.group.get_curve_shape();

        match curve_shape {
            ECPCurveShape::Montgomery => {
                if (point.x.bits() + 7) / 8 > (self.group.nbits + 7) / 8 {
                    return (false, "X coord for public point is too large");
                }

                return (true, "");
            },

            ECPCurveShape::ShortWeierstrass => self.check_weierstrass_public_key(point)
        }
    }

    /// Generates a valid private value for use
    /// in an ECC keypair
    pub fn get_valid_private_value(&self) -> BigUint {
        let mut rng = OsRng::new().unwrap();
        let n_size = (self.group.nbits + &7) / 8;
        let curve_shape = self.group.get_curve_shape();

        match curve_shape {
            ECPCurveShape::Montgomery => {
                let mut d = BigUint::zero();

                while d.bits() != self.group.nbits {
                    d = primes::generate(&self.group.nbits);
                }

                let mut d_bit_vec = biguint_to_bitvec(&d, EndianOrdering::Little);
                let b = d.bits() - 1;

                // Make sure the most significant bit is nbits
                if b > self.group.nbits {
                    d = d.shr(b.clone() - self.group.nbits.clone());
                    d_bit_vec = biguint_to_bitvec(&d, EndianOrdering::Little); 

                } else {
                    d_bit_vec.set(self.group.nbits, true);
                }

                // Make sure the last three bits are unset
                d_bit_vec.set(0, false);
                d_bit_vec.set(1, false);
                d_bit_vec.set(2, false);

                return bitvec_to_biguint(&d_bit_vec, EndianOrdering::Little);
            },

            ECPCurveShape::ShortWeierstrass => {
                let mut d = BigUint::zero();
                let mut count = 0;

                // Match the procedure given in RFC 6979 (deterministic ECDSA):
                // - use the same byte ordering;
                // - keep the leftmost nbits bits of the generated octet string;
                // - try until result is in the desired range.
                // This also avoids any bias, which is especially important for ECDSA.
                while d < BigUint::one() || d >= self.group.n {
                    d = primes::generate(&self.group.nbits);
                    d = d.shr(8 * n_size - self.group.nbits);

                    // Each try has at worst a probability 1/2 of failing (the msb has
                    // a probability 1/2 of being 0, and then the result will be < N),
                    // so after 30 tries failure probability is a most 2**(-30).
                    //
                    // For most curves, 1 try is enough with overwhelming probability,
                    // since N starts with a lot of 1s in binary, but some curves
                    // such as secp224k1 are actually very close to the worst case.
                    count += 1;

                    if count > 30 {
                        panic!("Short Weierstrass private value generation failed");
                    }
                }

                return d;
            }
        }
    }

    /// Check that an affine point is valid as a public key,
    /// Short weierstrass curves (SEC1 3.2.3.1)
    /// 
    /// * `point` - Point to check
    fn check_weierstrass_public_key(&self, point: &ECPPoint) -> (bool, &'static str) {
        if point.x.clone() < BigInt::zero()             || 
           point.y.clone().unwrap() < BigInt::zero()    ||
           point.x >= self.group.p.to_bigint().unwrap() ||
           point.y.clone().unwrap() >= self.group.p.to_bigint().unwrap()
        {
            return (false, "X and Y coords need to be normalized");
        }

        // YY = Y^2
        // RHS = X (X^2 + A) + B = X^3 + A X + B
        let y_squared = self.group.mod_p( &(point.y.clone().unwrap() * point.y.clone().unwrap()) );
        let mut rhs = self.group.mod_p( &(point.x.clone() * point.x.clone()) );

        // Special case for A = -3
        // NOTE handle A as a signed int
        if self.group.a.to_bigint().unwrap() == -3.to_bigint().unwrap() {
            rhs = self.group.mod_increase( &(rhs - 3.to_bigint().unwrap()) );
        } else {
            rhs = self.group.mod_reduce( &(rhs.clone() + self.group.a.to_bigint().unwrap()) );
        }

        rhs = self.group.mod_p( &(rhs.clone() * point.x.clone()) );
        rhs = self.group.mod_reduce( &(rhs.clone() + self.group.b.to_bigint().unwrap()) );

        if rhs != y_squared {
            return (false, "Y^2 != X (X^2 + A) + B = X^3 + A X + B");
        }

        (true, "")
    }
    
}


/*---- TESTS ----*/

#[cfg(test)]
mod ecc_test {

    use rand::OsRng;
    use utils::ecc::ECPKeypair;
    use utils::ecc_curves::ECPSupportedCurves;

    #[test]
    fn keypair_generation_bp256r1() {
        let mut rng = OsRng::new().unwrap();
        let ecc = ECPKeypair::new(ECPSupportedCurves::BP256R1).setup(&mut rng);
    }

    #[test]
    fn keypair_generation_bp384r1() {
        let mut rng = OsRng::new().unwrap();
        let ecc = ECPKeypair::new(ECPSupportedCurves::BP384R1).setup(&mut rng);
    }

    #[test]
    fn keypair_generation_bp521r1() {
        let mut rng = OsRng::new().unwrap();
        let ecc = ECPKeypair::new(ECPSupportedCurves::BP521R1).setup(&mut rng);
    }

    #[test]
    fn keypair_generation_curve25519() {
        let mut rng = OsRng::new().unwrap();
        let ecc = ECPKeypair::new(ECPSupportedCurves::Curve25519).setup(&mut rng);
    }

}