/**
 * The Montgomery ladder approach computes the point multiplication in a 
 * fixed amount of time. This is required when performing multiplication, 
 * and generally working with values, for Montgomery curves because of 
 * the presence of side channel attacks (SCAs).
 */

#[allow(non_camel_case_types)]

use rand::OsRng;
use std::ops::Shr;

use num_traits::{ One, Zero, Signed, ToPrimitive };
use num_bigint::{ BigUint, BigInt, ToBigInt };

use utils::primes;
use utils::ecc_curves::{ ECPGroup, ECPPoint };
use utils::encoding::{ EndianOrdering, biguint_to_bitvec };


/**
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form. Essentially the R = m * P 
 * process, where R is returned. 
 * 
 * This implementation is not a translation of TLS's library, 
 * as their Montgomery ladder is prone to M-fault and cache 
 * Flush + Reload attacks. More information on this type of 
 * attack can be found here: 
 * https://link.springer.com/chapter/10.1007%2F978-3-662-44709-3_5
 * 
 * 
 * `group` - Curve group to operate from
 * `m` - M value in calculation
 * `P` - P point in calculation
 * `rng` - Random number generator
 */

pub fn multiply(group: &ECPGroup, m: &BigUint, P: &ECPPoint) -> ECPPoint {

    // Save PX and read from P before writing to R, in case P == R
    let PX = P.x.clone();
    let mut RP = P.clone();

    // Set R to double the generator P
    let mut R = double_point(group, &RP);
    let mut rng = OsRng::new().unwrap();
    R = randomize_point(group, &R, &mut rng);

    // Loop invariant: R = result so far, RP = R + P
    let mut i = m.bits();
    let mut point_selection = vec![R.clone(), RP.clone()];
    let m_bit_vec = biguint_to_bitvec(&m, EndianOrdering::Little);

    // Using pure arithmetic (vs conditional branching) avoids traditional
    // M-fault and flush + reload attacks
    while i > 0 {
        let d_i = ((m.clone() >> i) & BigUint::one()).to_usize().unwrap();
        point_selection[(d_i + 1) % 2] = add_points(group, &R, &RP, &PX);
        point_selection[d_i] = double_point(group, &point_selection[d_i]);

        i >>= 1;
    }

    let invert_z = invert(group, &point_selection[0].z);
    let final_value = (&point_selection[0].x * invert_z.to_bigint().unwrap()) % group.p.clone();
    let final_point = ECPPoint::new( &final_value, None );

    normalize_point(group, &final_point)
}


/**
 * Invert coordinate using P modulus
 * 
 * `group` - Curve group to operate from
 * `coordinate` - Coordinate to invert
 */

fn invert(group: &ECPGroup, coordinate: &BigInt) -> BigInt {
    let exponent = (group.p.clone() - 2.to_bigint().unwrap()).to_biguint().unwrap();
    let uint_modulus = group.p.to_biguint().unwrap();

    coordinate.to_biguint().unwrap().modpow(&exponent, &uint_modulus).to_bigint().unwrap()
}


/**
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * 
 * `group` - Curve group to operate from
 * `point` - Point to normalize
 */

fn normalize_point(group: &ECPGroup, point: &ECPPoint) -> ECPPoint {
    let mut new_point = point.clone();

    new_point.z = primes::modular_inverse_int(&point.z, &group.p.to_bigint().unwrap());
    new_point.x = group.mod_p( &(&point.x * &point.z) ).abs();
    new_point.z = BigInt::one();

    new_point
}


/**
 * Randomize projective x/z coordinates:
 * (X, Z) -> (l X, l Z) for random l
 *
 * This countermeasure was first suggested in:
 * CORON, Jean-S'ebastien. Resistance against differential power analysis
 * for elliptic curve cryptosystems. In : Cryptographic Hardware and
 * Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 * <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 * 
 * `group` - Curve group to operate from
 * `point` - Point to randomize
 * `rng` - Random number generator
 */

fn randomize_point(group: &ECPGroup, point: &ECPPoint, mut rng: &mut OsRng) -> ECPPoint {
    let mut new_point = point.clone();
    let mut l = primes::generate_random_biguint(&mut rng, &group.p.bits()).to_bigint().unwrap();

    if l >= group.p {
        while l >= group.p {
            l = l.shr(1);
        }
    }

    new_point.x = group.mod_p( &(&point.x * &l) );
    new_point.z = group.mod_p( &(&point.z * &l) );

    new_point
}


/**
 * Doubles a point on a Montgomery curve
 * 
 * `group` - Curve group to operate from
 * `point` - Point to double
 */

fn double_point(group: &ECPGroup, point: &ECPPoint) -> ECPPoint {
    let mut new_point = ECPPoint::new( &BigInt::zero(), None );
    let x_squared = &point.x * &point.x;
    let z_squared = &point.z * &point.z;

    // TODO: Split z change out into 2 calculations
    new_point.x = ((&x_squared - &z_squared) * (&x_squared - &z_squared)) % group.p.clone();
    new_point.z = (&4.to_bigint().unwrap() * &point.x * &point.z * (&x_squared + &group.a.to_bigint().unwrap() * &point.x * &point.z + &z_squared)) % group.p.clone();

    new_point
}


/**
 * Adds two points on a Montgomery curves together
 * 
 * `group` - Curve group to operate from
 * `first` - First point
 * `second` - Second point
 * `gx` - Generator's X coordinate
 */

pub fn add_points(group: &ECPGroup, first: &ECPPoint, second: &ECPPoint, gx: &BigInt) -> ECPPoint {
    let mut new_point = ECPPoint::new( &BigInt::zero(), None );
    let x_mult = (&second.x * &first.x - &second.z * &first.z);
    let z_mult = (&second.x * &first.z - &second.z * &first.x);

    new_point.x = (&4.to_bigint().unwrap() * &x_mult * &x_mult) % group.p.clone();
    new_point.z = (&4.to_bigint().unwrap() * &z_mult * &z_mult * gx) % group.p.clone();

    new_point
}
