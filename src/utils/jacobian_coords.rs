/**
 * A util library used for Jacobian coordinate math.
 * 
 * Jacobian Coordinates are used to represent elliptic curve 
 * points on prime curves y^2 = x^3 + ax + b. They give a speed 
 * benefit over Affine Coordinates when the cost for field inversions 
 * is significantly higher than field multiplications. In Jacobian 
 * Coordinates the triple (X, Y, Z) represents the affine point (X / Z^2, Y / Z^3).
 */

use rand::OsRng;
use std::ops::{ Shr, Shl, Mul, Sub, Add };

use num_bigint::{ BigUint, BigInt, ToBigInt };
use num_traits::{ One, Zero, Signed };

use utils::primes;
use utils::ecc_curves::{ ECPPoint, ECPGroup };


/**
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, or timing attacks.
 *
 * Normalize Jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 * 
 * `group` - Curve group to operate from
 * `point` - Point to normalize coords from
 */

pub fn normalize_point(group: &ECPGroup, point: &ECPPoint) -> ECPPoint {
    let mut new_point = point.clone();
    
    if point.z == BigInt::zero() {
        return new_point;
    }

    // X = X / Z^2  mod p
    let z_i = primes::modular_inverse_int(&point.z, &group.p.to_bigint().unwrap());
    let zz_i = group.mod_p( &(&z_i * &z_i) );
    new_point.x = group.mod_p( &(&point.x * &zz_i) );

    // Y = Y / Z^3  mod p
    let y_i = group.mod_p( &(&point.y.clone().unwrap() * &zz_i) );
    new_point.y = Some( group.mod_p( &(&y_i * &z_i) ).abs() );

    // Z = 1
    new_point.z = BigInt::one();

    new_point
}


/**
 * Normalize jacobian coordinates of an array of points. Original source
 * code contains a potentially more efficient implementation, which is worth
 * inspecting at a later date
 * 
 * `group` - Curve group to operate from
 * `points` - Vector of points to normalize
 */

pub fn normalize_many(group: &ECPGroup, points: &mut Vec<ECPPoint>) -> () {
    for i in 0..points.len() {
        points[i] = normalize_point(group, &points[i]);
    }
}


/**
 * Conditional point inversion: Point (Q) -> -Point = (Point.X, -Point.Y, Point.Z). 
 * Uses the fact that -Point.Y mod P = P - Point.Y unless Point.Y == 0
 * 
 * `group` - Curve group to operate from
 */

pub fn invert_point(group: &ECPGroup, point: &ECPPoint) -> ECPPoint {
    let mut new_point = point.clone();
    let y_clone = new_point.y.clone().unwrap();

    if &y_clone != &BigInt::zero() {
        new_point.y = Some( group.p.to_bigint().unwrap().sub(&y_clone) ); // might need to remove abs
    }

    new_point
}


/**
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
* in original TLS implementation.
*
* Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
*
* Cost: 1D := 3M + 4S          (A ==  0)
*             4M + 4S          (A == -3)
*             3M + 6S + 1a     otherwise
* 
* `group` - Curve group to operate from
* `R` - R point
* `P` - P point
*/

pub fn double_point(group: &ECPGroup, P: &ECPPoint) -> ECPPoint {
    let mut new_point = ECPPoint::new( &BigInt::zero(), Some(BigInt::zero()) );
    let mut T = BigInt::zero();
    let mut U = BigInt::zero();

    // TODO: Handle Special case for A = -3
    // --- Start alternate conditional

    // M = 3.X^2
    let mut S = group.mod_p(&P.x.clone().mul(&P.x));
    let mut M = group.mod_reduce( &S.clone().mul(&3.to_bigint().unwrap()) );

    if &group.a != &BigUint::zero() {
        // M += A.Z^4
        S = group.mod_p( &P.z.clone().mul(&P.z.clone()) );
        T = group.mod_p( &S.clone().mul(S.clone()) );
        S = group.mod_p( &T.clone().mul(&group.a.to_bigint().unwrap()) );
        M = group.mod_reduce( &M.clone().add(S.clone()) );
    }
    // --- End alternate conditional

    // S = 4.X.Y^2
    T = group.mod_p( &P.y.clone().unwrap().mul(&P.y.clone().unwrap()) );
    T = group.mod_reduce( &T.clone().shl(1) );
    S = group.mod_p( &P.x.clone().mul(T.clone()) );
    S = group.mod_reduce( &S.shl(1) );

    // U = 8.Y^4
    U = group.mod_p( &T.clone().mul(T.clone()) );
    U = group.mod_reduce( &U.clone().shl(1) );

    // T = M^2 - 2.S
    T = group.mod_p( &M.clone().mul(M.clone()) );
    T = group.mod_increase( &T.clone().sub(S.clone()) );
    T = group.mod_increase( &T.clone().sub(S.clone()) );

    // S = M(S - T) - U
    S = group.mod_increase( &S.clone().sub(T.clone()) );
    S = group.mod_p( &S.clone().mul(M.clone()) );
    S = group.mod_increase( &S.clone().sub(U.clone()) );

    // U = 2.Y.Z
    U = group.mod_p( &P.y.clone().unwrap().mul(&P.z.clone()) );
    U = group.mod_reduce( &U.clone().shl(1) );

    // Assign to R
    new_point.x = T.clone();
    new_point.y = Some(S.clone());
    new_point.z = U.clone();

    new_point
}


/**
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step:
 * 
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * 
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * 
 * So branches for these cases do not leak secret information.
 *
 * Cost: 1A := 8M + 3S
 * 
 * `group` - Curve group to operate from
 * `P` - P point
 * `Q` - Q point
 */

pub fn add(group: &ECPGroup, P: &ECPPoint, mut Q: &mut ECPPoint) -> ECPPoint {
    // Trivial cases: P == 0 or Q == 0 (case 1)
    if P.z == BigInt::zero() {
        return Q.clone();
    }

    if Q.z == BigInt::zero() {
        return P.clone();
    }

    // Make sure Q coordinates are normalized
    if Q.z != BigInt::one() {
        normalize_point(group, &mut Q);
    }

    let mut t_1 = group.mod_p( &P.z.clone().mul(&P.z) );
    let mut t_2 = group.mod_p( &t_1.clone().mul(&P.z) );
    
    t_1 = group.mod_p( &t_1.clone().mul(&Q.x.clone()) );
    t_2 = group.mod_p( &t_2.clone().mul(&Q.y.clone().unwrap()) );
    t_1 = group.mod_increase( &t_1.clone().sub(&P.x.clone()) );
    t_2 = group.mod_increase( &t_2.clone().sub(&P.y.clone().unwrap()) );


    // All other cases
    let z = group.mod_p( &P.z.clone().mul(t_1.clone()) );
    let mut t_3 = group.mod_p( &t_1.clone().mul(t_1.clone()) );
    let mut t_4 = group.mod_p( &t_3.clone().mul(t_1.clone()) );

    t_3 = group.mod_p( &t_3.clone().mul(&P.x) );
    t_1 = group.mod_reduce( &t_3.clone().mul(&2.to_bigint().unwrap()) );

    let mut x = group.mod_p( &t_2.clone().mul(t_2.clone()) );
    x = group.mod_increase( &x.clone().sub(t_1.clone()) );
    x = group.mod_increase( &x.clone().sub(t_4.clone()) );
    t_3 = group.mod_increase( &t_3.clone().sub(x.clone()) );
    t_3 = group.mod_p( &t_3.clone().mul(t_2.clone()) );
    t_4 = group.mod_p( &t_4.clone().mul(&P.y.clone().unwrap()) );

    let y = group.mod_increase( &t_3.clone().sub(t_4.clone()) );

    ECPPoint {
        x: x.clone(),
        y: Some(y.clone()),
        z: z.clone()
    }
}


/**
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of normalize_point().
 * 
 * This is a security countermeasure implemented as in:
 * 
 * CORON, Jean-S'ebastien. Resistance against differential power analysis
 * for elliptic curve cryptosystems. In: Cryptographic Hardware and
 * Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 * <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 * 
 * `group` - Curve group to operate from
 * `P` - point to randomize
 * `rng` - Random number generator
 */

pub fn randomize_point(group: &ECPGroup, P: &ECPPoint, mut rng: &mut OsRng) -> ECPPoint {
    let mut new_point = P.clone();
    let p_size = &group.p.bits();
    let mut l = primes::generate(&p_size).to_bigint().unwrap();

    // Generate l such that 1 < l < p
    if l >= group.p.to_bigint().unwrap() {
        while l >= group.p.to_bigint().unwrap() {
            l = l.shr(1);
        }
    }

    // Z = l * Z
    new_point.z = group.mod_p( &P.z.clone().mul(&l) );

    // X = l^2 * X
    let l_squared = l.clone().mul(&l);
    new_point.x = group.mod_p( &P.x.clone().mul(&l_squared) );

    // Y = l^3 * Y
    let l_cubed = l_squared.clone().mul(&l).to_bigint().unwrap();
    new_point.y = Some( group.mod_p( &P.y.clone().unwrap().mul(&l_cubed) ) );

    new_point
}