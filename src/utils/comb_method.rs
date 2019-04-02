/// Comb method multiplication is used as a means of preventing or mitigating
/// side channel attacks (SCAs) on elliptic curve cryptosystems, in particular 
/// side power attacks (SPAs) on embedded systems.
/// 
/// The basic comb method is described in GECC 3.44 as an example. We use a
/// modified version that provides resistance to SPAs by avoiding zero
/// digits in the representation as in:
/// 
/// HEDABOU, Mustapha, PINEL, Pierre, et B'EN'ETEAU, Lucien. A comb method to
/// render ECC resistant against Side Channel Attacks. IACR Cryptology
/// ePrint Archive, 2004, vol. 2004, p. 342.
/// <http://eprint.iacr.org/2004/342.pdf>

use rand::OsRng;

use num_integer::Integer;
use num_traits::{ One, Zero };
use num_bigint::{ BigUint, BigInt };

use utils::jacobian_coords;
use utils::ecc_curves::{ ECPGroup, ECPPoint };
use utils::encoding::{ EndianOrdering, biguint_to_bitvec };


/*---- CONSTANTS ----*/

/// ceil( n / w )
const COMB_MAX_D: usize = 257;

/// 1 << (WINDOW_SIZE - 1)
const MAX_PRECOMPUTED_POINTS: usize = 33;


/// Maximum "window" size used for point multiplication.
/// Default: 6.
/// Minimum value: 2. Maximum value: 7.
///
/// Result is an array of at most ( 1 << ( ECP_WINDOW_SIZE - 1 ) )
/// points used for point multiplication. This value is directly tied to EC
/// peak memory usage, so decreasing it by one should roughly cut memory usage
/// by two (if large curves are in use).
///
/// Reduction in size may reduce speed, but larger curves are impacted first.
/// Sample performances (in ECDHE handshakes/s, with FIXED_POINT_OPT = 1):
///      w-size:     6       5       4       3       2
///      521       145     141     135     120      97
///      384       214     209     198     177     146
///      256       320     320     303     262     226
///      224       475     475     453     398     342
///      192       640     640     633     587     476
const ECP_WINDOW_SIZE: usize = 6;


/// Trade memory for speed on fixed-point multiplication.
///
/// This speeds up repeated multiplication of the generator (that is, the
/// multiplication in ECDSA signatures, and half of the multiplications in
/// ECDSA verification and ECDHE) by a factor roughly 3 to 4.
///
/// The cost is increasing EC peak memory usage by a factor roughly 2.
///
/// Change this value to false to reduce peak memory usage.
const FIXED_POINT_OPT: bool = true;


/*---- FUNCTIONS ----*/


/// Basic fixed comb method
/// 
/// ### Arguments
/// 
/// * `d` - Fixed D size
/// * `w` - Comb size, i.e. number of teeth of the comb, and must be between
///         2 and 7 (in practice, between 2 and MBEDTLS_ECP_WINDOW_SIZE)
/// * `m` - Expected to be odd and such that bitlength(m) <= w/// d
///         (the result will be incorrect if these assumptions are not satisfied)
fn fixed_method(d: &usize, w: &usize, m: &BigUint) -> Vec<u8> {
    let mut x = vec![0; d + 1];
    let m_vec = biguint_to_bitvec(&m, EndianOrdering::Little);

    // First, get the classical comb values (except for x_d = 0)
    for i in 0..*d {
        for j in 0..*w {
            if (i + d * j) < m_vec.len() {
                x[i] = x[i].clone() | ((m_vec.get(i + d * j).unwrap() as u8) << j );
            }
        }
    }

    // Now make sure x_1 .. x_d are odd
    let mut c = 0;
    
    for i in 1..(*d + 1) {
        // Add carry and update it
        let cc = &x[i].clone() & &c;
        x[i] = &x[i].clone() ^ &c;
        c = cc.clone();

        // Adjust if needed, avoiding branches
        let adjust = 1 - (x[i].clone() & 1);
        c = c.clone() | (x[i].clone() & ( x[i-1].clone() * adjust.clone() ));
        x[i] = x[i].clone() ^ ( x[i-1].clone() * adjust.clone() );
        x[i-1] = x[i-1].clone() | (adjust.clone() << 7);
    }

    x
}


/// Multiplication (R = m * P) using the comb method,
/// for curves in short Weierstrass form. R is returned
/// 
/// ### Arguments
/// 
/// * `group` - Curve group to operate from
/// * `m` - M value
/// * `P` - P point
/// * `rng` - Random number generator
pub fn multiply(group: &mut ECPGroup, m: &BigUint, P: &ECPPoint, mut rng: &mut OsRng) -> ECPPoint {

    let mut p_equals_g = if P.x == group.g.x && P.y == group.g.y {
        true } else {
        false };

    let m_is_even = m.is_even();
    let w = get_window_size(&group.nbits, p_equals_g.clone());

    if !FIXED_POINT_OPT {
        p_equals_g = false;
    }

    // Other sizes that depend on w
    let pre_len = 1 << (w - 1);
    let d = (group.nbits + w - 1) / w;

    // Prepare precomputed points: if P == G we want to
    // use group.t if already initialized, or initialize it.
    let mut T = Vec::new();
    
    if p_equals_g {
        T = precompute(group, P, &w, &d);
    } else {
        T = group.t.clone();
    }

    // Make sure M is odd (M = m or M = N - m, since N is odd)
    // using the fact that m * P = - (N - m) * P
    let mut M = m.clone();

    if m_is_even {
        M = &group.n - m;
    }

    // Go for comb multiplication, R = M * P
    let k = fixed_method(&d, &w, &M);
    let mut R = core_multiplication(group, P, &M, &mut rng);

    // Now get m * P from M * P and normalize it
    if m_is_even {
        R = jacobian_coords::invert_point(group, &R);
    }

    if p_equals_g {
        group.t = T;
        group.t_size = pre_len;
    }

    jacobian_coords::normalize_point(group, &R)
}   

/// Core multiplication algorithm for the (modified) comb method.
/// This part is actually common with the basic comb method (GECC 3.44)
///
/// Cost: d A + d D + 1 R
/// 
/// `group` - Curve group to operate from
/// `T` - pre-computed points
/// `pre_len` - Length for point selection
/// `k` - Boolean selector over iterations
/// `d` - Iteration counter
/// `rng` - Random number generator
pub fn core_multiplication(
    group: &ECPGroup, 
    P: &ECPPoint,
    m: &BigUint,
    mut rng: &mut OsRng
) -> ECPPoint {

    // Start with a non-zero point and randomize its coordinates
    let mut R = ECPPoint::new( &BigInt::zero(), Some(BigInt::zero()) );
    R.z = BigInt::one();
    
    R = jacobian_coords::randomize_point(group, &R.clone(), &mut rng);
    let mut i = m.bits();
    let mut p_clone = P.clone();

    while i > 0 {
        R = jacobian_coords::double_point(group, &R);
        R = jacobian_coords::add(group, &R, &mut p_clone);

        i -= 1;
    }

    R
}

/// Minimize the number of multiplications in R = m * P, that is minimize
/// 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
/// (see costs of the various parts, with 1S = 1M)
/// 
/// ### Arguments
/// 
/// `nbits` - Bit size needed for calculation
/// `p_equals_g` - Whether the P and G points in original multiplication are equal
fn get_window_size(nbits: &usize, p_equals_g: bool) -> usize {
    let mut w = if nbits >= &384 {
        5 } else {
        4 };
    
    // If P == G, pre-compute a bit more, since this may be re-used later.
    // Just adding one avoids upping the cost of the first multi too much,
    // and the memory cost too.
    if FIXED_POINT_OPT {
        if p_equals_g {
            w += 1;
        }
    }
    
    // Make sure w is within bounds.
    // (The last test is useful only for very small curves in the test suite.)
    if w > ECP_WINDOW_SIZE {
        w = ECP_WINDOW_SIZE;
    }
    
    if w >= *nbits {
        w = 2;
    }

    w
}

/// Precompute points for the comb method
///
/// If i = i_{w-1} ... i_1 is the binary representation of i, then
/// T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
///
/// T must be able to hold 2^{w - 1} elements
///
/// Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
fn precompute(group: &ECPGroup, P: &ECPPoint, w: &usize, d: &usize) -> Vec<ECPPoint> {
    let mut T = vec![ECPPoint::new( &BigInt::zero(), Some(BigInt::zero()) ); MAX_PRECOMPUTED_POINTS + 1];
    let mut i = 1;

    // Set T[0] = P and
    // T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
    T[0] = P.clone();

    let mut k = 1;
    while i < (1 << (w - 1)) {
        T[i] = T[i >> 1].clone();
        let mut calc_value = T[i].clone();
        
        for j in 0..*d {
            calc_value = jacobian_coords::double_point(group, &calc_value); 
        }

        T[k] = calc_value.clone();

        k += 1;
        i <<= 1;
    }

    jacobian_coords::normalize_many(group, &mut T);

    // Compute the remaining ones using the minimal number of additions
    // Be careful to update T[2^l] only after using it!
    let mut j = 0;
    i = 1;
    k = 1;

    while i < (1 << (w - 1)) {
        j = i;

        while j > 0 {
            T[i + j] = jacobian_coords::add(group, &T[j].clone(), &mut T[i].clone());
            T[k] = T[i + j].clone();

            j -= 1;
            k += 1;
        }

        i <<= 1;
    }

    jacobian_coords::normalize_many(group, &mut T);

    T
}

/// Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]. R is returned
/// 
/// ### Arguments
/// 
/// `group` - Curve group to operate from
/// `T` - Vector precomputed points
/// `i` - "i" value in calculation
fn select(group: &ECPGroup, T: &Vec<ECPPoint>, i: usize) -> ECPPoint {
    let mut R = ECPPoint::new( &BigInt::zero(), Some(BigInt::zero()) );

    // ignore signing and scale down
    let ii = ( i & 127 ) >> 1;

    // Read the whole table to thwart cache-based timing attacks
    for j in 0..T.len() {
        if j == ii {
            R.x = T[j].x.clone();
            R.y = Some(T[j].y.clone().unwrap());
        }
    }

    // Safely invert result if i is "negative"
    if i >> 7 == 0 {
        R = jacobian_coords::invert_point(group, &R);
    }

    R
}