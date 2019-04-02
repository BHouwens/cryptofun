use rand::OsRng;
use std::ops::{ Shl, BitXor, Rem, Shr };

use num_integer::Integer;
use num_traits::{ One, Zero, ToPrimitive };
use num_bigint::{ BigUint, ToBigInt, BigInt, RandBigInt };

const LARGE_THRESHOLD: usize = 25;


/*-------- PUBLIC FUNCTIONS --------*/


/**
 * Generates a prime number
 *
 * `bitlength` - The bit length of the number
 */

pub fn generate(bitlength: &usize) -> BigUint {
    let mut generator = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Could not load OS RNG with error {}", e)
    };

    loop {
        let candidate = generate_random_biguint(&mut generator, bitlength);

        if (bitlength < &LARGE_THRESHOLD && is_small_prime(&candidate)) || 
           (bitlength >= &LARGE_THRESHOLD && is_large_prime(&candidate)) {
            return candidate;
        }
    }
}


/**
 * Generates a prime number that is safe for discrete log crypto
 *
 * `bitlength` - Bit length of prime number
 */

pub fn generate_discrete_log_prime(bitlength: &usize) -> BigUint {
    loop {
        let candidate = generate(bitlength);

        if is_discrete_log_safe(&candidate) {
            return candidate;
        }
    }
}


/** 
 * Checks for prime number safety by ensuring that 
 * "q" in "p = 2q + 1" is a Sophie Germain prime
 *
 * `candidate` - Candidate prime, the "p" in above equation
 */

fn is_discrete_log_safe(candidate: &BigUint) -> bool {
    let two = BigUint::one() + BigUint::one();
    let q = candidate.shr(1) - BigUint::one();

    if q.clone().rem(two) != BigUint::zero() {
        return is_large_prime(&q);
    }

    false
}


/** 
 * Gets the modular inverse for provided parameters using Extended Euclidean
 *
 * `a` - Value to apply EE to
 * `modulus` - Modulus for calculation
 */

pub fn modular_inverse(a: &BigUint, modulus: &BigUint) -> BigUint {
    let int_a = a.to_bigint().unwrap();
    let int_modulus = modulus.to_bigint().unwrap();

    let mut mn = (int_modulus.clone(), int_a.clone());
    let mut xy = (BigInt::zero(), BigInt::one());
 
    while mn.1 != BigInt::zero() {
        xy = (xy.1.clone(), xy.0.clone() - (mn.0.clone() / mn.1.clone()) * xy.1.clone());
        mn = (mn.1.clone(), mn.0.clone() % mn.1.clone());
    }
 
    while xy.0 < BigInt::zero() {
        xy.0 = xy.0.clone() + int_modulus.clone();
    }

    xy.0.to_biguint().unwrap()
}


/**
 * Gets the modular inverse for provided parameters using Extended Euclidean,
 * with a signed integer parameter expectation. Useful for Jacobian coordinate 
 * normalization
 * 
 * `a` - Value to apply EE to
 * `modulus` - Modulus for calculation
 */

pub fn modular_inverse_int(a: &BigInt, modulus: &BigInt) -> BigInt {
    let mut mn = (modulus.clone(), a.clone());
    let mut xy = (BigInt::zero(), BigInt::one());
 
    while mn.1 != BigInt::zero() {
        xy = (xy.1.clone(), xy.0.clone() - (mn.0.clone() / mn.1.clone()) * xy.1.clone());
        mn = (mn.1.clone(), mn.0.clone() % mn.1.clone());
    }
 
    while xy.0 < BigInt::zero() {
        xy.0 = xy.0.clone() + modulus.clone();
    }

    xy.0
}


/** 
 * Generates an optimised large number for primality testing
 *
 * `generator` - Random number generator
 * `bitlength` - Bit length for number
 */

pub fn generate_random_biguint(generator: &mut OsRng, bitlength: &usize) -> BigUint {
    let candidate:BigUint = generator.gen_biguint(bitlength - 1);
    let shifted_candidate = candidate.shl(1);
    let final_candidate = shifted_candidate.bitxor(BigUint::one());

    final_candidate
}


/*-------- PRIVATE FUNCTIONS --------*/


/**
 * Full, efficient check whether large candidate is prime
 *
 * `candidate` - Candidate to check
 */

fn is_large_prime(candidate: &BigUint) -> bool {
    if !fermat_little(candidate) {
        return false;
    }

    if !miller_rabin(candidate, 3) {
        return false;
    }

    true
}


/** 
 * Full check whether small candidate is prime
 *
 * `candidate` - Candidate to check
 */

fn is_small_prime(candidate: &BigUint) -> bool {
    let cast = candidate.clone().to_u64().unwrap();

    if cast < 2 {
        return false;

    } else if cast == 2 {
        return true;

    } else {
        let sqrt = (cast as f64).sqrt().abs();

        for i in 2..(sqrt as u64) {
            if cast % i == 0 {
                return false;
            }
        }
    }

    true
}


/** 
 * Checks whether a candidate is definitely composite
 * based on Fermat's little theorem
 * 
 * `candidate` - Candidate to check
 */

fn fermat_little(candidate: &BigUint) -> bool {
    let mut generator = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Could not load OS RNG with error {}", e)
    };

    let random:BigUint = generator.gen_biguint_below(candidate);
    let result = random.modpow(&(candidate - BigUint::one()), candidate);

    result == BigUint::one()
}


/**
 * Checks whether candidate is prime via Miller-Rabin test.
 * 3 iterations is considered secure at an error probability of 2^80
 *
 * `candidate` - Candidate to check
 * `iterations` - Number of iterations to perform
 */

fn miller_rabin(candidate: &BigUint, iterations: usize) -> bool {
    let (s, d) = greatest_2_divisor(candidate);
    let one = BigUint::one();
    let two = &one + &one;
    let mut generator = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Could not load OS RNG with error {}", e)
    };

    for _ in 0..iterations {
        let basis = generator.gen_biguint_range(&two, &(candidate - &two));
        let mut y = basis.modpow(&d, candidate);

        if y == one || y == (candidate - &one) {
            continue;
        } else {
            for _ in 0..s {
                y = y.modpow(&two, candidate);

                if y == one {
                    return false;
                } else if y == candidate - &one {
                    break;
                }
            }

            return false;
        }
    }

    true
}


/**
 * Util function for Miller-Rabin test
 *
 * `num` - Number to use
 */

fn greatest_2_divisor(num: &BigUint) -> (usize, BigUint) {
    let mut s = 0;
    let mut num = num - BigUint::one();

    while num.is_even() {
        num = num >> 1;
        s += 1
    }

    (s, num)
}