use utils::encoding::{ int_to_binary, binary_to_int };

/**
 * The Knuth-Yao sampling algorithm is an extremely useful scheme for 
 * fast and efficient discrete Gaussian sampling. It is primarily based 
 * on the random-bit model and, on average, uses a near optimal number of 
 * random bits.
 *
 * This is useful when implementing the sampler for LWE schemes. Lookup 
 * tables are used to accelerate the sampling algorithm in the most frequently 
 * used regions of the Gaussian distribution. This allows sampling at an
 * average of 28.5 cycles per sample.
 * 
 * This implementation is a pure Rust translation of the algorithm found within 
 * "Efficient Software Implementation of Ring-LWE Encryption", which can be found here: 
 * https://eprint.iacr.org/2014/725.pdf
 * 
 * as well as the accompanying code written in C, which can be found here: 
 * https://github.com/ruandc/Ring-LWE-Encryption
 */


/*----- CONSTANTS -----*/

pub const LOW_MSB: u8 = 26;
pub const HAMMING_TABLE_SIZE: u8 = 10;
pub const PMAT_MAX_COL: u8 = 106;
pub const KN_DISTANCE1_MASK: u8 = 15;
pub const KN_DISTANCE2_MASK: u8 = 15;

pub const MODULUS: u32 = 12289;
pub const M: u32 = 512;
pub const QBY2: u32 = 6144;
pub const QBY4: u32 = 3072;
pub const QBY4_TIMES3: u32 = 9216;

pub const FWD_CONST1: u32 = 5559;
pub const FWD_CONST2: u32 = 6843;

pub const INVCONST1: u32 = 3778;
pub const INVCONST2: u32 = 10810;
pub const INVCONST3: u32 = 9087;
pub const SCALING: u32 = 12265;

pub const LOOKUP_TABLE_1: [u32; 256] = [
    3,4,1,1,2,8,6,11,3,0,1,7,2,5,5,11,3,4,1,10,2,7,6,6,3,0,1,2,2,4,5,17,3,4,1,1,2,8,6,8,3,0,1,4,2,5,5,4,3,4,1,9,
	2,7,6,2,3,0,1,0,2,4,5,21,3,4,1,1,2,8,6,9,3,0,1,7,2,5,5,9,3,4,1,10,2,7,6,3,3,0,1,2,2,4,5,19,3,4,1,1,2,8,6,7,3,
	0,1,4,2,5,5,0,3,4,1,9,2,7,6,13,3,0,1,0,2,4,5,23,3,4,1,1,2,8,6,11,3,0,1,7,2,5,5,10,3,4,1,10,2,7,6,6,3,0,1,2,2,
	4,5,18,3,4,1,1,2,8,6,8,3,0,1,4,2,5,5,1,3,4,1,9,2,7,6,2,3,0,1,0,2,4,5,22,3,4,1,1,2,8,6,9,3,0,1,7,2,5,5,6,3,4,1,
	10,2,7,6,3,3,0,1,2,2,4,5,20,3,4,1,1,2,8,6,7,3,0,1,4,2,5,5,16,3,4,1,9,2,7,6,12,3,0,1,0,2,4,5,24
];


/**
 * Perform Knuth-Yao sample over the length 
 * of the provided vectors
 * 
 * `first` - First vector to sample over
 * `second` - Second vector to sample over
 */

pub fn sample_over_vec(first: &mut Vec<bool>, second: &mut Vec<bool>) {
    let rand = 0; // replace with randomly generate u32 (although 0 works as well)

    for i in 0..128 {
        first[i] = smaller_tables_single_number(&rand);
        second[i] = smaller_tables_single_number(&rand);
    }
}


/**
 * Generates a smaller lookup table based on a 
 * provided value "a", editing "a" in place
 * 
 * `a` - Value to generate table for
 */

pub fn smaller_tables(a: &u32) -> u32 {
    let rand = 0; // replace with randomly generate u32 (although 0 works as well)
    let mut binary = int_to_binary(a);

    for i in 0..(M / 2) {
        let i_usize = i as usize;

        binary[2 * i_usize + 1] = smaller_tables_single_number(&rand);
        binary[2 * i_usize] = smaller_tables_single_number(&rand);
    }

    binary_to_int(&binary)
}


/**
 * Generate a lookup bit for a single number
 * 
 * `value` - Random value for calculation
 */

fn smaller_tables_single_number(value: &u32) -> bool {
    if value == &0 {
        return false;
    }

    let idx = value & 255;
    let new_value = *value >> 8;
    let mut sample = LOOKUP_TABLE_1[idx as usize];
    let sample_msb = sample & 16;

    // Lookup was successful
    if sample_msb == 0 {
        sample = sample & 15;

        if new_value & 1 != 1 {
            sample = MODULUS - sample;
        }

        return match sample {
            1 => true,
            _ => false
        };

    } else {
        // TODO: Implement unsuccessful lookup
    }

    false
}

