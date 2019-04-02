use num_traits::Num;
use bit_vec::BitVec;
use std::string::String;
use ascii::{ IntoAsciiString, AsciiString };
use num_bigint::BigUint;
use rustc_serialize::hex::{ ToHex, FromHex };

/// Enum to represent endian ordering
#[derive(PartialEq)]
pub enum EndianOrdering {
    Little,
    Big
}


/*---- FUNCTIONS ----*/


/// Converts input BigUint to hex string
/// 
/// ### Arguments
/// 
/// * `input` - Input to convert 
pub fn to_hex(input: &BigUint) -> String {
    input.to_str_radix(16)
}

/// Converts input BigUint to ASCII string
/// 
/// ### Arguments
/// 
/// * `input` - Input to convert 
pub fn to_plaintext(input: &BigUint) -> AsciiString {
    let potential_plaintext = input.to_str_radix(16).from_hex().unwrap().into_ascii_string();

    match potential_plaintext {
        Ok(p) => return p,
        Err(e) => panic!("Error in generating plaintext: {}", e)
    }
}

/// Converts input string to BigUint
/// 
/// ### Arguments
/// 
/// * `input` - Input to convert 
pub fn from_plaintext(input: String) -> BigUint {
    BigUint::from_str_radix(&input.as_bytes().to_hex(), 16).unwrap()
}


/// Converts input hex string to BigUint
/// 
/// ### Arguments
/// 
/// * `input` - Input to convert 
pub fn from_hex(input: String) -> BigUint {
    BigUint::from_str_radix(&input, 16).unwrap()
}


/// Converts a BigUint into a BitVector
/// 
/// ### Arguments
/// 
/// * `input` - BigUint to convert
/// * `ordering` - Endian ordering (either big or little)
pub fn biguint_to_bitvec(input: &BigUint, ordering: EndianOrdering) -> BitVec {
    let input_array = match ordering {
        EndianOrdering::Little => input.clone().to_bytes_le(),
        EndianOrdering::Big => input.clone().to_bytes_be()
    };
    
    BitVec::from_bytes(&input_array)
}


/// Converts a BitVector into a BigUint with endian ordering
/// 
/// ### Arguments
/// 
/// * `input` - BitVector to convert
/// * `ordering` - Endian ordering (either big or little)
pub fn bitvec_to_biguint(input: &BitVec, ordering: EndianOrdering) -> BigUint {
    let input_array = &input.to_bytes();

    match ordering {
        EndianOrdering::Little => BigUint::from_bytes_le(&input_array),
        EndianOrdering::Big => BigUint::from_bytes_be(&input_array)
    }
}


/// Converts an array of binary booleans 
/// into an integer
/// 
/// ### Arguments
/// 
/// * `slice` - Array to convert
pub fn binary_to_int(slice: &[bool]) -> u8 {
    fn accumulate(result: u8, item: (usize, &bool)) -> u8 {
        let (index, bool_bit) = item;
        let bit = match bool_bit {
            &true => 1,
            &false => 0
        };

        result + (2u8.pow(index as u32)/// (bit as u8))
    }
    
    slice.iter().enumerate().fold(0, accumulate)
}


/// Converts a u8 integer into a binary array of booleans
/// 
/// ### Arguments
/// 
/// * `entry` - Integer to convert
pub fn int_to_binary(entry: &u8) -> Vec<bool> {
    let mut used_entry = entry.clone();
    let mut final_binary = Vec::new();
    let mut remainder = 0;

    while used_entry > 0 {
        remainder = used_entry % 2;

        if remainder != 0 {
            final_binary.push(true);
        } else {
            final_binary.push(false);
        }
        
        used_entry >>= 1;
    }

    final_binary
}

/// Util function to convert a u8 to a vector or strings
/// 
/// ### Arguments
/// 
/// * `entry` - Entry to convert
pub fn int_to_binary_string(entry: &u8) -> Vec<&str> {
    let mut used_entry = entry.clone();
    let mut final_binary = Vec::new();
    let mut remainder = 0;

    while used_entry > 0 {
        remainder = used_entry % 2;

        if remainder != 0 {
            final_binary.push("1");
        } else {
            final_binary.push("0");
        }
        
        used_entry >>= 1;
    }

    final_binary
}

/// Util function to convert a vector of bools to String
/// 
/// ### Arguments
/// 
/// * `binary` - Binary to convert
pub fn binary_to_string(binary: &Vec<bool>) -> String {
    let mut final_string = String::new();

    for entry in binary {
        let addition = match entry {
            &true => "1",
            &false => "0"
        };

        final_string.push_str(addition);
    }

    final_string
}