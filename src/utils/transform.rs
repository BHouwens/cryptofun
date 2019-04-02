/**
 * Flattens an array of chunk tuples that contain 
 * chunk slice data
 * 
 * `input` - Input to flatten
 */

pub fn flatten_chunks_with_chunk_data<T: Clone>(input: &Vec<(T, Vec<u8>)>) -> (Vec<T>, Vec<u8>) {
    let size = input.iter().fold(0, |a, b| a + b.1.len());
    
    let recoded_bytes = input.into_iter().fold(Vec::with_capacity(size), |mut acc, v| {
        acc.extend(v.1.clone()); acc
    });

    let chunk_slices = input.into_iter().fold(Vec::with_capacity(size), |mut acc, v| {
        acc.push(v.0.clone()); acc
    });

    (chunk_slices, recoded_bytes)
}


/**
 * Flatten an array of arrays of values
 * 
 * `input` - Input to flatten
 */

pub fn flatten_chunks<T: Clone>(input: &Vec<Vec<T>>) -> Vec<T> {
    let size = input.iter().fold(0, |a, b| a + b.len());
    input.into_iter().fold(Vec::with_capacity(size), |mut acc, v| {
        acc.extend(v.clone()); acc
    })
}


/**
 * Due to the inconsistency of the chunking in standard
 * Rust, an "exact" chunker is required
 * 
 * `full_input` - Input to chunk
 * `chunk_size` - Size of chunks
 */

pub fn get_exact_chunks<T: Clone>(full_input: &Vec<T>, chunk_size: &usize) -> Vec<Vec<T>> {
    let mut chunked_output = Vec::with_capacity((full_input.len() / chunk_size) + 1);
    let mut chunk = Vec::<T>::with_capacity(*chunk_size + 1);
    let mut counter = 1;

    for entry in full_input {
        chunk.push(entry.clone());

        if counter == *chunk_size {
            chunked_output.push(chunk.clone());
            chunk.clear();
            counter = 0;
        }

        counter += 1;
    }

    chunked_output
}


/**
 * Chunks the input for threading purposes
 * 
 * `input` - Input to chunk
 * `chunk_size` - Size of chunks
 */

pub fn chunk_for_threads(input: &Vec<u8>, chunk_size: usize) -> Vec<Vec<u8>> {
    let mut clone = input.clone();
    let mut return_vec = Vec::with_capacity((input.len() / chunk_size) + 1);

    while clone.len() > 0 {
        if clone.len() > chunk_size {
            let carry = clone.split_off(chunk_size);
            return_vec.push(clone);
            clone = carry;

        } else {
            return_vec.push(clone);
            break;
        }

    }

    return_vec
}