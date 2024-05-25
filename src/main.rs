//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When we have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn ungroup(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut ungrouped = Vec::new();
    for block in blocks.iter() {
        ungrouped.extend_from_slice(block);
    }
    ungrouped
}

/// Does the opposite of the pad function.
fn unpad(data: Vec<u8>) -> Vec<u8> {
    let padded_elements: usize = data[data.len() - 1].into();
    data[..data.len() - padded_elements].to_vec()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let mut grouped = group(pad(plain_text));
    // We apply the encryption for every group
    grouped.iter_mut().for_each(|x| *x = aes_encrypt(*x, &key));
    grouped.into_iter().flat_map(|group| group).collect()
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let blocks_n = cipher_text.len() / BLOCK_SIZE;
    let mut answer = Vec::new();
    for i in 0..blocks_n {
        let mut block_array = [0; BLOCK_SIZE];
        block_array.copy_from_slice(&cipher_text[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
        let decrypted = aes_decrypt(block_array, &key);
        if i == blocks_n - 1 {
            // last one have padding
            answer.extend_from_slice(&unpad(decrypted.to_vec()));
        } else {
            answer.extend_from_slice(&decrypted);
        }
    }
    answer
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure    , and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
///
///

fn xor_vecs(vec1: &[u8; BLOCK_SIZE], vec2: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = vec1[i] ^ vec2[i];
    }
    result
}

use rand::{thread_rng, Rng};
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.
    let mut iv: [u8; 16] = [0u8; BLOCK_SIZE];
    let mut rng = thread_rng();
    rng.fill(&mut iv);

    // pad and group te plain text
    let grouped = group(pad(plain_text));

    let mut encrypted = Vec::new();

    // We send the encripted IV in a first block
    let mut current_encrypted_block = aes_encrypt(iv, &key);
    encrypted.extend_from_slice(current_encrypted_block.as_slice());

    for (index, block) in grouped.iter().enumerate() {
        match index {
            0 => {
                // the first one is xored with the IV
                current_encrypted_block = aes_encrypt(xor_vecs(&iv, &block), &key);
                encrypted.extend_from_slice(current_encrypted_block.as_slice());
            }
            _ => {
                // all the rest are xored with the previous block
                current_encrypted_block = aes_encrypt(
                    xor_vecs(
                        &current_encrypted_block.as_slice().try_into().unwrap(),
                        &block,
                    ),
                    &key,
                );
                encrypted.extend_from_slice(current_encrypted_block.as_slice());
            }
        }
        // println!("current_encrypted_block: {:?}", current_encrypted_block);
    }

    println!("iv: {:?}", iv);
    println!("grouped: {:?}", grouped);
    println!("encrypted: {:?}", encrypted);
    encrypted
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut grouped: Vec<[u8; BLOCK_SIZE]> = Vec::new();

    for group in cipher_text.chunks_exact(BLOCK_SIZE) {
        let mut group_array = [0u8; BLOCK_SIZE];
        group_array.copy_from_slice(group);
        grouped.push(group_array);
    }
    // we group in blocks of BLOCK_SIZE
    // let grouped: Vec<Vec<u8>> = cipher_text.chunks_exact(BLOCK_SIZE).map(|chunk| chunk.to_vec()).collect();

    // The first block has the IV
    let mut decrypted = Vec::new();
    let mut current_cipher_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE]; // this current value is never used
                                                                      // let grouped = cipher_text.chunks_exact(BLOCK_SIZE);
    let iv = aes_decrypt(grouped[0], &key);
    // println!("grouped: {:?}", grouped);
    // println!("grouped[1..grouped.len()-1].iter().enumerate(): {:?}", grouped[1..grouped.len()-1].iter().enumerate());
    for (index, block) in grouped[1..grouped.len()].iter().enumerate() {
        // println!("index: {:?}", index);
        // println!("block: {:?}", block);
        match index {
            0 => {
                // the first block should be xored with the the IV
                let decrypted_xored = aes_decrypt(*block, &key);
                decrypted.extend_from_slice(xor_vecs(&iv, &decrypted_xored).as_slice());
                current_cipher_block = *block; //s.try_into().expect("Slice length must be 16 bytes");
            }
            _ => {
                let decrypted_xored = aes_decrypt(*block, &key);
                decrypted.extend_from_slice(
                    xor_vecs(&current_cipher_block, &decrypted_xored).as_slice(),
                );
                current_cipher_block = *block;
            }
        }
    }

    // println!("iv: {:?}", iv);
    // println!("grouped: {:?}", grouped);
    // println!("decrypted: {:?}", decrypted);
    unpad(decrypted)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    let mut iv: [u8; BLOCK_SIZE / 2] = [0u8; BLOCK_SIZE / 2];
    let mut rng = thread_rng();
    rng.fill(&mut iv);

    // pad and group te plain text
    let grouped = group(pad(plain_text));
    let mut encrypted = Vec::new();
    let mut nonce_counter: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for (index, block) in grouped.iter().enumerate() {
        let counter: [u8; BLOCK_SIZE / 2] = [index as u8; BLOCK_SIZE / 2];

        let mut concat_vec = Vec::new();
        concat_vec.extend_from_slice(&iv);
        concat_vec.extend_from_slice(&counter);
        nonce_counter.copy_from_slice(&concat_vec);

        // let nonce_counter: [u8; 16]  = [&iv[..], &counter[..]].concat();
        let encrypted_nonce_counter = aes_encrypt(nonce_counter, &key);
        match index {
            0 => {
                // // The first Nonce | COUNTER is passed as the first block of the ciphertext
                // However here cannot be sent encripted
                encrypted.extend_from_slice(&nonce_counter);
                encrypted.extend_from_slice(xor_vecs(&encrypted_nonce_counter, &block).as_slice());
            }
            _ => {
                encrypted.extend_from_slice(xor_vecs(&encrypted_nonce_counter, &block).as_slice());
            }
        }
    }
    encrypted
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut grouped: Vec<[u8; BLOCK_SIZE]> = Vec::new();

    for group in cipher_text.chunks_exact(BLOCK_SIZE) {
        let mut group_array = [0u8; BLOCK_SIZE];
        group_array.copy_from_slice(group);
        grouped.push(group_array);
    }

    let mut decrypted = Vec::new();

    // The first block has the nonce
    let nonce: &[u8] = &grouped[0][0..BLOCK_SIZE / 2];
    let mut nonce_counter: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for (index, block) in grouped[1..grouped.len()].iter().enumerate() {
        println!("index {:?}", index);
        let counter: [u8; BLOCK_SIZE / 2] = [index as u8; BLOCK_SIZE / 2];
        let mut concat_vec = Vec::new();
        concat_vec.extend_from_slice(&nonce);
        concat_vec.extend_from_slice(&counter);
        nonce_counter.copy_from_slice(&concat_vec);

        let nonce_counter_encrypted: [u8; 16] = aes_encrypt(nonce_counter, &key);
        decrypted.extend_from_slice(xor_vecs(&block, &nonce_counter_encrypted).as_slice());
    }
    unpad(decrypted)
}

/// This function is not graded. It is just for collecting feedback.
/// On a scale from 0 - 100, with zero being extremely easy and 100 being extremely hard, how hard
/// did you find the exercises in this section?
pub fn how_hard_was_this_section() -> u8 {
    70
}

/// This function is not graded. It is just for collecting feedback.
/// About how much time (in hours) did you spend on the exercises in this section?
pub fn how_many_hours_did_you_spend_on_this_section() -> f32 {
    5.0
}

#[cfg(test)]
mod optional_tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        6, 108, 74, 203, 170, 212, 94, 238, 171, 104, 19, 17, 248, 197, 127, 138,
    ];

    #[test]
    #[cfg_attr(not(feature = "optional-tests"), ignore)]
    fn ungroup_test() {
        let data: Vec<u8> = (0..48).collect();
        let grouped = group(data.clone());
        let ungrouped = ungroup(grouped);
        assert_eq!(data, ungrouped);
    }

    #[test]
    #[cfg_attr(not(feature = "optional-tests"), ignore)]
    fn unpad_test() {
        // An exact multiple of block size
        let data: Vec<u8> = (0..48).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);

        // A non-exact multiple
        let data: Vec<u8> = (0..53).collect();
        let padded = pad(data.clone());

        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);
    }

    #[test]
    #[cfg_attr(not(feature = "optional-tests"), ignore)]
    fn ecb_encrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let encrypted = ecb_encrypt(plaintext, TEST_KEY);
        assert_eq!(
            "12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555".to_string(),
            hex::encode(encrypted)
        );
    }

    #[test]
    #[cfg_attr(not(feature = "optional-tests"), ignore)]
    fn ecb_decrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext =
            hex::decode("12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555")
                .unwrap();
        println!("plaintext, {:?}", plaintext);
        println!("ciphertext, {:?}", ciphertext);
        assert_eq!(plaintext, ecb_decrypt(ciphertext, TEST_KEY))
        // assert_eq!(0, 1)
    }

    #[test]
    #[cfg_attr(not(feature = "optional-tests"), ignore)]
    fn cbc_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = cbc_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = cbc_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = cbc_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }

    #[test]
    #[cfg_attr(not(feature = "optional-tests"), ignore)]
    fn ctr_roundtrip_test() {
        // Because CTR uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = ctr_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = ctr_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = ctr_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }
}
