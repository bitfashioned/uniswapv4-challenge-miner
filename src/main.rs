use std::sync::{Arc, Mutex};
use num_cpus;
use rand::{thread_rng, Rng};
use tiny_keccak::{Hasher, Sha3};
use clap::Parser;

// Derive the address of a contract created using the CREATE2 opcode.
// Address: deployer address
// Salt: deployment salt
// Code_hash: keccak256 hash of the initcode
pub fn create2_addr(address: &[u8; 20], salt: &[u8; 32], code_hash: &[u8; 32]) -> [u8; 20] {
    let mut buf = [0; 85];

    buf[0] = 0xFF;
    buf[1..21].copy_from_slice(address);
    buf[21..53].copy_from_slice(salt);
    buf[53..85].copy_from_slice(code_hash);

    let mut hasher = Sha3::v256();
    hasher.update(&buf[..]);

    let mut out = [0; 32];
    hasher.finalize(&mut out);
    let mut result = [0; 20];
    result.copy_from_slice(&out[12..32]);
    result
}


// Compute address score according to Uniswap V4 Address Challenge Rules
// https://github.com/Uniswap/v4-periphery/blob/0bbf0dc09889e3bc34c7aa08962160a27ba4b340/src/libraries/VanityAddressLib.sol#L18
/*
    10 points for every leading 0 nibble
    40 points if the first 4 is followed by 3 more 4s
    20 points if the first nibble after the four 4s is NOT a 4
    20 points if the last 4 nibbles are 4s
    1 point for every 4
*/
pub fn compute_score(address: &[u8; 20]) -> u32 {
    let mut calculated_score = 0;
    let mut starting_zeros = true;
    let mut starting_fours = true;
    let mut first_four = true;
    let mut four_counts = 0;

    for i in 0..40 {
        let current_nibble = if i % 2 == 0 {
            (address[i / 2] >> 4) & 0x0F
        } else {
            address[i / 2] & 0x0F
        };

        if starting_zeros && current_nibble == 0 {
            calculated_score += 10;
            continue;
        } else {
            starting_zeros = false;
        }

        if starting_fours {
            if first_four && current_nibble != 4 {
                return 0;
            }

            if current_nibble == 4 {
                four_counts += 1;
                if four_counts == 4 {
                    calculated_score += 40;
                    if i == 39 {
                        calculated_score += 20;
                    }
                }
            } else {
                if four_counts == 4 {
                    calculated_score += 20;
                }
                starting_fours = false;
            }
            first_four = false;
        }

        if current_nibble == 4 {
            calculated_score += 1;
        }
    }

    if address[18] & 0x0F == 0x04 && address[19] & 0xF0 == 0x40 {
        calculated_score += 20;
    }

    calculated_score
}

const DEPLOYER_ADDRESS_HEX: &str = "48E516B34A1274f49457b9C6182097796D0498Cb";
const INITCODE_HASH_HEX: &str = "94d114296a5af85c1fd2dc039cdaa32f1ed4b0fe0868f02d888bfc91feb645d9";
const SUBMITTER_ADDRESS_HEX: &str = "b46B370a1A16B959bFF7d47010E256C50Db8330F";

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of threads to use (0 for all)
    #[arg(short, long)]
    threads: usize,
}


fn main() {
    let args = Args::parse();
    let max_threads = num_cpus::get();
    let num_threads = match args.threads {
        0 => max_threads,
        n => n,
    };

    let deployer: [u8; 20] = hex::decode(DEPLOYER_ADDRESS_HEX).expect("Decoding failed").try_into().expect("Incorrect length");
    let code_hash: [u8; 32] = hex::decode(INITCODE_HASH_HEX).expect("Decoding failed").try_into().expect("Incorrect length");
    let submitter: [u8; 20] = hex::decode(SUBMITTER_ADDRESS_HEX).expect("Decoding failed").try_into().expect("Incorrect length");
    let best_address = Arc::new(Mutex::new((deployer, 0)));

    println!("Running with {} threads", num_threads);

    let handles: Vec<_> = (0..num_threads).map(|i: usize| {
        let best_address = Arc::clone(&best_address);
        std::thread::spawn(move || {
            let mut rand: u64 = i as u64;
            let mut pepper = [0; 4];
            thread_rng().fill(&mut pepper);
            loop {
                let mut salt: [u8; 32] = [0; 32];
                salt[..20].copy_from_slice(&submitter);
                salt[20..24].copy_from_slice(&pepper);
                salt[24..].copy_from_slice(&rand.to_be_bytes());
                let address = create2_addr(&deployer, &salt, &code_hash);
                let score = compute_score(&address);
                let mut best = best_address.lock().unwrap();
                if score > best.1 {
                    *best = (address, score);
                    println!("New best address: 0x{} with score: {}, salt: 0x{}", hex::encode(best.0), best.1, hex::encode(salt));
                }
                rand += num_threads as u64;
            }
        })
    }).collect();

    for handle in handles {
        handle.join().unwrap();
    }
}
