# Cryptofun

A small cryptographic library in Rust, built for fun to get some fundamental understanding of certain cryptographic methods. This is a re-upload of an old repo. If you've found this because you're looking for good, well maintained Rust libraries for crypto stuff check out the following instead:

## Cryptography 

[Sodium Oxide](https://github.com/sodiumoxide/sodiumoxide), a Rust library with bindings to C's *libsodium*. The documentation and maintenance is the most mature and robust in Rust, and comes with the following:

- **Public key signing** through ECC Ed25519 curve (Edwards curves being preferred for signing)
- **Public key encryption** through a Curve25519 Salsa20 Poly1305 setup
- **Secret key encryption** through a bunch of options (ChaCha20, Salsa20 and variations)

..

## Hashing

I could put a list here but I can't do a better job than the one done on this [repo](https://github.com/RustCrypto/hashes#supported-algorithms), which has a full and comprehensive list of pure Rust implementations along with cryptanalytic progress at industry level.

..

### TODO

- Implement post-quantum RingLWE to a working degree