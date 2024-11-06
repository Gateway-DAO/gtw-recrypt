# Gateway Reencryption Computer

A Rust wrapper API for [IronCore Labs&#39; Recrypt](https://github.com/ironcorelabs/recrypt) library, providing a simplified interface for proxy re-encryption operations.

## Overview

This project provides a high-level wrapper around the Recrypt library, making it easier to integrate proxy re-encryption capabilities into Rust applications. It's organized as a workspace with multiple members:

-   `compute`: Core computer implementation (with gRPC server)
-   `recrypt`: Vendored fork of the IronCore Labs Recrypt library

## Prerequisites

-   Rust 1.75 or later
-   Cargo
-   System dependencies required by Recrypt

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
recrypt-compute = "0.1.0"
```

## Usage

Basic example of encrypting and re-encrypting data:

```rust
use recrypt_wrapper::{RecryptApi, EncryptionKey};

fn main() -> Result<(), Box<dyn Error>> {
    // Keys for encryption benchmark
    let (priv_key1, pub_key1) = new_encryption_keypair();
    let signing_keys = new_signing_keypair();

    let encrypted = encrypt(&data, &pub_key1, &signing_keys).unwrap();

    // Transform the encryption to second delegatee
    let (priv_key2, pub_key2) = new_encryption_keypair();
    let transform_key = new_transform_key(&priv_key1, &pub_key2, &signing_keys);
    let transformed = transform(encrypted, transform_key, &signing_keys);

    let decrypted = decrypt(&transformed, &priv_key2, size).unwrap();

    Ok(())
}
```

## API Documentation

For detailed API documentation, run:

```bash
cargo doc --open
```

## Project Structure

Clone the project and its submodules with the following

```
git submodule update --init --recursive
```

```
.
├── Cargo.toml
├── compute/  # library to host gRPC computer to proxy transform encryption operations
└── recrypt/  # https://github.com/Gateway-DAO/recrypt-rs
```

## Building

```bash
# Build all workspace members
cargo build

# Build specific member
cargo build -p compute
```

## Testing

```bash
# Run all tests
cargo test

# Run specific member tests
cargo test -p compute
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

-   [IronCore Labs](https://github.com/ironcorelabs) for the original Recrypt library
-   All contributors to this project

## Security

For security issues, please email [info@mygateway.xyz](mailto:info@mygateway.xyz) instead of opening a public issue.
