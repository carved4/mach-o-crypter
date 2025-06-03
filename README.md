A Go-based implementation of a crypter for Mach-O binaries on macOS supporting ChaCha20-Poly1305, AES-GCM, and Twofish-GCM authenticated encryption, with zlib compression, CBOR payload packaging, and secure in-memory execution with anti-forensic features.

Feel free to open issues or DM with feedback or use cases!

## Overview
This project contains two components:

1. **crypt** - A tool to encrypt a Mach-O executable file using ChaCha20-Poly1305, AES-GCM, or Twofish-GCM authenticated encryption, and package it into a single CBOR payload:
    - Combines encrypted binary, key derivation parameters, and cryptographic material into a single file
    - Uses zlib compression to reduce payload size when beneficial
    - Uses CBOR (Concise Binary Object Representation) for compact, non-textual storage
    - Embeds Argon2 parameters for future-proofing and versioning

2. **stub** - A Go binary that embeds, decrypts, and executes the encrypted Mach-O binary using a secure execution flow:
    - Detects CPU architecture at runtime (ARM64/x86_64)
    - Decrypts and decompresses (if compressed) the binary in memory with memory protection (mlock, MADV_NOCORE)
    - Drops the decrypted binary to a secure location in user cache directories
    - Executes it using syscall.Exec with proper environment variables
    - Implements anti-forensic techniques for file deletion
    - Uses stealthy logging to avoid system.log entries
    - Securely wipes sensitive data from memory using constant-time operations


## How to Use
1. Clone the repository
2. `cd mach-o-crypter`
3. Put your target Mach-O executable in `mach-o-crypter/crypt`
4. In a shell, `cd` into `mach-o-crypter/crypt`
5.  A single `payload.cbor` file will be created in the `mach-o-crypter/stub` directory
7. `cd` into `mach-o-crypter/stub`
8. Build the stub: `go build -v`
9. Run the stub: `./stub`
10. Done!

## Features

- **Encryption/Decryption**: ChaCha20-Poly1305, AES-GCM, or Twofish-GCM AEAD (Authenticated Encryption with Associated Data)
- **Compression**: zlib compression to reduce payload size when beneficial
- **Secure Key Derivation**: Argon2id, a memory-hard KDF resistant to brute-force attacks (defaults: time=3, memory=128MB)
- **Packed Argon2 Params**: key derivation settings stored as a compact byte slice inside the CBOR payload
- **Protection Against Bit-Flip Attacks**: Authentication prevents tampering with encrypted data
- **Architecture Detection**: Runtime detection of ARM64 vs x86_64 for universal binary support
- **CBOR Payload Format**: Single-file packaging of all cryptographic material and encrypted binary
- **Secure Execution Flow**:
  - Decryption in memory with mlock protection
  - Temporary file in user cache directories (`~/Library/Caches` or `/private/var/folders/*/C/`) with randomized bundle ID
  - Proper file permissions with chmod
  - Execution with environment variables preserved
  - Anti-forensic file deletion with hole punching and zero-overwrite
- **Memory Security**:
  - Memory locking to prevent swap exposure
  - Constant-time memory wiping with runtime.KeepAlive protection
  - Encryption tool wipes key material after payload creation
  - MADV_NOCORE to prevent memory dumps
  - MADV_FREE to reclaim memory pages immediately after use
- **Stealthy Operation**:
  - No logging to system.log
