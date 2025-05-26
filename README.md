# Macho-Crypter - A Mach-O Binary Crypter for macOS

A Go-based implementation of a crypter for Mach-O binaries on macOS with ChaCha20-Poly1305 authenticated encryption, CBOR payload packaging, and secure in-memory execution with anti-forensic features.

Feel free to open issues or DM with feedback or use cases!

## Overview
This project contains two components:

1. **crypt** - A tool to encrypt a Mach-O executable file using ChaCha20-Poly1305 authenticated encryption, and package it into a single CBOR payload:
    - Combines encrypted binary, key derivation parameters, and cryptographic material into a single file
    - Uses CBOR (Concise Binary Object Representation) for compact, non-textual storage
    - Embeds Argon2 parameters for future-proofing and versioning

2. **stub** - A Go binary that embeds, decrypts, and executes the encrypted Mach-O binary using a secure execution flow:
    - Detects CPU architecture at runtime (ARM64/x86_64)
    - Decrypts the binary in memory with memory protection (mlock, MADV_NOCORE)
    - Drops the decrypted binary to a secure location in user cache directories
    - Executes it using syscall.Exec with proper environment variables
    - Implements anti-forensic techniques for file deletion
    - Uses stealthy logging to avoid system.log entries
    - Securely wipes sensitive data from memory using constant-time operations


## How to Use
1. Clone the repository
2. `cd gocrypter`
3. Put your target Mach-O executable in `gocrypter/crypt`
4. In a shell, `cd` into `gocrypter/crypt`
5. To encrypt your binary: `go run main.go your_binary` (replace with the name of your Mach-O binary)
6. A single `payload.cbor` file will be created in the `gocrypter/stub` directory
7. `cd` into `gocrypter/stub`
8. Build the stub: `go build -v`
9. Run the stub: `./stub`
10. Done!

## Features

- **Encryption/Decryption**: ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
- **Secure Key Derivation**: Argon2id, a memory-hard KDF resistant to brute-force attacks
- **Protection Against Bit-Flip Attacks**: Authentication prevents tampering with encrypted data
- **Architecture Detection**: Runtime detection of ARM64 vs x86_64 for universal binary support
- **CBOR Payload Format**: Single-file packaging of all cryptographic material and encrypted binary
- **Secure Execution Flow**:
  - Decryption in memory with mlock protection
  - Temporary file in user cache directories that blend with system caches
  - Proper file permissions with chmod
  - Execution with environment variables preserved
  - Anti-forensic file deletion with hole punching
- **Memory Security**:
  - Memory locking to prevent swap exposure
  - Constant-time memory wiping with runtime.KeepAlive protection
  - MADV_NOCORE to prevent memory dumps
- **Stealthy Operation**:
  - No logging to system.log
  - Blends with legitimate application caches
  - Minimal filesystem footprint
- **Embedded Resources**: The encrypted payload is embedded in the stub binary using Go's embed package

## Security Improvements

The project implements multiple layers of security enhancements:

### Core Security Features

1. **Authenticated Encryption**: ChaCha20-Poly1305 provides both confidentiality and integrity/authenticity
2. **Secure Key Derivation**: Instead of storing encryption keys directly, we use Argon2id to derive keys
3. **Memory-Hard Key Derivation**: Makes brute force attacks significantly more expensive

### Advanced Memory Protection

1. **Memory Locking (mlock)**:
   - Prevents sensitive decrypted data from being swapped to disk
   - Reduces the risk of sensitive data being recovered from swap files

2. **Constant-Time Memory Wiping**:
   - Uses `crypto/subtle.ConstantTimeCopy` for secure memory wiping
   - Prevents compiler optimization from removing memory clearing operations
   - Employs `runtime.KeepAlive` to ensure memory wipes aren't optimized away

3. **Architecture-Aware Execution**:
   - Runtime detection of CPU architecture (ARM64 vs x86_64)
   - Uses `sysctlbyname("hw.optional.arm64")` for architecture detection
   - Ensures compatibility with Apple Silicon and Intel processors

### Filesystem Security

1. **Improved Temporary File Location**:
   - Uses `/private/var/folders/<uid>/T/` (user-specific temp directories) when available
   - Falls back to `/tmp` only if user-specific directories are inaccessible
   - Reduces visibility in common forensic scans

2. **Anti-Forensic File Handling**:
   - Implements file hole punching with `F_PUNCHHOLE` to complicate forensic recovery
   - Overwrites file content with zeros before deletion
   - Makes carving deleted files from disk significantly more difficult

3. **Secure Execution Flow**:
   - Random filenames with hidden attribute (dot prefix)
   - Immediate unlinking after execution
   - Proper permissions (0700)

### Build Improvements

1. **Platform-Specific Compilation**:
   - Uses `//go:build darwin` tags to ensure code only builds on macOS
   - Prevents accidental builds on unsupported platforms

## Security Considerations

This implementation includes numerous security enhancements but should still be used with caution in appropriate contexts.

**Important**: Do not use this outside of a lab environment or an authorized red team engagement. I am not responsible for your actions.

Additional security features implemented:
- Memory locking (mlock) to prevent sensitive data from being swapped to disk
- Constant-time memory wiping to prevent optimization from removing security operations
- Anti-forensic file deletion with zero-overwrite and hole punching
- Stealthy logging to avoid system.log entries
- Architecture detection for universal binary support
- User cache directory usage to blend with legitimate applications

Potential future improvements:
- Anti-debugging mechanisms
- VM detection
- Additional obfuscation techniques
- In-memory execution without touching disk
## Platform Support

This implementation is specifically designed for macOS and Mach-O binaries. It uses macOS-specific system calls and file handling.

## Example Usage

1. Create a simple Mach-O binary to test with
2. Encrypt it using the crypt tool
3. Build and run the stub
4. The binary will be executed securely with all environment variables preserved

## License

See the LICENSE file for details.
