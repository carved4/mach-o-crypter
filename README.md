# Macho-Crypter - A Mach-O Binary Crypter for macOS

A Go-based implementation of a crypter for Mach-O binaries on macOS with ChaCha20-Poly1305 authenticated encryption and secure in-memory execution.

Feel free to open issues or DM with feedback or use cases!

## Overview
This project contains two components:

1. **crypt** - A tool to encrypt a Mach-O executable file using ChaCha20-Poly1305 authenticated encryption, and turn it into two parts:
    - The encrypted_input.bin (which contains the encrypted bytes of the target executable)
    - The config.txt which contains information needed for secure key derivation and decryption
2. **stub** - A Go binary that embeds, decrypts, and executes the encrypted Mach-O binary using a secure execution flow:
    - Decrypts the binary in memory
    - Drops the decrypted binary to a temporary file with a random name in /tmp
    - Makes it executable
    - Executes it using syscall.SYS_EXECVE with proper environment variables
    - Immediately unlinks the file after execution
    - Securely wipes sensitive data from memory


## How to Use
1. Clone the repository
2. `cd gocrypter`
3. Put your target Mach-O executable in `gocrypter/crypt`
4. In a shell, `cd` into `gocrypter/crypt`
5. To encrypt your binary: `go run main.go your_binary` (replace with the name of your Mach-O binary)
6. The files `encrypted_Input.bin` and `config.txt` will be created in the `gocrypter/stub` directory
7. `cd` into `gocrypter/stub`
8. Build the stub: `go build -v`
9. Run the stub: `./stub`
10. Done!

## Features

- **Encryption/Decryption**: ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
- **Secure Key Derivation**: Argon2id, a memory-hard KDF resistant to brute-force attacks
- **Protection Against Bit-Flip Attacks**: Authentication prevents tampering with encrypted data
- **Secure Execution Flow**:
  - Decryption in memory
  - Temporary file with random name in /tmp
  - Proper file permissions with chmod
  - Execution with environment variables preserved
  - Immediate file unlinking
- **Memory Security**:
  - Multi-phase memory overwriting (random data followed by zeros)
  - Forced garbage collection
  - Path string wiping
- **Embedded Resources**: The encrypted file and configuration data are embedded in the stub binary using Go's embed package

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

While significantly improved, this is still a basic implementation and may not be suitable for production use without additional OPSEC measures.

**Important**: Do not use this outside of a lab environment or an authorized red team engagement. I am not responsible for your actions.

Potential improvements:
- Anti-debugging mechanisms
- VM detection
- Additional obfuscation techniques
- More sophisticated memory protection
## Platform Support

This implementation is specifically designed for macOS and Mach-O binaries. It uses macOS-specific system calls and file handling.

## Example Usage

1. Create a simple Mach-O binary to test with
2. Encrypt it using the crypt tool
3. Build and run the stub
4. The binary will be executed securely with all environment variables preserved

## License

See the LICENSE file for details.
