package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Default Argon2 parameters
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = chacha20poly1305.KeySize
	saltSize     = 16
	passwordSize = 32 // Size of the random password
)

// PayloadData represents the structure of our CBOR payload
type PayloadData struct {
	EncryptedBytes []byte `cbor:"encrypted"`
	Password       []byte `cbor:"password"`
	Salt           []byte `cbor:"salt"`
	Nonce          []byte `cbor:"nonce"`
	ArgonParams    struct {
		Time    uint32 `cbor:"time"`
		Memory  uint32 `cbor:"memory"`
		Threads uint8  `cbor:"threads"`
	} `cbor:"argon_params"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Run with %s <inputfile.exe>\n", os.Args[0])
		os.Exit(1)
	}

	fname := os.Args[1]
	plaintextBytes, err := os.ReadFile(fname)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	stubDir := filepath.Join("..", "stub")
	payloadPath := filepath.Join(stubDir, "payload.cbor")

	// Generate a random password (instead of using the key directly)
	password := make([]byte, passwordSize)
	if _, err := io.ReadFull(rand.Reader, password); err != nil {
		log.Fatalf("Failed to generate random password: %v", err)
	}

	// Generate a random salt for Argon2
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatalf("Failed to generate random salt: %v", err)
	}

	// Generate a random nonce for ChaCha20-Poly1305
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("Failed to generate random nonce: %v", err)
	}

	// Derive the encryption key using Argon2id
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalf("Failed to create AEAD: %v", err)
	}

	// Encrypt the data with authentication
	encryptedBytes := aead.Seal(nil, nonce, plaintextBytes, nil)

	// Create the payload structure
	payload := PayloadData{
		EncryptedBytes: encryptedBytes,
		Password:       password,
		Salt:           salt,
		Nonce:          nonce,
	}
	
	// Set the Argon2 parameters
	payload.ArgonParams.Time = argonTime
	payload.ArgonParams.Memory = argonMemory
	payload.ArgonParams.Threads = uint8(argonThreads)
	
	// Marshal the payload to CBOR
	cborData, err := cbor.Marshal(payload)
	if err != nil {
		log.Fatalf("Failed to marshal CBOR data: %v", err)
	}
	
	// Write the CBOR data to file
	if err := os.WriteFile(payloadPath, cborData, 0600); err != nil {
		log.Fatalf("Failed to write CBOR payload: %v", err)
	}

	fmt.Printf("Encryption completed successfully!\nCBOR payload saved to:\n- %s\n", payloadPath)
} 