package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Default Argon2 parameters
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = chacha20poly1305.KeySize
	saltSize     = 16
	passwordSize = 32 // Size of the random password
)

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
	encryptedFilePath := filepath.Join(stubDir, "encrypted_Input.bin")
	configFilePath := filepath.Join(stubDir, "config.txt")

	encryptedFile, err := os.Create(encryptedFilePath)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	defer encryptedFile.Close()

	configFile, err := os.Create(configFilePath)
	if err != nil {
		log.Fatalf("Failed to create config file: %v", err)
	}
	defer configFile.Close()

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

	if _, err := encryptedFile.Write(encryptedBytes); err != nil {
		log.Fatalf("Failed to write encrypted data: %v", err)
	}

	// Write the password, salt, and nonce to the config file
	// We'll store them as hex for easier debugging
	configData := fmt.Sprintf("%s\n%s\n%s\n", 
		hex.EncodeToString(password),
		hex.EncodeToString(salt),
		hex.EncodeToString(nonce))
	
	if _, err := configFile.WriteString(configData); err != nil {
		log.Fatalf("Failed to write config data: %v", err)
	}

	fmt.Printf("Encryption completed successfully!\nFiles saved to:\n- %s\n- %s\n", encryptedFilePath, configFilePath)
} 