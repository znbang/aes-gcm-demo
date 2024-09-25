package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	passphrase := "passphrase"
	plaintext := "plaintext"

	fmt.Println("passphrase:", passphrase)
	fmt.Println("plaintext:", plaintext)

	encrypted, err := encrypt(passphrase, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encrypted:", encrypted)

	decrypted, err := decrypt(passphrase, encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted:", decrypted)
}

const SaltSize = 16
const BlockSize = 32
const IterCount = 4096

func encrypt(passphrase string, plaintext string) (string, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("create salt failed: %w", err)
	}

	key := pbkdf2.Key([]byte(passphrase), salt, IterCount, BlockSize, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher block failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("create nonce failed: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	result := append(salt, ciphertext...)

	return hex.EncodeToString(result), nil
}

func decrypt(passphrase string, encodedText string) (string, error) {
	result, err := hex.DecodeString(encodedText)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext failed: %w", err)
	}

	salt := result[:SaltSize]
	ciphertext := result[SaltSize:]

	key := pbkdf2.Key([]byte(passphrase), salt, IterCount, BlockSize, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher block failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < SaltSize+nonceSize {
		return "", fmt.Errorf("ciphertext shorter than salt + nonce")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt ciphertext failed: %w", err)
	}

	return string(plaintext), nil
}
