package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrCipherTextTooShort = errors.New("cipher text length is smaller than nonce length")
)

// Encrypt encrypts the provided data using the given AES key and returns the ciphertext
// which includes the nonce as the first part of the result.
func Encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	cipherText := aesGCM.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

// Decrypt decrypts the provided ciphertext using the given AES key and returns the decrypted data.
// The ciphertext must include the nonce at the start.
func Decrypt(key, cipherData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherData) < nonceSize {
		return nil, ErrCipherTextTooShort
	}

	nonce, cipherText := cipherData[:nonceSize], cipherData[nonceSize:]
	return aesGCM.Open(nil, nonce, cipherText, nil)
}
