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
	plainData, err := aesGCM.Open(nil, nonce, cipherText, nil)
	return plainData, err
}
