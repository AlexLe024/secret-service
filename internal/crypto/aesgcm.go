package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AESGCMService struct {
	key []byte
}

func NewAESGCMService(key []byte) (*AESGCMService, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: key must be exactly 32 bytes for AES-256")
	}
	return &AESGCMService{key: key}, nil
}

func (s *AESGCMService) Encrypt(plainText []byte) (cipherText []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherText = gcm.Seal(nil, nonce, plainText, nil)
	return cipherText, nonce, nil
}

func (s *AESGCMService) Decrypt(cipherText []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, errors.New("crypto: decryption failed — wrong key or corrupted data")
	}

	return plainText, nil
}
