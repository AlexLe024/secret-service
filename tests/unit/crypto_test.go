package crypto_test

import (
	"bytes"
	"testing"

	"secret-service/internal/crypto"
)

func TestAESGCM_EncryptDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes

	svc, err := crypto.NewAESGCMService(key)
	if err != nil {
		t.Fatalf("создание сервиса: %v", err)
	}

	t.Run("шифрование и расшифрование возвращают исходный текст", func(t *testing.T) {
		plain := []byte("my-super-secret-api-key")

		cipherText, nonce, err := svc.Encrypt(plain)
		if err != nil {
			t.Fatalf("шифрование: %v", err)
		}

		if bytes.Equal(cipherText, plain) {
			t.Error("зашифрованный текст не должен совпадать с исходным")
		}

		decrypted, err := svc.Decrypt(cipherText, nonce)
		if err != nil {
			t.Fatalf("расшифрование: %v", err)
		}

		if !bytes.Equal(decrypted, plain) {
			t.Errorf("расшифрованный текст %q != исходный %q", decrypted, plain)
		}
	})

	t.Run("каждое шифрование даёт разный nonce", func(t *testing.T) {
		plain := []byte("same-value")

		_, nonce1, _ := svc.Encrypt(plain)
		_, nonce2, _ := svc.Encrypt(plain)

		if bytes.Equal(nonce1, nonce2) {
			t.Error("nonce должен быть уникальным для каждого шифрования")
		}
	})

	t.Run("неверный ключ не расшифровывает", func(t *testing.T) {
		plain := []byte("secret")
		cipherText, nonce, _ := svc.Encrypt(plain)

		wrongKey := []byte("00000000000000000000000000000000")
		wrongSvc, _ := crypto.NewAESGCMService(wrongKey)

		_, err := wrongSvc.Decrypt(cipherText, nonce)
		if err == nil {
			t.Error("расшифрование с неверным ключом должно возвращать ошибку")
		}
	})

	t.Run("повреждённый ciphertext не расшифровывается", func(t *testing.T) {
		plain := []byte("secret")
		cipherText, nonce, _ := svc.Encrypt(plain)

		// Портим данные
		cipherText[0] ^= 0xFF

		_, err := svc.Decrypt(cipherText, nonce)
		if err == nil {
			t.Error("расшифрование повреждённых данных должно возвращать ошибку")
		}
	})

	t.Run("неверная длина ключа", func(t *testing.T) {
		shortKey := []byte("short")
		_, err := crypto.NewAESGCMService(shortKey)
		if err == nil {
			t.Error("ключ длиной не 32 байта должен возвращать ошибку")
		}
	})
}
