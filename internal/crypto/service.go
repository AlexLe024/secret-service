package crypto

type Service interface {
	Encrypt(plainText []byte) (cipherText []byte, nonce []byte, err error)
	Decrypt(cipherText []byte, nonce []byte) ([]byte, error)
}
