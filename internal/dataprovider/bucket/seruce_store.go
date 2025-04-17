package bucket

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/hkdf"
	"io"
)

type secureEntry struct {
	nats.KeyValueEntry
	value []byte
}

func (s *secureEntry) Value() []byte {
	return s.value
}

// deriveKey uses HKDF with SHA-256 to generate a 32-byte AES key
func deriveKey(password, salt []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, password, salt, nil)

	key := make([]byte, 32) // AES-256 needs 32 bytes
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encrypt(plaintext, password, salt []byte) ([]byte, error) {
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, ErrPasswordHashFailed
	}

	cc, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidCipherBlock
	}

	gcm, err := cipher.NewGCM(cc)
	if err != nil {
		return nil, ErrCipherGCMCreation
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrNonceGeneration
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, password, salt []byte) ([]byte, error) {
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidCipherBlock
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCipherGCMCreation
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCipherTooShort
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
