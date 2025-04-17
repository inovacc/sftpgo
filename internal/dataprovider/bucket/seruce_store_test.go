package bucket

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		password  []byte
		salt      []byte
		plaintext []byte
	}{
		{
			name:      "Basic text",
			password:  []byte("simple-password"),
			salt:      []byte("2vp6rCG6QmdjK1SDgvQJPL4qm8J"),
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "Empty text",
			password:  []byte("password123"),
			salt:      []byte("2vp6rCG6QmdjK1SDgvQJPL4qm8J"),
			plaintext: []byte(""),
		},
		{
			name:      "Long text",
			password:  []byte("secure-pass"),
			salt:      []byte("2vp6rCG6QmdjK1SDgvQJPL4qm8J"),
			plaintext: bytes.Repeat([]byte("long text "), 100),
		},
		{
			name:      "Binary data",
			password:  []byte("binary-pass"),
			salt:      []byte("2vp6rCG6QmdjK1SDgvQJPL4qm8J"),
			plaintext: []byte{0x00, 0xFF, 0x10, 0x20, 0x30},
		},
		{
			name:      "Special characters",
			password:  []byte("special!@#$%^&*()"),
			salt:      []byte("2vp6rCG6QmdjK1SDgvQJPL4qm8J"),
			plaintext: []byte("Text with 特殊字符 and 😀 emoji"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt the plaintext
			encrypted, err := encrypt(tt.plaintext, tt.password, tt.salt)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			// Verify encrypted data is different from plaintext
			if bytes.Equal(encrypted, tt.plaintext) {
				t.Error("encrypted data is identical to plaintext")
			}

			// Decrypt the encrypted data
			decrypted, err := decrypt(encrypted, tt.password, tt.salt)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			// Verify decrypted data matches original plaintext
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted data doesn't match original plaintext\ngot: %x\nwant: %x",
					decrypted, tt.plaintext)
			}
		})
	}

	t.Run("Wrong password", func(t *testing.T) {
		plaintext := []byte("secret message")
		password := []byte("correct-password")
		wrongPassword := []byte("wrong-password")

		// Encrypt with the correct password
		encrypted, err := encrypt(plaintext, password, []byte("salt"))
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Try to decrypt with the wrong password
		_, err = decrypt(encrypted, wrongPassword, []byte("salt"))
		if err == nil {
			t.Error("expected error when decrypting with wrong password, got nil")
		}
	})

	t.Run("Invalid encrypted data", func(t *testing.T) {
		password := []byte("test-password")
		invalidData := []byte("not encrypted data")

		_, err := decrypt(invalidData, password, []byte("salt"))
		if err == nil {
			t.Error("expected error when decrypting invalid data, got nil")
		}
	})
}
