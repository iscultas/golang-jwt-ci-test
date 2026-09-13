package jwa_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

var aesGCMAlgorithms = []struct {
	algorithm *jwa.AESGCM
	keySize   int
}{
	{jwa.A128GCM(), 16},
	{jwa.A192GCM(), 24},
	{jwa.A256GCM(), 32},
}

func TestAESGCMRoundTrips(t *testing.T) {
	for _, pairing := range aesGCMAlgorithms {
		t.Run(pairing.algorithm.String(), func(t *testing.T) {
			if pairing.algorithm.KeySize() != pairing.keySize {
				t.Errorf("got a key size of %d, want %d", pairing.algorithm.KeySize(), pairing.keySize)
			}

			if pairing.algorithm.IVSize() != 12 {
				t.Errorf("got an IV size of %d, want 12", pairing.algorithm.IVSize())
			}

			cek := make([]byte, pairing.algorithm.KeySize())
			iv := make([]byte, pairing.algorithm.IVSize())
			plaintext := []byte("Live long and prosper.")
			additionalAuthenticatedData := []byte("eyJhbGciOiJkaXIifQ")

			ciphertext, tag, err := pairing.algorithm.Encrypt(plaintext, cek, iv, additionalAuthenticatedData)
			if err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			if len(ciphertext) != len(plaintext) {
				t.Errorf("got a %d-octet ciphertext, want %d", len(ciphertext), len(plaintext))
			}

			if len(tag) != 16 {
				t.Errorf("got a %d-octet tag, want 16", len(tag))
			}

			decrypted, err := pairing.algorithm.Decrypt(ciphertext, cek, iv, additionalAuthenticatedData, tag)
			if err != nil {
				t.Fatalf("cannot decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("round trip changed the plaintext: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestAESGCMRejectsTamperedInput(t *testing.T) {
	algorithm := jwa.A256GCM()

	cek := make([]byte, algorithm.KeySize())
	iv := make([]byte, algorithm.IVSize())
	plaintext := []byte("Live long and prosper.")
	additionalAuthenticatedData := []byte("eyJhbGciOiJkaXIifQ")

	ciphertext, tag, err := algorithm.Encrypt(plaintext, cek, iv, additionalAuthenticatedData)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	for _, tampered := range []string{"ciphertext", "iv", "aad", "tag", "short iv", "short tag"} {
		t.Run(tampered, func(t *testing.T) {
			ciphertext := bytes.Clone(ciphertext)
			iv := bytes.Clone(iv)
			additionalAuthenticatedData := bytes.Clone(additionalAuthenticatedData)
			tag := bytes.Clone(tag)

			switch tampered {
			case "ciphertext":
				ciphertext[0] ^= 1
			case "iv":
				iv[0] ^= 1
			case "aad":
				additionalAuthenticatedData[0] ^= 1
			case "tag":
				tag[0] ^= 1
			case "short iv":
				iv = iv[:len(iv)-1]
			case "short tag":
				tag = tag[:len(tag)-1]
			}

			_, err := algorithm.Decrypt(ciphertext, cek, iv, additionalAuthenticatedData, tag)

			if !errors.Is(err, jwa.ErrDecryptionFailed) {
				t.Errorf("got %v, want ErrDecryptionFailed", err)
			}
		})
	}
}

func TestAESGCMRejectsWrongKeySize(t *testing.T) {
	for _, pairing := range aesGCMAlgorithms {
		t.Run(pairing.algorithm.String(), func(t *testing.T) {
			for _, size := range []int{16, 24, 32, 0} {
				if size == pairing.keySize {
					continue
				}

				_, _, err := pairing.algorithm.Encrypt(
					[]byte("plaintext"), make([]byte, size), make([]byte, pairing.algorithm.IVSize()), nil,
				)

				if !errors.Is(err, jwa.ErrInvalidKeySize) {
					t.Errorf("%d-octet key: got %v, want ErrInvalidKeySize", size, err)
				}
			}
		})
	}
}

func TestAESGCMRejectsWrongIVSize(t *testing.T) {
	algorithm := jwa.A128GCM()

	for _, size := range []int{0, 11, 13, 16} {
		_, _, err := algorithm.Encrypt(
			[]byte("plaintext"), make([]byte, algorithm.KeySize()), make([]byte, size), nil,
		)

		if !errors.Is(err, jwa.ErrInvalidInitializationVector) {
			t.Errorf("%d-octet IV: got %v, want ErrInvalidInitializationVector", size, err)
		}
	}
}
