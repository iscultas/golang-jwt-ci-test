package jwa

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func decodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("cannot decode %q: %v", value, err)
	}

	return decoded
}

func TestAESKeyWrapReproducesRFC3394(t *testing.T) {
	for _, vector := range aesKeyWrapVectors {
		t.Run(vector.section, func(t *testing.T) {
			block, err := aes.NewCipher(decodeVectorHex(t, vector.kek))
			if err != nil {
				t.Fatalf("cannot build the cipher: %v", err)
			}

			ciphertext := wrap(block, decodeVectorHex(t, vector.keyData))

			if want := decodeVectorHex(t, vector.ciphertext); !bytes.Equal(ciphertext, want) {
				t.Errorf("ciphertext mismatch:\n got %x\nwant %x", ciphertext, want)
			}
		})
	}
}

func TestAESKeyWrapUnwrapsRFC3394(t *testing.T) {
	for _, vector := range aesKeyWrapVectors {
		t.Run(vector.section, func(t *testing.T) {
			block, err := aes.NewCipher(decodeVectorHex(t, vector.kek))
			if err != nil {
				t.Fatalf("cannot build the cipher: %v", err)
			}

			keyData, ok := unwrap(block, decodeVectorHex(t, vector.ciphertext))
			if !ok {
				t.Fatal("the published ciphertext did not authenticate")
			}

			if want := decodeVectorHex(t, vector.keyData); !bytes.Equal(keyData, want) {
				t.Errorf("key data mismatch:\n got %x\nwant %x", keyData, want)
			}
		})
	}
}

func TestAESKeyWrapRejectsATamperedCiphertext(t *testing.T) {
	for _, vector := range aesKeyWrapVectors {
		t.Run(vector.section, func(t *testing.T) {
			block, err := aes.NewCipher(decodeVectorHex(t, vector.kek))
			if err != nil {
				t.Fatalf("cannot build the cipher: %v", err)
			}

			ciphertext := decodeVectorHex(t, vector.ciphertext)

			for i := range ciphertext {
				tampered := bytes.Clone(ciphertext)
				tampered[i] ^= 1

				if _, ok := unwrap(block, tampered); ok {
					t.Errorf("octet %d flipped and the ciphertext still authenticated", i)
				}
			}
		})
	}
}

func TestAESKeyWrapRejectsAWrongKEK(t *testing.T) {
	for _, vector := range aesKeyWrapVectors {
		t.Run(vector.section, func(t *testing.T) {
			kek := decodeVectorHex(t, vector.kek)
			kek[0] ^= 1

			block, err := aes.NewCipher(kek)
			if err != nil {
				t.Fatalf("cannot build the cipher: %v", err)
			}

			if _, ok := unwrap(block, decodeVectorHex(t, vector.ciphertext)); ok {
				t.Error("the ciphertext authenticated under the wrong KEK")
			}
		})
	}
}
