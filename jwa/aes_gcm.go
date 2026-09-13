package jwa

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"slices"
)

// AESGCM is AES in Galois/Counter Mode, the content encryption family.
//
// [AESCBCHMACSHA2] assembles two primitives, but AESGCM is an AEAD mode with
// no other primitive. Thus the authentication tag comes from the mode.
type AESGCM struct {
	symmetricAlgorithm
}

var (
	a128gcm = &AESGCM{symmetricAlgorithm{"A128GCM", 16}}
	a192gcm = &AESGCM{symmetricAlgorithm{"A192GCM", 24}}
	a256gcm = &AESGCM{symmetricAlgorithm{"A256GCM", 32}}
)

// A128GCM returns AES-128 in Galois/Counter Mode. The CEK has 16 octets.
func A128GCM() *AESGCM { return a128gcm }

// A192GCM returns AES-192 in Galois/Counter Mode. The CEK has 24 octets.
func A192GCM() *AESGCM { return a192gcm }

// A256GCM returns AES-256 in Galois/Counter Mode. The CEK has 32 octets.
func A256GCM() *AESGCM { return a256gcm }

// KeySize returns the necessary length of the CEK in octets.
func (algorithm *AESGCM) KeySize() int { return algorithm.keySize }

const (
	gcmIVSize  = 12
	gcmTagSize = 16
)

// IVSize returns the necessary length of the IV in octets, which is always 12.
func (algorithm *AESGCM) IVSize() int { return gcmIVSize }

func (algorithm *AESGCM) aead(cek []byte) (cipher.AEAD, error) {
	if err := algorithm.checkKeySize(cek); err != nil {
		return nil, err
	}

	return newGCM(cek)
}

// Encrypt returns the ciphertext and the authentication tag as two values. The
// serialization gives each of them a different part, but the GCM mode makes one
// value. Thus Encrypt divides them.
//
// Encrypt gives [ErrInvalidKeySize] for a CEK of the incorrect length, and
// [ErrInvalidInitializationVector] for an IV that is not 12 octets.
func (algorithm *AESGCM) Encrypt(
	plaintext, cek, iv, additionalAuthenticatedData []byte,
) ([]byte, []byte, error) {
	aead, err := algorithm.aead(cek)
	if err != nil {
		return nil, nil, err
	}

	if len(iv) != gcmIVSize {
		return nil, nil, fmt.Errorf(
			"%w: %s: got %d octets, want %d", ErrInvalidInitializationVector, algorithm, len(iv), gcmIVSize,
		)
	}

	sealed := aead.Seal(nil, iv, plaintext, additionalAuthenticatedData)

	return sealed[:len(sealed)-gcmTagSize], sealed[len(sealed)-gcmTagSize:], nil
}

// Decrypt returns the plaintext. It attaches tag to the end of ciphertext
// again, where Encrypt found it.
//
// Decrypt gives [ErrDecryptionFailed] for all data that comes from the token:
// an IV or tag of the incorrect length, and an authentication check that does
// not agree. This is necessary, because a recipient must not tell an attacker
// which check rejected a message. A CEK of the incorrect length comes from the
// key of the recipient, not from the token, thus it keeps [ErrInvalidKeySize].
func (algorithm *AESGCM) Decrypt(
	ciphertext, cek, iv, additionalAuthenticatedData, tag []byte,
) ([]byte, error) {
	aead, err := algorithm.aead(cek)
	if err != nil {
		return nil, err
	}

	if len(iv) != gcmIVSize || len(tag) != gcmTagSize {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := aead.Open(nil, iv, slices.Concat(ciphertext, tag), additionalAuthenticatedData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
