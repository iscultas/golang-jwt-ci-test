package jwa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// AESKeyWrap is the AES Key Wrap Algorithm of RFC 3394. RFC 7518 section 4.4
// uses this algorithm with the default initial value of that document.
//
// The standard library does not supply RFC 3394. Thus this package contains
// its wrap and unwrap operations. The test vectors of RFC 3394 section 4
// show that the two operations are correct.
// The key encryption key length is a property of the algorithm, not of the key
// that a caller supplies. A128KW names a 128-bit key encryption key for all
// keys, as ES256 names P-256.
type AESKeyWrap struct {
	symmetricAlgorithm
}

var (
	a128kw = &AESKeyWrap{symmetricAlgorithm{"A128KW", 16}}
	a192kw = &AESKeyWrap{symmetricAlgorithm{"A192KW", 24}}
	a256kw = &AESKeyWrap{symmetricAlgorithm{"A256KW", 32}}
)

// A128KW returns AES-128 key wrapping. The key encryption key has 16 octets.
func A128KW() *AESKeyWrap { return a128kw }

// A192KW returns AES-192 key wrapping. The key encryption key has 24 octets.
func A192KW() *AESKeyWrap { return a192kw }

// A256KW returns AES-256 key wrapping. The key encryption key has 32 octets.
func A256KW() *AESKeyWrap { return a256kw }

const keyWrapBlockSize = 8

var keyWrapDefaultIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

func (algorithm *AESKeyWrap) cipher(key any) (cipher.Block, error) {
	kek, err := algorithm.secret(key)
	if err != nil {
		return nil, err
	}

	return aes.NewCipher(kek)
}

func wrap(block cipher.Block, plaintext []byte) []byte {
	n := len(plaintext) / keyWrapBlockSize

	a := make([]byte, keyWrapBlockSize)
	copy(a, keyWrapDefaultIV)

	r := make([]byte, len(plaintext))
	copy(r, plaintext)

	var buffer [aes.BlockSize]byte

	for j := range 6 {
		for i := 1; i <= n; i++ {
			register := r[(i-1)*keyWrapBlockSize : i*keyWrapBlockSize]

			copy(buffer[:keyWrapBlockSize], a)
			copy(buffer[keyWrapBlockSize:], register)
			block.Encrypt(buffer[:], buffer[:])

			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buffer[:keyWrapBlockSize])^t)

			copy(register, buffer[keyWrapBlockSize:])
		}
	}

	return append(a, r...)
}

func unwrap(block cipher.Block, ciphertext []byte) ([]byte, bool) {
	n := len(ciphertext)/keyWrapBlockSize - 1

	a := make([]byte, keyWrapBlockSize)
	copy(a, ciphertext[:keyWrapBlockSize])

	r := make([]byte, len(ciphertext)-keyWrapBlockSize)
	copy(r, ciphertext[keyWrapBlockSize:])

	var buffer [aes.BlockSize]byte

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			register := r[(i-1)*keyWrapBlockSize : i*keyWrapBlockSize]

			//nolint:gosec // The counter t of RFC 3394, which runs to 6n for a key of n registers.
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(buffer[:keyWrapBlockSize], binary.BigEndian.Uint64(a)^t)
			copy(buffer[keyWrapBlockSize:], register)
			block.Decrypt(buffer[:], buffer[:])

			copy(a, buffer[:keyWrapBlockSize])
			copy(register, buffer[keyWrapBlockSize:])
		}
	}

	return r, subtle.ConstantTimeCompare(a, keyWrapDefaultIV) == 1
}

func checkWrappable(data []byte) bool {
	return len(data) >= 2*keyWrapBlockSize && len(data)%keyWrapBlockSize == 0
}

// EncryptKey returns a new CEK and the JWE Encrypted Key that holds it. It makes
// the CEK and then wraps it.
func (algorithm *AESKeyWrap) EncryptKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	return encryptKey(algorithm, key, encryption, parameters)
}

// WrapKey returns the JWE Encrypted Key for the given cek.
//
// WrapKey gives [ErrInvalidKeySize] if cek is shorter than 16 octets, or if its
// length is not a multiple of 8 octets. RFC 3394 operates on full semiblocks
// only.
func (algorithm *AESKeyWrap) WrapKey(
	cek []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	block, err := algorithm.cipher(key)
	if err != nil {
		return nil, err
	}

	if !checkWrappable(cek) {
		return nil, fmt.Errorf(
			"%w: %s: cannot wrap a %d-octet key", ErrInvalidKeySize, algorithm, len(cek),
		)
	}

	return wrap(block, cek), nil
}

// DecryptKey returns the CEK from the JWE Encrypted Key.
//
// DecryptKey gives [ErrDecryptionFailed] in four conditions:
//
//   - encryptedKey is too short
//   - the length of encryptedKey is not a multiple of 8 octets
//   - the integrity check does not agree
//   - the CEK does not have the length that encryption gives
//
// All four values come from the token, thus they use one error.
func (algorithm *AESKeyWrap) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	block, err := algorithm.cipher(key)
	if err != nil {
		return nil, err
	}

	if len(encryptedKey) < 3*keyWrapBlockSize || len(encryptedKey)%keyWrapBlockSize != 0 {
		return nil, ErrDecryptionFailed
	}

	cek, ok := unwrap(block, encryptedKey)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	if err := checkContentEncryptionKeySize(encryption, cek); err != nil {
		return nil, err
	}

	return cek, nil
}
