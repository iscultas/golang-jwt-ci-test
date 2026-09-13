package jwa

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// AESCBCHMACSHA2 is the assembled content encryption family. AES-CBC gives
// confidentiality and HMAC-SHA-2 gives authenticity. One mode does not give the
// two properties together. The standard library does not assemble this family,
// thus this package assembles it. The published test vectors show that the
// result is correct.
//
// The sequence is encrypt-then-MAC, and the sequence is important in the two
// directions. [AESCBCHMACSHA2.Decrypt] verifies the tag before it reads the
// padding. Thus an attacker does not get the padding oracle that a
// MAC-then-encrypt sequence supplies.
type AESCBCHMACSHA2 struct {
	name string

	hash crypto.Hash
}

var (
	a128cbcHS256 = &AESCBCHMACSHA2{"A128CBC-HS256", crypto.SHA256}
	a192cbcHS384 = &AESCBCHMACSHA2{"A192CBC-HS384", crypto.SHA384}
	a256cbcHS512 = &AESCBCHMACSHA2{"A256CBC-HS512", crypto.SHA512}
)

// A128CBCHS256 returns AES-128-CBC with HMAC-SHA-256. The input key has 32
// octets.
func A128CBCHS256() *AESCBCHMACSHA2 { return a128cbcHS256 }

// A192CBCHS384 returns AES-192-CBC with HMAC-SHA-384. The input key has 48
// octets.
func A192CBCHS384() *AESCBCHMACSHA2 { return a192cbcHS384 }

// A256CBCHS512 returns AES-256-CBC with HMAC-SHA-512. The input key has 64
// octets.
func A256CBCHS512() *AESCBCHMACSHA2 { return a256cbcHS512 }

// String returns the "enc" value of this algorithm, for example "A128CBC-HS256".
func (algorithm *AESCBCHMACSHA2) String() string { return algorithm.name }

// KeySize returns the length of the input key K in octets. The three algorithms
// use 32, 48 and 64 octets. Each length is the output length of the hash in the
// name.
func (algorithm *AESCBCHMACSHA2) KeySize() int { return algorithm.hash.Size() }

func (algorithm *AESCBCHMACSHA2) halfSize() int { return algorithm.hash.Size() / 2 }

// IVSize returns the necessary length of the IV in octets, which is always the
// AES block length of 16.
func (algorithm *AESCBCHMACSHA2) IVSize() int { return aes.BlockSize }

func (algorithm *AESCBCHMACSHA2) keys(cek []byte) (macKey, encryptionKey []byte, err error) {
	if len(cek) != algorithm.KeySize() {
		return nil, nil, fmt.Errorf(
			"%w: %s: got %d octets, want %d", ErrInvalidKeySize, algorithm, len(cek), algorithm.KeySize(),
		)
	}

	return cek[:algorithm.halfSize()], cek[algorithm.halfSize():], nil
}

func (algorithm *AESCBCHMACSHA2) tag(macKey, iv, ciphertext, additionalAuthenticatedData []byte) []byte {
	mac := hmac.New(algorithm.hash.New, macKey)

	mac.Write(additionalAuthenticatedData)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(additionalAuthenticatedData))*8))

	return mac.Sum(nil)[:algorithm.halfSize()]
}

// Encrypt returns the ciphertext and the truncated authentication tag.
//
// Encrypt gives [ErrInvalidKeySize] for a CEK of the incorrect length, and
// [ErrInvalidInitializationVector] for an IV that is not 16 octets.
func (algorithm *AESCBCHMACSHA2) Encrypt(
	plaintext, cek, iv, additionalAuthenticatedData []byte,
) ([]byte, []byte, error) {
	macKey, encryptionKey, err := algorithm.keys(cek)
	if err != nil {
		return nil, nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, nil, fmt.Errorf(
			"%w: %s: got %d octets, want %d", ErrInvalidInitializationVector, algorithm, len(iv), aes.BlockSize,
		)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := pad(plaintext)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)

	return ciphertext, algorithm.tag(macKey, iv, ciphertext, additionalAuthenticatedData), nil
}

// Decrypt returns the plaintext. It verifies the tag first, and it reads the
// ciphertext only after the tag is correct. This is step 2 of the decryption
// procedure. Thus an incorrect ciphertext does not come to the padding check,
// and an attacker cannot use that check.
//
// Decrypt gives [ErrDecryptionFailed] for all data that comes from the token:
//
//   - an IV of the incorrect length
//   - a ciphertext that is not a multiple of the block length
//   - a tag check that does not agree
//   - bad padding
//
// One error is necessary here, because a recipient must not show which check
// rejected a message.
func (algorithm *AESCBCHMACSHA2) Decrypt(
	ciphertext, cek, iv, additionalAuthenticatedData, tag []byte,
) ([]byte, error) {
	macKey, encryptionKey, err := algorithm.keys(cek)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecryptionFailed
	}

	if !hmac.Equal(tag, algorithm.tag(macKey, iv, ciphertext, additionalAuthenticatedData)) {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	plaintext, ok := unpad(plaintext)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func pad(plaintext []byte) []byte {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize

	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)

	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	return padded
}

func unpad(padded []byte) ([]byte, bool) {
	if len(padded) == 0 || len(padded)%aes.BlockSize != 0 {
		return nil, false
	}

	padding := int(padded[len(padded)-1])

	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aes.BlockSize)

	for i := 1; i <= aes.BlockSize; i++ {
		counted := subtle.ConstantTimeLessOrEq(i, padding)
		octet := padded[len(padded)-i]

		//nolint:gosec // padding is int(one octet) above, thus the conversion back is the same value.
		valid &= subtle.ConstantTimeSelect(counted, subtle.ConstantTimeByteEq(octet, byte(padding)), 1)
	}

	if valid != 1 {
		return nil, false
	}

	return padded[:len(padded)-padding], true
}
