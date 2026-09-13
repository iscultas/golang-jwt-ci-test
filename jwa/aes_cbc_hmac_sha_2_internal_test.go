package jwa

import (
	"bytes"
	"crypto/aes"
	"errors"
	"testing"
)

func block(t *testing.T, n int, tail ...byte) []byte {
	t.Helper()

	if n < len(tail) {
		t.Fatalf("a %d-octet buffer cannot end with %d octets", n, len(tail))
	}

	padded := bytes.Repeat([]byte{0xAA}, n-len(tail))

	return append(padded, tail...)
}

func TestUnpadAcceptsCorrectPadding(t *testing.T) {
	for _, test := range []struct {
		name   string
		padded []byte
		want   int
	}{
		{"OneOctet", block(t, aes.BlockSize, 0x01), aes.BlockSize - 1},
		{"WholeBlock", bytes.Repeat([]byte{0x10}, aes.BlockSize), 0},
		{"FiveOctets", block(t, 2*aes.BlockSize, 0x05, 0x05, 0x05, 0x05, 0x05), 2*aes.BlockSize - 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			plaintext, ok := unpad(test.padded)
			if !ok {
				t.Fatal("unpad refused correct padding")
			}

			if len(plaintext) != test.want {
				t.Errorf("unpad gives %d octets, want %d", len(plaintext), test.want)
			}

			if !bytes.Equal(plaintext, test.padded[:test.want]) {
				t.Error("unpad changed the plaintext it kept")
			}
		})
	}
}

func TestUnpadRefusesIncorrectPadding(t *testing.T) {
	for _, test := range []struct {
		name   string
		padded []byte
	}{
		{"Empty", nil},
		{"ShorterThanABlock", block(t, aes.BlockSize-1, 0x01)},
		{"NotAWholeBlock", block(t, aes.BlockSize+1, 0x01)},
		{"ZeroPadding", block(t, aes.BlockSize, 0x00)},
		{"PastTheBlockSize", block(t, aes.BlockSize, 0x11)},
		{"OneOctetOfTheRunIsWrong", block(t, aes.BlockSize, 0x02, 0x03, 0x03)},
	} {
		t.Run(test.name, func(t *testing.T) {
			plaintext, ok := unpad(test.padded)
			if ok {
				t.Fatal("unpad accepted incorrect padding")
			}

			if plaintext != nil {
				t.Errorf("unpad gives %v with false, want nil", plaintext)
			}
		})
	}
}

func TestDecryptRefusesMalformedLengthsAheadOfTheCipher(t *testing.T) {
	algorithm := A128CBCHS256()

	cek := bytes.Repeat([]byte{0x2A}, algorithm.KeySize())
	additionalAuthenticatedData := []byte("aad")

	macKey, _, err := algorithm.keys(cek)
	if err != nil {
		t.Fatalf("cannot split the key: %v", err)
	}

	wholeBlocks := bytes.Repeat([]byte{0x5C}, 2*aes.BlockSize)
	iv := bytes.Repeat([]byte{0x3B}, aes.BlockSize)

	for _, test := range []struct {
		name       string
		ciphertext []byte
		iv         []byte
	}{
		{"ShortIV", wholeBlocks, iv[:aes.BlockSize-1]},
		{"LongIV", wholeBlocks, append(bytes.Clone(iv), 0)},
		{"NoIV", wholeBlocks, nil},
		{"CiphertextIsNotWholeBlocks", wholeBlocks[:aes.BlockSize+1], iv},
	} {
		t.Run(test.name, func(t *testing.T) {
			tag := algorithm.tag(macKey, test.iv, test.ciphertext, additionalAuthenticatedData)

			_, err := algorithm.Decrypt(
				test.ciphertext, cek, test.iv, additionalAuthenticatedData, tag,
			)
			if !errors.Is(err, ErrDecryptionFailed) {
				t.Errorf("got %v, want ErrDecryptionFailed", err)
			}
		})
	}
}
