package jwa

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestConcatKDFReproducesAppendixC(t *testing.T) {
	sharedSecret := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}

	derived := concatKDF(sharedSecret, "A128GCM", []byte("Alice"), []byte("Bob"), 16)

	want, err := base64.RawURLEncoding.DecodeString("VqqN6vgjbSBcIijNcacQGg")
	if err != nil {
		t.Fatalf("cannot decode the expected key: %v", err)
	}

	if !bytes.Equal(derived, want) {
		t.Errorf("derived key mismatch:\n got %x\nwant %x", derived, want)
	}
}

func TestConcatKDFSpansMultipleRounds(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{1}, 32)

	for _, size := range []int{16, 32, 48, 64} {
		derived := concatKDF(sharedSecret, "A256CBC-HS512", nil, nil, size)

		if len(derived) != size {
			t.Errorf("got %d octets, want %d", len(derived), size)
		}
	}

	long := concatKDF(sharedSecret, "A256CBC-HS512", nil, nil, 64)
	if bytes.Equal(long[:32], long[32:]) {
		t.Error("the second round repeated the first, so the round counter did not advance")
	}

	if bytes.Equal(concatKDF(sharedSecret, "A256CBC-HS512", nil, nil, 16), long[:16]) {
		t.Error("keydatalen did not affect the derivation, so SuppPubInfo is not being hashed")
	}
}

func TestConcatKDFBindsItsContext(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{1}, 32)
	baseline := concatKDF(sharedSecret, "A128GCM", []byte("Alice"), []byte("Bob"), 16)

	for _, variation := range []struct {
		name    string
		derived []byte
	}{
		{"Z", concatKDF(bytes.Repeat([]byte{2}, 32), "A128GCM", []byte("Alice"), []byte("Bob"), 16)},
		{"AlgorithmID", concatKDF(sharedSecret, "A128CBC-HS256", []byte("Alice"), []byte("Bob"), 16)},
		{"PartyUInfo", concatKDF(sharedSecret, "A128GCM", []byte("Carol"), []byte("Bob"), 16)},
		{"PartyVInfo", concatKDF(sharedSecret, "A128GCM", []byte("Alice"), []byte("Dave"), 16)},

		{"the boundary between apu and apv", concatKDF(sharedSecret, "A128GCM", []byte("Ali"), []byte("ceBob"), 16)},
	} {
		if bytes.Equal(baseline, variation.derived) {
			t.Errorf("changing %s did not change the derived key", variation.name)
		}
	}
}
