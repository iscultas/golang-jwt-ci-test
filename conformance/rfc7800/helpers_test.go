package rfc7800_test

import (
	"crypto"
	"crypto/sha256"
)

func crypto256() crypto.Hash { return crypto.SHA256 }

func secret() []byte {
	key := sha256.Sum256([]byte("rfc7800 conformance"))

	return key[:]
}
