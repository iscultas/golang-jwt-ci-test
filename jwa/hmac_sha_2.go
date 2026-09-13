package jwa

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

// HMACSHA2 is HMAC with a SHA-2 hash function. It signs and verifies a JWS with
// one secret. The signer and the verifier use the same secret.
//
// The secret has a minimum length of the hash output. Sign and Verify
// give [ErrWeakKey] for a shorter secret.
type HMACSHA2 struct {
	signingAlgorithm
}

var (
	hs256 = &HMACSHA2{signingAlgorithm{"HS256", crypto.SHA256}}
	hs384 = &HMACSHA2{signingAlgorithm{"HS384", crypto.SHA384}}
	hs512 = &HMACSHA2{signingAlgorithm{"HS512", crypto.SHA512}}
)

// HS256 returns HMAC with SHA-256. The secret has 32 octets or more.
func HS256() *HMACSHA2 { return hs256 }

// HS384 returns HMAC with SHA-384. The secret has 48 octets or more.
func HS384() *HMACSHA2 { return hs384 }

// HS512 returns HMAC with SHA-512. The secret has 64 octets or more.
func HS512() *HMACSHA2 { return hs512 }

func (algorithm *HMACSHA2) mac(token []byte, key any) ([]byte, error) {
	secret, ok := key.([]byte)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "[]byte")
	}

	if size := algorithm.hash.Size(); len(secret) < size {
		return nil, fmt.Errorf("%w: %s: got %d octets, want %d", ErrWeakKey, algorithm, len(secret), size)
	}

	hash := hmac.New(algorithm.hash.New, secret)

	if _, err := hash.Write(token); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// Sign returns the HMAC of token. It accepts only a []byte secret as the key,
// and gives [ErrInvalidKeyType] for a different type. It gives [ErrWeakKey] for
// a secret that is shorter than the hash output.
func (algorithm *HMACSHA2) Sign(token []byte, key any) ([]byte, error) {
	return algorithm.mac(token, key)
}

// Verify gives a nil error only when signature is the HMAC of unsignedToken. It
// accepts only the same []byte secret that Sign used, and gives
// [ErrSignatureMismatch] for a different MAC. The compare has a constant time.
func (algorithm *HMACSHA2) Verify(unsignedToken, signature []byte, key any) error {
	mac, err := algorithm.mac(unsignedToken, key)
	if err != nil {
		return err
	}

	if !hmac.Equal(mac, signature) {
		return fmt.Errorf("%w: %s", ErrSignatureMismatch, algorithm)
	}

	return nil
}
