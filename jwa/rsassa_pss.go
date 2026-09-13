package jwa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// RSASSAPSS is RSASSA-PSS with a SHA-2 hash function and MGF1.
//
// The minimum modulus is 2048 bits. Sign and Verify give [ErrWeakKey] for a
// smaller modulus.
type RSASSAPSS struct {
	signingAlgorithm
}

var (
	ps256 = &RSASSAPSS{signingAlgorithm{"PS256", crypto.SHA256}}
	ps384 = &RSASSAPSS{signingAlgorithm{"PS384", crypto.SHA384}}
	ps512 = &RSASSAPSS{signingAlgorithm{"PS512", crypto.SHA512}}
)

// PS256 returns RSASSA-PSS with SHA-256 and MGF1 with SHA-256.
func PS256() *RSASSAPSS { return ps256 }

// PS384 returns RSASSA-PSS with SHA-384 and MGF1 with SHA-384.
func PS384() *RSASSAPSS { return ps384 }

// PS512 returns RSASSA-PSS with SHA-512 and MGF1 with SHA-512.
func PS512() *RSASSAPSS { return ps512 }

// Sign returns the RSASSA-PSS signature of token. It accepts only an
// [*rsa.PrivateKey] with a modulus of 2048 bits or more.
//
// The salt has the length of the hash output.
func (algorithm *RSASSAPSS) Sign(token []byte, key any) ([]byte, error) {
	privateKey, digest, err := algorithm.rsaSigningKey(token, key)
	if err != nil {
		return nil, err
	}

	return rsa.SignPSS(rand.Reader, privateKey, algorithm.hash, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       algorithm.hash,
	})
}

// Verify gives a nil error only for a correct RSASSA-PSS signature. It accepts
// only an [*rsa.PublicKey] with a modulus of 2048 bits or more. An incorrect
// signature gives [ErrSignatureMismatch].
//
// Verify accepts a salt of all lengths, but Sign writes only one length. The
// rule controls the producer of a signature, and a different producer can read
// it differently. To reject its correct signature decreases interoperability
// and makes the module no more correct.
func (algorithm *RSASSAPSS) Verify(unsignedToken, signature []byte, key any) error {
	publicKey, digest, err := algorithm.rsaVerificationKey(unsignedToken, key)
	if err != nil {
		return err
	}

	return rsaVerificationResult(algorithm, rsa.VerifyPSS(publicKey, algorithm.hash, digest, signature, nil))
}
