package jwa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// RSASSAPKCS1V15 is RSASSA-PKCS1-v1_5 with a SHA-2 hash function.
//
// The minimum modulus is 2048 bits. Sign and Verify give [ErrWeakKey] for a
// smaller modulus.
type RSASSAPKCS1V15 struct {
	signingAlgorithm
}

var (
	rs256 = &RSASSAPKCS1V15{signingAlgorithm{"RS256", crypto.SHA256}}
	rs384 = &RSASSAPKCS1V15{signingAlgorithm{"RS384", crypto.SHA384}}
	rs512 = &RSASSAPKCS1V15{signingAlgorithm{"RS512", crypto.SHA512}}
)

// RS256 returns RSASSA-PKCS1-v1_5 with SHA-256.
func RS256() *RSASSAPKCS1V15 { return rs256 }

// RS384 returns RSASSA-PKCS1-v1_5 with SHA-384.
func RS384() *RSASSAPKCS1V15 { return rs384 }

// RS512 returns RSASSA-PKCS1-v1_5 with SHA-512.
func RS512() *RSASSAPKCS1V15 { return rs512 }

// Sign returns the RSASSA-PKCS1-v1_5 signature of token. It accepts only an
// [*rsa.PrivateKey] with a modulus of 2048 bits or more.
func (algorithm *RSASSAPKCS1V15) Sign(token []byte, key any) ([]byte, error) {
	privateKey, digest, err := algorithm.rsaSigningKey(token, key)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, privateKey, algorithm.hash, digest)
}

// Verify gives a nil error only for a correct RSASSA-PKCS1-v1_5 signature. It
// accepts only an [*rsa.PublicKey] with a modulus of 2048 bits or more.
//
// An incorrect signature gives [ErrSignatureMismatch] with the error from the
// standard library attached. Thus a caller can see the cause.
func (algorithm *RSASSAPKCS1V15) Verify(unsignedToken, signature []byte, key any) error {
	publicKey, digest, err := algorithm.rsaVerificationKey(unsignedToken, key)
	if err != nil {
		return err
	}

	return rsaVerificationResult(algorithm, rsa.VerifyPKCS1v15(publicKey, algorithm.hash, digest, signature))
}
