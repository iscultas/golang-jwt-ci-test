package jwa

import (
	"crypto/ed25519"
	"fmt"
)

// EdDSAAlgorithm is EdDSA with the Ed25519 parameter set of RFC 8032
// section 5.1.
//
// It supplies two "alg" identifiers: the general "EdDSA" identifier, and
// "Ed25519" as its replacement. The two identifiers are the same operation on
// the same key. Only the "alg" value is different, thus one type supplies the
// two.
type EdDSAAlgorithm struct {
	signingAlgorithm
}

var (
	eddsa = &EdDSAAlgorithm{signingAlgorithm{"EdDSA", 0}}

	ed25519Algorithm = &EdDSAAlgorithm{signingAlgorithm{"Ed25519", 0}}
)

// EdDSA returns the general "EdDSA" identifier.
//
// RFC 9864 section 4.1.2 makes this identifier deprecated and gives [Ed25519] as
// its replacement. A deprecated identifier stays permitted. Section 4.4 gives
// the two identifiers as different, and only Ed25519 has a MUST NOT. Thus this
// package keeps EdDSA, and it verifies tokens that are in use at this time. A new
// deployment must use [Ed25519].
func EdDSA() *EdDSAAlgorithm { return eddsa }

// Ed25519 returns the "fully-specified" "Ed25519" identifier.
//
// Ed25519 signs and verifies accurately as [EdDSA] does, on the same keys. The
// name of the curve is in the identifier. Thus a protocol that agrees on "alg"
// values only can know which curve it agreed to. The "EdDSA" identifier does not
// give this data.
func Ed25519() *EdDSAAlgorithm { return ed25519Algorithm }

// Sign returns the Ed25519 signature of token. It accepts only an
// [ed25519.PrivateKey] of 64 octets.
//
// Sign gives [ErrInvalidKeyType] for a key of a different length, because
// [ed25519.Sign] panics for such a key. A key of the incorrect length can come
// from a parsed JWK.
func (algorithm *EdDSAAlgorithm) Sign(token []byte, key any) ([]byte, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "ed25519.PrivateKey")
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"%w: %s: private key of %d octets, want %d",
			ErrInvalidKeyType, algorithm, len(privateKey), ed25519.PrivateKeySize,
		)
	}

	return ed25519.Sign(privateKey, token), nil
}

// Verify gives a nil error only for a correct signature on unsignedToken. It
// accepts only an [ed25519.PublicKey] of 32 octets, and gives
// [ErrSignatureMismatch] for a signature that the key does not agree with.
//
// An Ed25519 signature always has 64 octets. Verify gives
// [ErrMalformedSignature] for a different length. This makes a bad token
// different from a token with an incorrect signature.
func (algorithm *EdDSAAlgorithm) Verify(unsignedToken, signature []byte, key any) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return invalidKeyType(algorithm, key, "ed25519.PublicKey")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"%w: %s: public key of %d octets, want %d",
			ErrInvalidKeyType, algorithm, len(publicKey), ed25519.PublicKeySize,
		)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf(
			"%w: %s: got %d octets, want %d",
			ErrMalformedSignature, algorithm, len(signature), ed25519.SignatureSize,
		)
	}

	if !ed25519.Verify(publicKey, unsignedToken, signature) {
		return fmt.Errorf("%w: %s", ErrSignatureMismatch, algorithm)
	}

	return nil
}
