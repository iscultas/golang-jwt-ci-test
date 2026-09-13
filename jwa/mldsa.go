package jwa

import (
	"crypto/mldsa"
	"fmt"
)

// MLDSAAlgorithm is ML-DSA, the Module-Lattice-Based Digital Signature Standard
// of US NIST FIPS 204. RFC 9964 gives it three "alg" identifiers, one for each
// parameter set of FIPS 204 Table 1.
//
// The three parameter sets are three security levels of one scheme. Thus one
// type supplies the three, and the parameters field keeps them apart. A key of
// one set cannot sign or verify with the identifier of a different set.
//
// ML-DSA is a post-quantum scheme, and its keys and signatures are larger than
// those of each other algorithm in this package. The smallest public key has
// 1312 octets and the smallest signature has 2420 octets, against 32 and 64 for
// Ed25519. This size makes ML-DSA unsuitable for some deployments, and a JWK
// Thumbprint is the way to name a key and not repeat it.
type MLDSAAlgorithm struct {
	signingAlgorithm

	parameters mldsa.Parameters
}

var (
	mldsa44 = &MLDSAAlgorithm{signingAlgorithm{"ML-DSA-44", 0}, mldsa.MLDSA44()}
	mldsa65 = &MLDSAAlgorithm{signingAlgorithm{"ML-DSA-65", 0}, mldsa.MLDSA65()}
	mldsa87 = &MLDSAAlgorithm{signingAlgorithm{"ML-DSA-87", 0}, mldsa.MLDSA87()}
)

// MLDSA44 returns the "ML-DSA-44" identifier.
func MLDSA44() *MLDSAAlgorithm { return mldsa44 }

// MLDSA65 returns the "ML-DSA-65" identifier.
func MLDSA65() *MLDSAAlgorithm { return mldsa65 }

// MLDSA87 returns the "ML-DSA-87" identifier.
func MLDSA87() *MLDSAAlgorithm { return mldsa87 }

func (algorithm *MLDSAAlgorithm) checkPrivateKey(key any) (*mldsa.PrivateKey, error) {
	privateKey, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "*mldsa.PrivateKey")
	}

	if *privateKey == (mldsa.PrivateKey{}) {
		return nil, fmt.Errorf("%w: %s: zero private key", ErrInvalidKeyType, algorithm)
	}

	if parameters := privateKey.PublicKey().Parameters(); parameters != algorithm.parameters {
		return nil, fmt.Errorf(
			"%w: %s: private key of %s", ErrInvalidKeyType, algorithm, parameters,
		)
	}

	return privateKey, nil
}

// Sign returns the ML-DSA signature of token. It accepts only an
// [*mldsa.PrivateKey] of the parameter set that the identifier of the algorithm
// names.
//
// Sign gives [ErrInvalidKeyType] for a key of a different parameter set. The
// three identifiers are three algorithms, and a signature from a key of one set
// is not a signature that a verifier of a different set accepts.
func (algorithm *MLDSAAlgorithm) Sign(token []byte, key any) ([]byte, error) {
	privateKey, err := algorithm.checkPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return privateKey.Sign(nil, token, nil)
}

// Verify gives a nil error only for a correct signature on unsignedToken. It
// accepts only an [*mldsa.PublicKey] of the parameter set that the identifier of
// the algorithm names, and gives [ErrSignatureMismatch] for a signature that the
// key does not agree with.
//
// An ML-DSA signature has one width for each parameter set, which FIPS 204
// Table 2 gives. Verify gives [ErrMalformedSignature] for a different length.
// This makes a bad token different from a token with an incorrect signature.
func (algorithm *MLDSAAlgorithm) Verify(unsignedToken, signature []byte, key any) error {
	publicKey, ok := key.(*mldsa.PublicKey)
	if !ok {
		return invalidKeyType(algorithm, key, "*mldsa.PublicKey")
	}

	if *publicKey == (mldsa.PublicKey{}) {
		return fmt.Errorf("%w: %s: zero public key", ErrInvalidKeyType, algorithm)
	}

	if parameters := publicKey.Parameters(); parameters != algorithm.parameters {
		return fmt.Errorf("%w: %s: public key of %s", ErrInvalidKeyType, algorithm, parameters)
	}

	if size := algorithm.parameters.SignatureSize(); len(signature) != size {
		return fmt.Errorf(
			"%w: %s: got %d octets, want %d", ErrMalformedSignature, algorithm, len(signature), size,
		)
	}

	if mldsa.Verify(publicKey, unsignedToken, signature, nil) != nil {
		return fmt.Errorf("%w: %s", ErrSignatureMismatch, algorithm)
	}

	return nil
}
