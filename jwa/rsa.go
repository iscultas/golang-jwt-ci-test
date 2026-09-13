package jwa

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

const rsaModulusBits = 2048

func checkRSAModulus(algorithm Algorithm, modulus *big.Int) error {
	if bits := modulus.BitLen(); bits < rsaModulusBits {
		return fmt.Errorf("%w: %s: got a %d-bit modulus, want %d", ErrWeakKey, algorithm, bits, rsaModulusBits)
	}

	return nil
}

func (algorithm *signingAlgorithm) rsaSigningKey(token []byte, key any) (*rsa.PrivateKey, []byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, invalidKeyType(algorithm, key, "*rsa.PrivateKey")
	}

	if err := checkRSAModulus(algorithm, privateKey.N); err != nil {
		return nil, nil, err
	}

	digest, err := algorithm.digest(token)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, digest, nil
}

func (algorithm *signingAlgorithm) rsaVerificationKey(
	unsignedToken []byte, key any,
) (*rsa.PublicKey, []byte, error) {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, nil, invalidKeyType(algorithm, key, "*rsa.PublicKey")
	}

	if err := checkRSAModulus(algorithm, publicKey.N); err != nil {
		return nil, nil, err
	}

	digest, err := algorithm.digest(unsignedToken)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, digest, nil
}

func rsaVerificationResult(algorithm Algorithm, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%w: %s: %w", ErrSignatureMismatch, algorithm, err)
}
