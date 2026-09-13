package jwa

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/iscultas/jwt-go/internal/curve"
)

// ECDHESAlgorithm is key agreement with Elliptic Curve Diffie-Hellman Ephemeral
// Static. The producer makes a new key pair and agrees a secret with the static
// public key of the recipient. It then sends that secret through the Concat
// KDF. The ephemeral public key moves with the token as the "epk" Header
// Parameter.
//
// There are two modes, and this type supplies the two. In Direct Key Agreement
// the derived key is the CEK, and the algorithm wraps no key.
//
// In Key Agreement with Key Wrapping the derived key is a key encryption key
// for one of the AES Key Wrap algorithms. The CEK then comes from a different
// source.
//
// The two modes are different in three positions only: the length of the derived
// key, the AlgorithmID that goes to the KDF, and the JWE Encrypted Key, which is
// empty in Direct Key Agreement.
type ECDHESAlgorithm struct {
	name string

	keyWrap *AESKeyWrap
}

var (
	ecdhES       = &ECDHESAlgorithm{"ECDH-ES", nil}
	ecdhESA128KW = &ECDHESAlgorithm{"ECDH-ES+A128KW", a128kw}
	ecdhESA192KW = &ECDHESAlgorithm{"ECDH-ES+A192KW", a192kw}
	ecdhESA256KW = &ECDHESAlgorithm{"ECDH-ES+A256KW", a256kw}
)

// ECDHES returns ECDH-ES in Direct Key Agreement mode. The derived key is the
// CEK, and the JWE Encrypted Key is empty.
func ECDHES() *ECDHESAlgorithm { return ecdhES }

// ECDHESA128KW returns ECDH-ES with AES-128 key wrapping.
func ECDHESA128KW() *ECDHESAlgorithm { return ecdhESA128KW }

// ECDHESA192KW returns ECDH-ES with AES-192 key wrapping.
func ECDHESA192KW() *ECDHESAlgorithm { return ecdhESA192KW }

// ECDHESA256KW returns ECDH-ES with AES-256 key wrapping.
func ECDHESA256KW() *ECDHESAlgorithm { return ecdhESA256KW }

// String returns the "alg" value of this algorithm, for example "ECDH-ES".
func (algorithm *ECDHESAlgorithm) String() string { return algorithm.name }

func (algorithm *ECDHESAlgorithm) derivedKeySize(encryption ContentEncrypter) int {
	if algorithm.keyWrap == nil {
		return encryption.KeySize()
	}

	return algorithm.keyWrap.keySize
}

func (algorithm *ECDHESAlgorithm) algorithmID(encryption ContentEncrypter) string {
	if algorithm.keyWrap == nil {
		return encryption.String()
	}

	return algorithm.name
}

// ErrIndistinctAgreementParties is the error for "apu" and "apv" values that are
// equal.
//
// RFC 7518 section 4.6.2 gives the rule: "The 'apu' and 'apv' values MUST be
// distinct, when used." The Concat KDF receives the two values as PartyUInfo and
// PartyVInfo. Their function is to connect the derived key to the identity of
// each party. Equal values let each contribution replace the other, and the
// connection then has no value.
//
// This package gives the error in the two directions. A key that this package
// does not derive is not a key that it accepts from a token.
var ErrIndistinctAgreementParties = errors.New("jwa: apu and apv are not distinct")

func agreementPrivateKey(algorithm Algorithm, key any) (*ecdh.PrivateKey, error) {
	switch key := key.(type) {
	case *ecdh.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		privateKey, err := key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidKeyType, algorithm, err)
		}

		return privateKey, nil
	}

	return nil, invalidKeyType(algorithm, key, "*ecdsa.PrivateKey or *ecdh.PrivateKey")
}

func agreementPublicKey(algorithm Algorithm, key any) (*ecdh.PublicKey, error) {
	switch key := key.(type) {
	case *ecdh.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		publicKey, err := key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidKeyType, algorithm, err)
		}

		return publicKey, nil
	}

	return nil, invalidKeyType(algorithm, key, "*ecdsa.PublicKey or *ecdh.PublicKey")
}

func (algorithm *ECDHESAlgorithm) agree(
	privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	if len(parameters.AgreementPartyUInfo) != 0 &&
		bytes.Equal(parameters.AgreementPartyUInfo, parameters.AgreementPartyVInfo) {
		return nil, fmt.Errorf("%w: %s", ErrIndistinctAgreementParties, algorithm)
	}

	if privateKey.Curve() != publicKey.Curve() {
		return nil, fmt.Errorf(
			"%w: %s: the ephemeral key is on %s, the recipient key on %s",
			ErrInvalidKeyType, algorithm, curve.Name(publicKey.Curve()), curve.Name(privateKey.Curve()),
		)
	}

	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidKeyType, algorithm, err)
	}

	return concatKDF(
		sharedSecret,
		algorithm.algorithmID(encryption),
		parameters.AgreementPartyUInfo,
		parameters.AgreementPartyVInfo,
		algorithm.derivedKeySize(encryption),
	), nil
}

func (algorithm *ECDHESAlgorithm) deriveKeyEncryptionKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	publicKey, err := agreementPublicKey(algorithm, key)
	if err != nil {
		return nil, err
	}

	ephemeralKey, publishableKey, err := newEphemeralKey(algorithm, key, publicKey)
	if err != nil {
		return nil, err
	}

	derivedKey, err := algorithm.agree(ephemeralKey, publicKey, encryption, parameters)
	if err != nil {
		return nil, err
	}

	parameters.EphemeralPublicKey = publishableKey

	return derivedKey, nil
}

func newEphemeralKey(
	algorithm Algorithm, key any, publicKey *ecdh.PublicKey,
) (*ecdh.PrivateKey, any, error) {
	ephemeralKey, err := publicKey.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	switch key := key.(type) {
	case *ecdh.PublicKey:
		return ephemeralKey, ephemeralKey.PublicKey(), nil
	case *ecdsa.PublicKey:
		ephemeralPublicKey, err := ecdsa.ParseUncompressedPublicKey(
			key.Curve, ephemeralKey.PublicKey().Bytes(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: %w", ErrInvalidKeyType, algorithm, err)
		}

		return ephemeralKey, ephemeralPublicKey, nil
	}

	return nil, nil, invalidKeyType(algorithm, key, "*ecdsa.PublicKey or *ecdh.PublicKey")
}

// EncryptKey returns the CEK and the JWE Encrypted Key.
//
// In Key Agreement with Key Wrapping, EncryptKey makes a new CEK and wraps it.
// In Direct Key Agreement, the derived key is the CEK and the JWE Encrypted Key
// is empty.
func (algorithm *ECDHESAlgorithm) EncryptKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	if algorithm.keyWrap != nil {
		return encryptKey(algorithm, key, encryption, parameters)
	}

	derivedKey, err := algorithm.deriveKeyEncryptionKey(key, encryption, parameters)
	if err != nil {
		return nil, nil, err
	}

	return derivedKey, []byte{}, nil
}

// WrapKey returns the JWE Encrypted Key for the given cek. It agrees a new key
// for each call.
//
// WrapKey gives [ErrDirectKeyManagement] in Direct Key Agreement mode. This
// type supplies the two modes. Thus it cannot reject the operation with a
// missing method, as [Direct] does. Thus it rejects the operation at runtime.
func (algorithm *ECDHESAlgorithm) WrapKey(
	cek []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	if algorithm.keyWrap == nil {
		return nil, fmt.Errorf("%w: %s", ErrDirectKeyManagement, algorithm)
	}

	derivedKey, err := algorithm.deriveKeyEncryptionKey(key, encryption, parameters)
	if err != nil {
		return nil, err
	}

	return algorithm.keyWrap.WrapKey(cek, derivedKey, encryption, parameters)
}

// DecryptKey returns the CEK. It reads the "epk", "apu" and "apv" values from
// parameters and does the agreement again.
//
// In Direct Key Agreement, DecryptKey gives [ErrDecryptionFailed] if encryptedKey
// is not empty, or if the derived key does not have the length that encryption
// gives.
func (algorithm *ECDHESAlgorithm) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	privateKey, err := agreementPrivateKey(algorithm, key)
	if err != nil {
		return nil, err
	}

	ephemeralPublicKey, err := agreementPublicKey(algorithm, parameters.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}

	derivedKey, err := algorithm.agree(privateKey, ephemeralPublicKey, encryption, parameters)
	if err != nil {
		return nil, err
	}

	if algorithm.keyWrap == nil {
		if len(encryptedKey) != 0 {
			return nil, ErrDecryptionFailed
		}

		if err := checkContentEncryptionKeySize(encryption, derivedKey); err != nil {
			return nil, err
		}

		return derivedKey, nil
	}

	return algorithm.keyWrap.DecryptKey(encryptedKey, derivedKey, encryption, parameters)
}
