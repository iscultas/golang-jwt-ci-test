package jwa_test

import (
	"crypto/mldsa"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

var mldsaAlgorithms = []struct {
	name       string
	algorithm  *jwa.MLDSAAlgorithm
	parameters mldsa.Parameters
}{
	{"ML-DSA-44", jwa.MLDSA44(), mldsa.MLDSA44()},
	{"ML-DSA-65", jwa.MLDSA65(), mldsa.MLDSA65()},
	{"ML-DSA-87", jwa.MLDSA87(), mldsa.MLDSA87()},
}

func generateMLDSAKey(t *testing.T, parameters mldsa.Parameters) *mldsa.PrivateKey {
	t.Helper()

	privateKey, err := mldsa.GenerateKey(parameters)
	if err != nil {
		t.Fatalf("cannot generate %s key: %v", parameters, err)
	}

	return privateKey
}

func TestMLDSARoundTrip(t *testing.T) {
	for _, algorithm := range mldsaAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			privateKey := generateMLDSAKey(t, algorithm.parameters)
			token := []byte("token")

			signature, err := algorithm.algorithm.Sign(token, privateKey)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			if len(signature) != algorithm.parameters.SignatureSize() {
				t.Errorf(
					"got a signature of %d octets, want %d", len(signature), algorithm.parameters.SignatureSize(),
				)
			}

			if err := algorithm.algorithm.Verify(token, signature, privateKey.PublicKey()); err != nil {
				t.Errorf("cannot verify: %v", err)
			}
		})
	}
}

func TestMLDSARejectsWrongKeyType(t *testing.T) {
	for _, algorithm := range mldsaAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			privateKey := generateMLDSAKey(t, algorithm.parameters)

			_, err := algorithm.algorithm.Sign([]byte("token"), privateKey.PublicKey())
			if !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("signing with a public key: got error %v, want %v", err, jwa.ErrInvalidKeyType)
			}

			signature := make([]byte, algorithm.parameters.SignatureSize())

			if err := algorithm.algorithm.Verify([]byte("token"), signature, privateKey); !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("verifying with a private key: got error %v, want %v", err, jwa.ErrInvalidKeyType)
			}
		})
	}
}

func TestMLDSARejectsZeroKey(t *testing.T) {
	for _, algorithm := range mldsaAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			_, err := algorithm.algorithm.Sign([]byte("token"), new(mldsa.PrivateKey))
			if !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("signing: got error %v, want %v", err, jwa.ErrInvalidKeyType)
			}

			signature := make([]byte, algorithm.parameters.SignatureSize())

			if err := algorithm.algorithm.Verify([]byte("token"), signature, new(mldsa.PublicKey)); !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("verifying: got error %v, want %v", err, jwa.ErrInvalidKeyType)
			}
		})
	}
}

func TestMLDSARejectsOtherParameterSet(t *testing.T) {
	privateKey := generateMLDSAKey(t, mldsa.MLDSA44())

	for _, algorithm := range mldsaAlgorithms[1:] {
		t.Run(algorithm.name, func(t *testing.T) {
			_, err := algorithm.algorithm.Sign([]byte("token"), privateKey)
			if !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("signing: got error %v, want %v", err, jwa.ErrInvalidKeyType)
			}

			signature := make([]byte, algorithm.parameters.SignatureSize())

			err = algorithm.algorithm.Verify([]byte("token"), signature, privateKey.PublicKey())
			if !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("verifying: got error %v, want %v", err, jwa.ErrInvalidKeyType)
			}
		})
	}
}

func TestMLDSARejectsMalformedSignature(t *testing.T) {
	for _, algorithm := range mldsaAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			publicKey := generateMLDSAKey(t, algorithm.parameters).PublicKey()

			err := algorithm.algorithm.Verify([]byte("token"), []byte("short"), publicKey)
			if !errors.Is(err, jwa.ErrMalformedSignature) {
				t.Errorf("got error %v, want %v", err, jwa.ErrMalformedSignature)
			}
		})
	}
}

func TestMLDSARejectsWrongSignature(t *testing.T) {
	for _, algorithm := range mldsaAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			publicKey := generateMLDSAKey(t, algorithm.parameters).PublicKey()
			signature := make([]byte, algorithm.parameters.SignatureSize())

			err := algorithm.algorithm.Verify([]byte("token"), signature, publicKey)
			if !errors.Is(err, jwa.ErrSignatureMismatch) {
				t.Errorf("got error %v, want %v", err, jwa.ErrSignatureMismatch)
			}
		})
	}
}

func TestMLDSAIdentifiers(t *testing.T) {
	for _, algorithm := range mldsaAlgorithms {
		if algorithm.algorithm.String() != algorithm.name {
			t.Errorf("got %s, want %s", algorithm.algorithm, algorithm.name)
		}
	}
}
