package rfc6979_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

// RFC 6979 Appendix A.2 (test vectors): the published (r, s) for each of the
// three JWS pairings.
//
// This is the assertion that separates RFC 6979 from merely repeatable signing.
// An implementation deriving its nonce by hashing the message through any other
// construction would still be deterministic, still self-consistent, and still
// disagree with every other implementation in the world -- which only a
// published vector can catch.
//
// rfc-req: RFC6979-SA_2-R01
func TestPublishedVectorsAreReproduced(t *testing.T) {
	for _, testCase := range vectors {
		t.Run(testCase.name, func(t *testing.T) {
			signer, ok := algorithm(t, testCase).(jwa.Signer)
			if !ok {
				t.Fatalf("%s cannot sign", testCase.algorithm)
			}

			signature, err := signer.Sign([]byte(testCase.message), privateKey(t, testCase))
			if err != nil {
				t.Fatalf("appendix %s: cannot sign: %v", testCase.appendix, err)
			}

			length := coordinateLength(testCase.curve)
			if len(signature) != length*2 {
				t.Fatalf("got a %d-octet signature, want %d", len(signature), length*2)
			}

			for _, half := range []struct {
				name      string
				got, want *big.Int
			}{
				{"r", new(big.Int).SetBytes(signature[:length]), integer(t, testCase.r)},
				{"s", new(big.Int).SetBytes(signature[length:]), integer(t, testCase.s)},
			} {
				if half.got.Cmp(half.want) != 0 {
					t.Errorf(
						"appendix %s: %s mismatch:\n got %x\nwant %x",
						testCase.appendix, half.name, half.got, half.want,
					)
				}
			}
		})
	}
}

// RFC 6979 Appendix A.2 (test vectors): the published signatures, verified
// rather than reproduced.
//
// Asserted separately because it is the compatibility claim RFC 8725
// section 3.2 makes -- that the deterministic approach "is completely compatible
// with existing ECDSA verifiers and so can be implemented without new algorithm
// identifiers being required". Verification must be indifferent to how the nonce
// was chosen, and a verifier that somehow was not would pass the reproduction
// test above while rejecting every signature made anywhere else.
//
// rfc-req: RFC6979-SA_2-R02
func TestPublishedSignaturesVerify(t *testing.T) {
	for _, testCase := range vectors {
		t.Run(testCase.name, func(t *testing.T) {
			verifier, ok := algorithm(t, testCase).(jwa.Verifier)
			if !ok {
				t.Fatalf("%s cannot verify", testCase.algorithm)
			}

			length := coordinateLength(testCase.curve)
			signature := make([]byte, length*2)
			integer(t, testCase.r).FillBytes(signature[:length])
			integer(t, testCase.s).FillBytes(signature[length:])

			if err := verifier.Verify(
				[]byte(testCase.message), signature, &privateKey(t, testCase).PublicKey,
			); err != nil {
				t.Errorf("appendix %s: the published signature did not verify: %v", testCase.appendix, err)
			}
		})
	}
}

// RFC 6979 Appendix A.2 (test vectors): each appendix publishes the key pair as
// a private key x alongside the public point U = xG.
//
// Costs nothing and is asserted on its own so that a mistranscribed private key
// fails as what it is, rather than surfacing as an unexplained signature
// mismatch above.
//
// rfc-req: RFC6979-SA_2-R03
func TestPublishedKeysDeriveTheirPublishedPublicKey(t *testing.T) {
	for _, testCase := range vectors {
		t.Run(testCase.name, func(t *testing.T) {
			key := privateKey(t, testCase)

			for _, coordinate := range []struct {
				name      string
				got, want *big.Int
			}{
				{"Ux", key.X, integer(t, testCase.publicKeyX)},
				{"Uy", key.Y, integer(t, testCase.publicKeyY)},
			} {
				if coordinate.got.Cmp(coordinate.want) != 0 {
					t.Errorf(
						"appendix %s: %s mismatch:\n got %x\nwant %x",
						testCase.appendix, coordinate.name, coordinate.got, coordinate.want,
					)
				}
			}
		})
	}
}

// RFC 6979 section 3.2: k is generated from the private key and the message hash
// through an HMAC_DRBG, with nothing drawn from a random source.
//
// The property the construction exists to provide. RFC8725-S3_2-R07 observes the
// same thing; it is asserted here too because a regression to randomised signing
// would break this long before anyone noticed a vector, and because this covers
// all three algorithms rather than the one the RFC 8725 suite exercises.
//
// rfc-req: RFC6979-S3_2-R01
func TestSigningIsDeterministic(t *testing.T) {
	for _, testCase := range vectors {
		t.Run(testCase.name, func(t *testing.T) {
			signer := algorithm(t, testCase).(jwa.Signer)
			key := privateKey(t, testCase)

			first, err := signer.Sign([]byte(testCase.message), key)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			second, err := signer.Sign([]byte(testCase.message), key)
			if err != nil {
				t.Fatalf("cannot sign again: %v", err)
			}

			if string(first) != string(second) {
				t.Errorf(
					"two signatures over the same input differ:\n%x\n%x",
					first, second,
				)
			}
		})
	}
}

// RFC 6979 section 3.2: the DRBG is seeded with the message hash as well as the
// private key, so k is a function of both.
//
// The half of the property that determinism alone does not give. A nonce derived
// from the key by itself would repeat across messages, and two ECDSA signatures
// sharing a nonce hand the private key to anyone holding both -- which is the
// attack RFC 8725 section 3.2 warns of. A suite asserting only that signing
// repeats would be checking the safer half.
//
// rfc-req: RFC6979-S3_2-R02
func TestNonceVariesWithTheMessage(t *testing.T) {
	for _, testCase := range vectors {
		t.Run(testCase.name, func(t *testing.T) {
			signer := algorithm(t, testCase).(jwa.Signer)
			key := privateKey(t, testCase)

			signature, err := signer.Sign([]byte(testCase.message), key)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			other, err := signer.Sign([]byte(testCase.message+" (different)"), key)
			if err != nil {
				t.Fatalf("cannot sign the second message: %v", err)
			}

			if string(signature) == string(other) {
				t.Error("two different messages produced the same signature under one key")
			}

			length := coordinateLength(testCase.curve)
			if string(signature[:length]) == string(other[:length]) {
				t.Errorf("R repeated across two messages, so k did not depend on the message: %x", signature[:length])
			}
		})
	}
}

func algorithm(t *testing.T, testCase vector) jwa.Algorithm {
	t.Helper()

	resolved, ok := jwa.ByName(testCase.algorithm)
	if !ok {
		t.Fatalf("%s is not a registered algorithm", testCase.algorithm)
	}

	return resolved
}

func privateKey(t *testing.T, testCase vector) *ecdsa.PrivateKey {
	t.Helper()

	scalar := make([]byte, coordinateLength(testCase.curve))
	integer(t, testCase.privateKey).FillBytes(scalar)

	key, err := ecdsa.ParseRawPrivateKey(testCase.curve, scalar)
	if err != nil {
		t.Fatalf("cannot parse the published private key: %v", err)
	}

	return key
}

func integer(t *testing.T, value string) *big.Int {
	t.Helper()

	number, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("cannot read %q as a hex integer", value)
	}

	return number
}

func coordinateLength(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}
