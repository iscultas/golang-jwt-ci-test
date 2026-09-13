package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ECDSA signs with one of the three curve and hash pairs of RFC 7518
// section 3.4. The curve is a property of the algorithm, not of the key. ES256 is
// "ECDSA using P-256 and SHA-256", and its rule that "the JWS Signature value
// MUST be a 64-octet sequence" applies to all keys that a caller supplies.
//
// Sign is deterministic, as RFC 6979 gives it. RFC 8725 section 3.2 recommends
// this because ECDSA algorithms "require[s] a unique random value for every
// message that is signed. If even just a few bits of the random value are
// predictable across multiple messages, then the security of the signature scheme
// may be compromised. In the worst case, the private key may be recoverable by an
// attacker." This package calculates the nonce from the key and the message. Thus
// it does not use the random source. Verify is not different, because the result
// is a usual ECDSA signature. The same RFC records that the procedure "is
// completely compatible with available ECDSA verifiers".
type ECDSA struct {
	signingAlgorithm

	curve elliptic.Curve
}

var (
	es256 = &ECDSA{signingAlgorithm{"ES256", crypto.SHA256}, elliptic.P256()}
	es384 = &ECDSA{signingAlgorithm{"ES384", crypto.SHA384}, elliptic.P384()}
	es512 = &ECDSA{signingAlgorithm{"ES512", crypto.SHA512}, elliptic.P521()}
)

// ES256 returns ECDSA with the P-256 curve and SHA-256. The signature has 64
// octets.
func ES256() *ECDSA { return es256 }

// ES384 returns ECDSA with the P-384 curve and SHA-384. The signature has 96
// octets.
func ES384() *ECDSA { return es384 }

// ES512 returns ECDSA with the P-521 curve and SHA-512. The signature has 132
// octets.
func ES512() *ECDSA { return es512 }

func coordinateLength(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

func (algorithm *ECDSA) checkCurve(curve elliptic.Curve) error {
	if curve != algorithm.curve {
		return fmt.Errorf(
			"%w: %s: got a %s key, want %s", ErrInvalidKeyType, algorithm, curveName(curve), algorithm.curve.Params().Name,
		)
	}

	return nil
}

func curveName(curve elliptic.Curve) string {
	if curve == nil {
		return "curveless"
	}

	return curve.Params().Name
}

// Sign returns the ECDSA signature of token. It accepts only an
// [*ecdsa.PrivateKey] on the curve of this algorithm, and gives
// [ErrInvalidKeyType] for a key on a different curve.
//
// The signature is the two integers R and S at a constant width. It is not
// ASN.1 DER.
func (algorithm *ECDSA) Sign(token []byte, key any) ([]byte, error) {
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "*ecdsa.PrivateKey")
	}

	if err := algorithm.checkCurve(privateKey.Curve); err != nil {
		return nil, err
	}

	digest, err := algorithm.digest(token)
	if err != nil {
		return nil, err
	}

	derSignature, err := privateKey.Sign(nil, digest, algorithm.hash)
	if err != nil {
		return nil, err
	}

	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSignature, &parsed); err != nil {
		return nil, err
	}

	length := coordinateLength(algorithm.curve)

	signature := make([]byte, length*2)
	parsed.R.FillBytes(signature[:length])
	parsed.S.FillBytes(signature[length:])

	return signature, nil
}

// Verify gives a nil error only for a correct signature on unsignedToken. It
// accepts only an [*ecdsa.PublicKey] on the curve of this algorithm, and gives
// [ErrSignatureMismatch] for a signature that the key does not agree with.
//
// Verify gives [ErrMalformedSignature] for a signature of a different length,
// because R and S have a constant width on each curve.
func (algorithm *ECDSA) Verify(unsignedToken, signature []byte, key any) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return invalidKeyType(algorithm, key, "*ecdsa.PublicKey")
	}

	if err := algorithm.checkCurve(publicKey.Curve); err != nil {
		return err
	}

	length := coordinateLength(algorithm.curve)
	if len(signature) != length*2 {
		return fmt.Errorf(
			"%w: %s: got %d octets, want %d", ErrMalformedSignature, algorithm, len(signature), length*2,
		)
	}

	digest, err := algorithm.digest(unsignedToken)
	if err != nil {
		return err
	}

	r := new(big.Int).SetBytes(signature[:length])
	s := new(big.Int).SetBytes(signature[length:])

	if !ecdsa.Verify(publicKey, digest, r, s) {
		return fmt.Errorf("%w: %s", ErrSignatureMismatch, algorithm)
	}

	return nil
}
