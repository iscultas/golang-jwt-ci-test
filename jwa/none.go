package jwa

import "fmt"

// NoneAlgorithm is the "alg" value for an unsecured JWS. It makes the empty
// signature, and it accepts only the empty signature.
//
// The risk is in the use of this algorithm, not in the signature check. An
// unsecured JWS gives no data about its producer. Thus none must not be in a
// verification allowlist for tokens from an unknown source.
type NoneAlgorithm struct {
	signingAlgorithm
}

var none = &NoneAlgorithm{signingAlgorithm{"none", 0}}

// None returns the "none" algorithm.
//
// A caller that uses [Algorithms] as a verification allowlist must remove this
// algorithm first. See [NoneAlgorithm] for the risk.
func None() *NoneAlgorithm { return none }

// Sign returns the empty signature. An unsecured JWS has no other value. Sign
// ignores the key.
func (algorithm *NoneAlgorithm) Sign(token []byte, jwk any) ([]byte, error) {
	return []byte{}, nil
}

// Verify gives a nil error only for an empty signature.
//
// A token with signature octets and an "alg" value of "none" is not an unsecured
// JWS with bad syntax. Such a token names the one algorithm that does not sign,
// but it transmits a signature. Thus Verify gives [ErrMalformedSignature] for
// it.
func (algorithm *NoneAlgorithm) Verify(unsignedToken, signature []byte, key any) error {
	if len(signature) != 0 {
		return fmt.Errorf(
			"%w: %s: got %d octets, want 0", ErrMalformedSignature, algorithm, len(signature),
		)
	}

	return nil
}
