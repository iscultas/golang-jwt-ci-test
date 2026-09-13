package jwt

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

var (
	// ErrHeaderKeyRefused is the error when a [HeaderKeyPolicy] rejects the key
	// that a token holds. It also holds the error of the policy, thus a caller can
	// test for either error.
	ErrHeaderKeyRefused = errors.New("jwt: refused the key the token carries")

	// ErrPrivateHeaderKey is the error for a "jwk" header parameter with private
	// key material.
	//
	// RFC 7515 section 4.1.3 gives the parameter as "the public key that
	// corresponds to the key used to digitally sign the JWS". RFC 9449
	// section 4.3 gives the prohibition directly, as its seventh check. A private
	// key here comes from a producer that published its own secret, or from an
	// attacker. Neither value is a key for verification.
	ErrPrivateHeaderKey = errors.New("jwt: the jwk header parameter carries a private key")

	// ErrSymmetricHeaderKey is the error for a "jwk" header parameter with a
	// symmetric key.
	//
	// A protected header moves with the token to each party that receives it.
	// Thus a secret in that position is a secret that the producer published, and
	// a signature that it verifies gives no data about the producer.
	ErrSymmetricHeaderKey = errors.New("jwt: the jwk header parameter carries a symmetric key")
)

// HeaderKeyPolicy finds if a caller can use the key that a token holds to
// verify that token. A nil result accepts the key, and an error rejects it.
//
// The policy gets the full protected header, and not only the key. The key
// does not make a token-supplied key satisfactory. The cause is in the header:
//
//   - a "kid" value that the recipient pinned
//   - an "x5c" chain to a trust anchor that the recipient holds
//   - a "typ" value that identifies a protocol where self-signed proofs are
//     correct
//   - a thumbprint that a different authenticated message bound before
//
// These values are in the header and not in the key.
//
// This package calls a policy only after the checks in headerKey pass. Thus a
// policy does not check for private or symmetric material.
type HeaderKeyPolicy func(key *jwk.Key, protected *header.Header) error

// WithHeaderKey makes the key that a token holds a candidate for verification of
// that token, if policy accepts it. This option makes no change for a nil policy.
//
// This package adds the key to the candidates from the JWK Set of the caller, and
// does not replace them. Thus a token that verifies with a published key
// continues to verify. Only a token that verifies with no key gets a
// rejection. A caller with no key set can give a nil set and use this option
// only. That is the condition of a protocol where the key of the token is the
// only key.
//
// The options collect, and each policy must accept the key. A profile that must
// have this behavior adds its policy through this same option. Thus a caller
// that also gives a policy gets the two, and this package does not replace one
// with the other.
func WithHeaderKey(policy HeaderKeyPolicy) func(*VerificationConfig) {
	return func(config *VerificationConfig) {
		if policy == nil {
			return
		}

		config.headerKeys = append(config.headerKeys, policy)
	}
}

func headerKey(protected *header.Header) (*jwk.Key, error) {
	key := protected.JWK

	switch {
	case key != nil:
		if key.Type() == jwk.OctetSequence {
			return nil, ErrSymmetricHeaderKey
		}

		if key.IsPrivate() {
			return nil, ErrPrivateHeaderKey
		}

	case len(protected.X509CertificateChain) > 0:
		leaf, err := parseCertificate(protected.X509CertificateChain[0])
		if err != nil {
			return nil, err
		}

		key = jwk.NewKey(leaf.PublicKey)

	default:
		return nil, nil
	}

	if err := checkHeaderCertificates(key, protected); err != nil {
		return nil, err
	}

	return key, nil
}

func parseCertificate(encoded string) (*x509.Certificate, error) {
	der, err := base64url.DecodeStandard(encoded)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func checkHeaderCertificates(key *jwk.Key, protected *header.Header) error {
	if len(protected.X509CertificateChain) == 0 {
		return nil
	}

	subject := jwk.NewKey(
		key.Material(),
		jwk.WithX509CertificateSHA1Thumbprint(protected.X509CertificateSHA1Thumbprint),
		jwk.WithX509CertificateSHA256Thumbprint(protected.X509CertificateSHA256Thumbprint),
	)

	return subject.CheckCertificateChain(protected.X509CertificateChain)
}

func headerCandidates(
	protected *header.Header, algorithm jwa.Algorithm, config VerificationConfig,
) (candidates []*jwk.Key, refused error, err error) {
	if len(config.headerKeys) == 0 {
		return nil, nil, nil
	}

	key, err := headerKey(protected)
	if err != nil || key == nil {
		return nil, nil, err
	}

	candidates = jwk.NewKeySet(key).Candidates(
		jwk.Signature, []jwk.Operation{jwk.Verify}, algorithm, protected.KeyID,
	)
	if len(candidates) == 0 {
		return nil, nil, nil
	}

	for _, policy := range config.headerKeys {
		if err := policy(key, protected); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHeaderKeyRefused, err), nil
		}
	}

	return candidates, nil, nil
}
