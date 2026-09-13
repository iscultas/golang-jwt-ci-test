package rfc7517_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwk"
)

func generateP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return privateKey
}

func jwkCarrying(t *testing.T, privateKey *ecdsa.PrivateKey, chain ...*x509.Certificate) string {
	t.Helper()

	document, err := json.Marshal(jwk.NewKey(&privateKey.PublicKey))
	if err != nil {
		t.Fatalf("cannot serialize the key: %v", err)
	}

	elements := make([]string, 0, len(chain))
	for _, certificate := range chain {
		elements = append(elements, `"`+base64.StdEncoding.EncodeToString(certificate.Raw)+`"`)
	}

	return string(document[:len(document)-1]) + `,"x5c":[` + strings.Join(elements, ",") + `]}`
}

// rfc-req: RFC7517-S4_7-R03
//
// RFC 7517 section 4.7, MUST: "The key in the first certificate MUST match the
// public key represented by other members of the JWK."
//
// Decided by the JWK alone. The identically worded sentence in section 4.6 is
// about a certificate that must first be fetched over the network, which is why
// that one is recorded not-testable and this one is not.
func TestACertificateForAnotherKeyIsRefused(t *testing.T) {
	subject, other := generateP256(t), generateP256(t)
	certificate := selfSigned(t, other)

	t.Run("marshal", func(t *testing.T) {
		key := jwk.NewKey(&subject.PublicKey, jwk.WithX509CertificateChain([]*x509.Certificate{certificate}))

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
			t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		var decoded jwk.Key

		err := json.Unmarshal([]byte(jwkCarrying(t, subject, certificate)), &decoded)
		if !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
			t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
		}
	})

	t.Run("a symmetric key", func(t *testing.T) {
		key := jwk.NewKey(
			[]byte("0123456789abcdef"), jwk.WithX509CertificateChain([]*x509.Certificate{certificate}),
		)

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
			t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
		}
	})
}

// rfc-req: RFC7517-S4_7-R01
//
// RFC 7517 section 4.7, MUST: "The PKIX certificate containing the key value
// MUST be the first certificate."
//
// Position, not presence. A chain that carries the key's certificate somewhere
// does not satisfy this, which is what the reversed case pins.
func TestTheKeysCertificateMustComeFirst(t *testing.T) {
	issuerKey := generateP256(t)
	issuer := selfSigned(t, issuerKey)

	subject := generateP256(t)
	leaf := issuedBy(t, subject, issuerKey, issuer, 0)

	t.Run("first", func(t *testing.T) {
		key := jwk.NewKey(&subject.PublicKey, jwk.WithX509CertificateChain([]*x509.Certificate{leaf, issuer}))

		if _, err := json.Marshal(key); err != nil {
			t.Errorf("got error %v, want nil", err)
		}
	})

	t.Run("second", func(t *testing.T) {
		key := jwk.NewKey(&subject.PublicKey, jwk.WithX509CertificateChain([]*x509.Certificate{issuer, leaf}))

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
			t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
		}
	})

	t.Run("a stranger after the leaf", func(t *testing.T) {
		strangerKey := generateP256(t)

		key := jwk.NewKey(&subject.PublicKey, jwk.WithX509CertificateChain(
			[]*x509.Certificate{leaf, selfSigned(t, strangerKey)},
		))

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrUnorderedCertificateChain) {
			t.Errorf("got error %v, want ErrUnorderedCertificateChain", err)
		}
	})
}

// rfc-req: RFC7517-S4_7-R06
//
// RFC 7517 section 4.7, MUST: "If other members are present, the contents of
// those members MUST be semantically consistent with the related fields in the
// first certificate." Section 4.6, which it defers to, gives the case: "if the
// "use" member is present, then it MUST correspond to the usage that is
// specified in the certificate, when it includes this information".
//
// The last clause is a boundary and is asserted as one. A certificate with no
// key usage extension specifies nothing, and refusing a JWK on the strength of
// it would invent an obligation the sentence explicitly withholds.
func TestUseMustCorrespondToTheCertificate(t *testing.T) {
	privateKey := generateP256(t)

	for name, subject := range map[string]struct {
		usage    x509.KeyUsage
		use      jwk.PublicKeyUse
		accepted bool
	}{
		"sig against digitalSignature": {x509.KeyUsageDigitalSignature, jwk.Signature, true},
		"sig against keyEncipherment":  {x509.KeyUsageKeyEncipherment, jwk.Signature, false},
		"enc against keyAgreement":     {x509.KeyUsageKeyAgreement, jwk.Encryption, true},
		"enc against digitalSignature": {x509.KeyUsageDigitalSignature, jwk.Encryption, false},
		"enc against both":             {x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, jwk.Encryption, true},
		"enc against no extension":     {0, jwk.Encryption, true},
	} {
		t.Run(name, func(t *testing.T) {
			key := jwk.NewKey(
				&privateKey.PublicKey,
				jwk.WithPublicKeyUse(subject.use),
				jwk.WithX509CertificateChain(
					[]*x509.Certificate{issuedBy(t, privateKey, privateKey, nil, subject.usage)},
				),
			)

			_, err := json.Marshal(key)

			if subject.accepted && err != nil {
				t.Errorf("got error %v, want nil", err)
			}

			if !subject.accepted && !errors.Is(err, jwk.ErrInconsistentCertificateUse) {
				t.Errorf("got error %v, want ErrInconsistentCertificateUse", err)
			}
		})
	}
}

// RFC 7517 sections 4.8 and 4.9, MUST: "The key in the certificate MUST match
// the public key represented by other members of the JWK."
//
// "The certificate" is the one the thumbprint digests, and a JWK generally does
// not carry it -- the member exists so a certificate held elsewhere can be named
// compactly. Where the JWK does carry it, the requirement is a comparison, and a
// thumbprint naming the issuer rather than the leaf fails it: the issuer's key
// signed this certificate rather than being the key in it.
//
// What is deliberately not asserted matters as much. Nothing in RFC 7517 says a
// thumbprint must digest the first certificate, and two certificates may carry
// the same key, so requiring that would refuse documents the specification
// allows.
//
// rfc-req: RFC7517-S4_8-R01
// rfc-req: RFC7517-S4_9-R01
func TestAThumbprintNamingACarriedCertificateMustNameThisKeys(t *testing.T) {
	issuerKey := generateP256(t)
	issuer := selfSigned(t, issuerKey)

	subject := generateP256(t)
	leaf := issuedBy(t, subject, issuerKey, issuer, 0)

	sha1OfIssuer := sha1.Sum(issuer.Raw)
	sha256OfIssuer := sha256.Sum256(issuer.Raw)
	sha256OfLeaf := sha256.Sum256(leaf.Raw)

	for name, option := range map[string]func(*jwk.Key){
		"x5t naming the issuer": jwk.WithX509CertificateSHA1Thumbprint(
			base64.RawURLEncoding.EncodeToString(sha1OfIssuer[:]),
		),
		"x5t#S256 naming the issuer": jwk.WithX509CertificateSHA256Thumbprint(
			base64.RawURLEncoding.EncodeToString(sha256OfIssuer[:]),
		),
	} {
		t.Run(name, func(t *testing.T) {
			key := jwk.NewKey(
				&subject.PublicKey, jwk.WithX509CertificateChain([]*x509.Certificate{leaf, issuer}), option,
			)

			if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
				t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
			}
		})
	}

	t.Run("naming the leaf", func(t *testing.T) {
		key := jwk.NewKey(
			&subject.PublicKey,
			jwk.WithX509CertificateChain([]*x509.Certificate{leaf, issuer}),
			jwk.WithX509CertificateSHA256Thumbprint(base64.RawURLEncoding.EncodeToString(sha256OfLeaf[:])),
		)

		if _, err := json.Marshal(key); err != nil {
			t.Errorf("got error %v, want nil", err)
		}
	})

	t.Run("naming a certificate this JWK does not carry", func(t *testing.T) {
		strangerKey := generateP256(t)
		digest := sha256.Sum256(selfSigned(t, strangerKey).Raw)

		key := jwk.NewKey(
			&subject.PublicKey,
			jwk.WithX509CertificateChain([]*x509.Certificate{leaf, issuer}),
			jwk.WithX509CertificateSHA256Thumbprint(base64.RawURLEncoding.EncodeToString(digest[:])),
		)

		if _, err := json.Marshal(key); err != nil {
			t.Errorf("got error %v, want nil: nothing can be said about a certificate that is not here", err)
		}
	})
}

// RFC 7517 sections 4.8 and 4.9: "The "x5t" (X.509 certificate SHA-1
// thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest)
// of the DER encoding of an X.509 certificate [RFC5280]."
//
// No BCP 14 keyword, and normative all the same, in the way RFC 8174 notes is
// common: the sentence says what the member is, and thereby fixes both its
// encoding and -- through the digest it names -- its length. Neither was
// checked; these two were the last base64url-typed members in the module that
// reached no decoder at all.
//
// The two wrong-length cases are the boundary that matters: each is
// well-formed base64url, and wrong only in being the other member's digest.
//
// rfc-req: RFC7517-S4_8-R05
// rfc-req: RFC7517-S4_9-R05
func TestAThumbprintIsADigestOfTheStatedLength(t *testing.T) {
	privateKey := generateP256(t)

	sha1Sized := base64.RawURLEncoding.EncodeToString(make([]byte, sha1.Size))
	sha256Sized := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))

	for name, option := range map[string]func(*jwk.Key){
		"x5t outside the alphabet": jwk.WithX509CertificateSHA1Thumbprint("!!! not a thumbprint !!!"),
		"x5t with a line break":    jwk.WithX509CertificateSHA1Thumbprint("y2ZL5xkBEUCyeuv-CDLxK\nNq1XU4"),
		"x5t padded":               jwk.WithX509CertificateSHA1Thumbprint("y2ZL5xkBEUCyeuv-CDLxKNq1XU4="),
		"x5t in the standard alphabet": jwk.WithX509CertificateSHA1Thumbprint(
			"y2ZL5xkBEUCyeuv+CDLxKNq1XU4",
		),
		"x5t holding a SHA-256 digest":    jwk.WithX509CertificateSHA1Thumbprint(sha256Sized),
		"x5t#S256 holding a SHA-1 digest": jwk.WithX509CertificateSHA256Thumbprint(sha1Sized),
		"x5t#S256 outside the alphabet":   jwk.WithX509CertificateSHA256Thumbprint("not a digest"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(jwk.NewKey(&privateKey.PublicKey, option)); !errors.Is(
				err, jwk.ErrMalformedThumbprint,
			) {
				t.Errorf("got error %v, want ErrMalformedThumbprint", err)
			}
		})
	}

	t.Run("a well-formed digest with no certificate", func(t *testing.T) {
		document, err := json.Marshal(jwk.NewKey(
			&privateKey.PublicKey,
			jwk.WithX509CertificateSHA1Thumbprint(sha1Sized),
			jwk.WithX509CertificateSHA256Thumbprint(sha256Sized),
		))
		if err != nil {
			t.Fatalf("got error %v, want nil", err)
		}

		var decoded jwk.Key
		if err := json.Unmarshal(document, &decoded); err != nil {
			t.Errorf("got error %v on the way back, want nil", err)
		}
	})
}

func selfSigned(t *testing.T, privateKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	return certificateFor(t, "self-signed", privateKey, privateKey, nil, 0)
}

func issuedBy(
	t *testing.T, subject, issuer *ecdsa.PrivateKey, issuerCertificate *x509.Certificate, usage x509.KeyUsage,
) *x509.Certificate {
	t.Helper()

	return certificateFor(t, "issued", subject, issuer, issuerCertificate, usage)
}
