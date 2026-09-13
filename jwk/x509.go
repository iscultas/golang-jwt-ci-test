package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 7517 section 4.8 defines x5t as a SHA-1 thumbprint. Section 4.9 has the SHA-256 one.
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/iscultas/jwt-go/internal/base64url"
)

var (
	// ErrCertificateKeyMismatch is the error for a certificate chain that does not
	// hold the key which the other members of the JWK give. Each of the three
	// X.509 parameters makes that agreement necessary.
	ErrCertificateKeyMismatch = errors.New("jwk: certificate does not carry this key")

	// ErrMalformedThumbprint is the error for an "x5t" or "x5t#S256" value that is
	// not the base64url encoding of a digest of the correct length. The two
	// members are digests, which gives the two properties.
	ErrMalformedThumbprint = errors.New("jwk: malformed certificate thumbprint")

	// ErrUnorderedCertificateChain is the error for a certificate in "x5c" that the
	// next certificate did not sign. RFC 7517 section 4.7 gives the sequence: "each
	// subsequent certificate being the one used to certify the previous one".
	ErrUnorderedCertificateChain = errors.New("jwk: certificate chain is not in issuing order")

	// ErrInconsistentCertificateUse is the error for a "use" value that disagrees
	// with the key usage of the first certificate. RFC 7517 section 4.6 gives the
	// rule, and sections 4.7 to 4.9 each point to it: "if the "use" member is
	// present, then it MUST correspond to the usage that is specified in the
	// certificate".
	ErrInconsistentCertificateUse = errors.New("jwk: use does not match the certificate's key usage")
)

type publicKeyComparer interface {
	Equal(crypto.PublicKey) bool
}

func publicMaterial(material any) (publicKeyComparer, bool) {
	switch material := material.(type) {
	case *ecdsa.PrivateKey:
		return &material.PublicKey, true
	case *rsa.PrivateKey:
		return &material.PublicKey, true
	case ed25519.PrivateKey:
		return material.Public().(ed25519.PublicKey), true //nolint:forcetypeassert // Public of an ed25519.PrivateKey returns an ed25519.PublicKey, by the contract of that method.
	case *ecdh.PrivateKey:
		return material.PublicKey(), true
	case *mldsa.PrivateKey:
		publicKey, ok := mldsaPublicKey(material)

		return publicKey, ok
	case publicKeyComparer:
		return material, true
	}

	return nil, false
}

func sha1Thumbprint(certificate *x509.Certificate) []byte {
	digest := sha1.Sum(certificate.Raw) //nolint:gosec // The x5t of RFC 7517 section 4.8, compared against a value of the same document rather than a signature.

	return digest[:]
}

func sha256Thumbprint(certificate *x509.Certificate) []byte {
	digest := sha256.Sum256(certificate.Raw)

	return digest[:]
}

func decodeThumbprint(name, encoded string, size int) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}

	digest, err := base64url.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrMalformedThumbprint, name, err)
	}

	if len(digest) != size {
		return nil, fmt.Errorf("%w: %s: got %d octets, want %d", ErrMalformedThumbprint, name, len(digest), size)
	}

	return digest, nil
}

func certificateUse(certificate *x509.Certificate) (signature, encryption bool) {
	if certificate.KeyUsage == 0 {
		return false, false
	}

	signature = certificate.KeyUsage&(x509.KeyUsageDigitalSignature|
		x509.KeyUsageContentCommitment|
		x509.KeyUsageCertSign|
		x509.KeyUsageCRLSign) != 0

	encryption = certificate.KeyUsage&(x509.KeyUsageKeyEncipherment|
		x509.KeyUsageDataEncipherment|
		x509.KeyUsageKeyAgreement|
		x509.KeyUsageEncipherOnly|
		x509.KeyUsageDecipherOnly) != 0

	return signature, encryption
}

func (key *Key) checkCertificates() error {
	sha1Digest, err := decodeThumbprint("x5t", key.x509CertificateSHA1Thumbprint, sha1.Size)
	if err != nil {
		return err
	}

	sha256Digest, err := decodeThumbprint("x5t#S256", key.x509CertificateSHA256Thumbprint, sha256.Size)
	if err != nil {
		return err
	}

	if len(key.x509CertificateChain) == 0 {
		return nil
	}

	material, ok := publicMaterial(key.material)
	if !ok {
		if key.material == nil {
			return nil
		}

		return fmt.Errorf("%w: %T is not carried by a certificate", ErrCertificateKeyMismatch, key.material)
	}

	if !material.Equal(key.x509CertificateChain[0].PublicKey) {
		return fmt.Errorf("%w: the first certificate carries a different public key", ErrCertificateKeyMismatch)
	}

	if err := key.checkCertificateUse(); err != nil {
		return err
	}

	if err := key.checkChainOrder(); err != nil {
		return err
	}

	return key.checkThumbprintedCertificates(material, sha1Digest, sha256Digest)
}

// CheckCertificateChain applies the same rules to an "x5c" chain in a JOSE
// header, and not in a JWK.
//
// RFC 7515 section 4.1.6 gives the rule for a JWS in the same words that RFC 7517
// section 4.7 uses for a JWK: "The certificate containing the public key
// corresponding to the key used to digitally sign the JWS MUST be the first
// certificate." A header holds the chain as the encoded strings that it received.
// Thus this method parses the certificates, where the key that they must match
// is.
//
// Section 4.1.6 also makes a recipient "validate the certificate chain according
// to RFC 5280". This method does not do that. Such validation makes a trust
// anchor and a policy necessary, and it stays with the caller.
func (key *Key) CheckCertificateChain(chain []string) error {
	if len(chain) == 0 {
		return nil
	}

	certificates := make([]*x509.Certificate, 0, len(chain))

	for _, encoded := range chain {
		der, err := base64url.DecodeStandard(encoded)
		if err != nil {
			return err
		}

		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}

		certificates = append(certificates, certificate)
	}

	candidate := *key
	candidate.x509CertificateChain = certificates

	return candidate.checkCertificates()
}

func (key *Key) checkCertificateUse() error {
	if key.publicKeyUse == "" {
		return nil
	}

	signature, encryption := certificateUse(key.x509CertificateChain[0])
	if !signature && !encryption {
		return nil
	}

	if key.publicKeyUse == Signature && !signature {
		return fmt.Errorf("%w: use is %q but the certificate asserts encryption only", ErrInconsistentCertificateUse, Signature)
	}

	if key.publicKeyUse == Encryption && !encryption {
		return fmt.Errorf("%w: use is %q but the certificate asserts signing only", ErrInconsistentCertificateUse, Encryption)
	}

	return nil
}

func (key *Key) checkChainOrder() error {
	for i := 1; i < len(key.x509CertificateChain); i++ {
		issued, issuer := key.x509CertificateChain[i-1], key.x509CertificateChain[i]

		if err := issuer.CheckSignature(
			issued.SignatureAlgorithm, issued.RawTBSCertificate, issued.Signature,
		); err != nil {
			return fmt.Errorf(
				"%w: certificate %d did not certify certificate %d: %w", ErrUnorderedCertificateChain, i, i-1, err,
			)
		}
	}

	return nil
}

func (key *Key) checkThumbprintedCertificates(material publicKeyComparer, sha1Digest, sha256Digest []byte) error {
	for _, certificate := range key.x509CertificateChain {
		named := sha1Digest != nil && string(sha1Thumbprint(certificate)) == string(sha1Digest)
		if !named {
			named = sha256Digest != nil && string(sha256Thumbprint(certificate)) == string(sha256Digest)
		}

		if named && !material.Equal(certificate.PublicKey) {
			return fmt.Errorf(
				"%w: the certificate named by a thumbprint carries a different public key", ErrCertificateKeyMismatch,
			)
		}
	}

	return nil
}
