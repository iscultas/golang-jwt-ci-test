package jwk_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/iscultas/jwt-go/jwk"
)

func issue(
	t testing.TB, subject, issuer *ecdsa.PrivateKey, parent *x509.Certificate, usage x509.KeyUsage,
) *x509.Certificate {
	t.Helper()

	return issueFor(t, &subject.PublicKey, issuer, parent, usage)
}

func issueFor(
	t testing.TB,
	subject crypto.PublicKey,
	issuer crypto.Signer,
	parent *x509.Certificate,
	usage x509.KeyUsage,
) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("cannot draw a serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "jwk test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     usage,
	}

	if parent == nil {
		parent = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, subject, issuer)
	if err != nil {
		t.Fatalf("cannot create a certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cannot parse a certificate: %v", err)
	}

	return certificate
}

func generateKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return privateKey
}

func TestTheKeyBehindItsOwnCertificateIsAccepted(t *testing.T) {
	privateKey := generateKey(t)
	certificate := issue(t, privateKey, privateKey, nil, 0)

	for name, material := range map[string]any{
		"a public key":  &privateKey.PublicKey,
		"a private key": privateKey,
	} {
		t.Run(name, func(t *testing.T) {
			key := jwk.NewKey(material, jwk.WithX509CertificateChain([]*x509.Certificate{certificate}))

			if _, err := json.Marshal(key); err != nil {
				t.Errorf("a key carrying its own certificate was refused: %v", err)
			}
		})
	}
}

func TestAThumbprintIsNotADigestOfTheOtherHashsLength(t *testing.T) {
	privateKey := generateKey(t)

	for name, option := range map[string]func(*jwk.Key){
		"x5t one octet short of SHA-1": jwk.WithX509CertificateSHA1Thumbprint(
			base64.RawURLEncoding.EncodeToString(make([]byte, sha1.Size-1)),
		),
		"x5t#S256 one octet past SHA-256": jwk.WithX509CertificateSHA256Thumbprint(
			base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size+1)),
		),
	} {
		t.Run(name, func(t *testing.T) {
			key := jwk.NewKey(&privateKey.PublicKey, option)

			if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrMalformedThumbprint) {
				t.Errorf("marshal returned %v, want ErrMalformedThumbprint", err)
			}
		})
	}
}

func TestAKeyOfAnUnimplementedTypeKeepsItsCertificate(t *testing.T) {
	privateKey := generateKey(t)
	certificate := issue(t, privateKey, privateKey, nil, 0)

	document := `{"kty":"unimplemented","x5c":["` + base64.StdEncoding.EncodeToString(certificate.Raw) + `"]}`

	var decoded jwk.Key
	if err := json.Unmarshal([]byte(document), &decoded); err != nil {
		t.Errorf("a JWK of an unimplemented type was refused for its certificate: %v", err)
	}
}

func TestTheCertificateCheckAcceptsEveryPrivateKeyType(t *testing.T) {
	issuerKey := generateKey(t)

	ecdsaKey := generateKey(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate an RSA key: %v", err)
	}

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an Ed25519 key: %v", err)
	}

	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("cannot generate an ML-DSA key: %v", err)
	}

	for _, test := range []struct {
		name     string
		material any
		public   crypto.PublicKey
	}{
		{"ECDSA", ecdsaKey, &ecdsaKey.PublicKey},
		{"RSA", rsaKey, &rsaKey.PublicKey},
		{"Ed25519", ed25519Key, ed25519Key.Public()},
		{"MLDSA", mldsaKey, mldsaKey.PublicKey()},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := issueFor(t, test.public, issuerKey, nil, 0)

			key := jwk.NewKey(
				test.material, jwk.WithX509CertificateChain([]*x509.Certificate{certificate}),
			)

			if _, err := json.Marshal(key); err != nil {
				t.Errorf("a key with its own certificate did not marshal: %v", err)
			}
		})
	}
}
