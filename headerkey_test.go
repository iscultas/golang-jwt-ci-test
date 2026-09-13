package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

func generateKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return privateKey
}

func selfSignedCertificate(t testing.TB, privateKey *ecdsa.PrivateKey) string {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwt header key test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("cannot create a certificate: %v", err)
	}

	return base64.StdEncoding.EncodeToString(der)
}

func tokenCarrying(
	t testing.TB, privateKey *ecdsa.PrivateKey, headerOptions ...func(*header.Header),
) *jwt.Token {
	t.Helper()

	token := newToken(t, jwt.WithSignature(
		jwa.ES256(), jwk.NewKey(privateKey), jws.WithProtectedHeader(headerOptions...),
	))

	encodedToken, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize the token: %v", err)
	}

	return unmarshalToken(t, encodedToken)
}

func accept(*jwk.Key, *header.Header) error { return nil }

func TestTheHeaderKeyIsNotACandidateWithoutAPolicy(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey(privateKey.Public())))

	if token.Verify(t.Context(), nil, jwt.DefaultVerificationConfig) == nil {
		t.Error("a token verified under the key it carries with no policy asked for")
	}

	if err := token.Verify(t.Context(),
		jwk.NewKeySet(), jwt.NewVerificationConfig(),
	); !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Errorf("got error %v, want ErrNoSuitableKey", err)
	}
}

func TestTheHeaderKeyVerifiesWhenThePolicyAccepts(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey(privateKey.Public())))

	config := jwt.NewVerificationConfig(jwt.WithHeaderKey(accept))

	if err := token.Verify(t.Context(), nil, config); err != nil {
		t.Errorf("a token carrying its own key did not verify under an accepting policy: %v", err)
	}
}

func TestTheHeaderKeyDoesNotDisplaceTheKeySet(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey(privateKey.Public())))

	refuse := func(*jwk.Key, *header.Header) error { return errors.New("no") }
	config := jwt.NewVerificationConfig(jwt.WithHeaderKey(refuse))

	t.Run("ThePublishedKeyStillVerifies", func(t *testing.T) {
		keySet := jwk.NewKeySet(jwk.NewKey(privateKey.Public()))

		if err := token.Verify(t.Context(), keySet, config); err != nil {
			t.Errorf("a refused header key suppressed a published key that signed: %v", err)
		}
	})

	t.Run("TheRefusalIsReportedWhenNothingElseWasOffered", func(t *testing.T) {
		err := token.Verify(t.Context(), nil, config)

		if !errors.Is(err, jwt.ErrHeaderKeyRefused) {
			t.Errorf("got error %v, want ErrHeaderKeyRefused", err)
		}

		if errors.Is(err, jwk.ErrNoSuitableKey) {
			t.Error("the refusal was reported as the absence of a key")
		}
	})
}

func TestEveryHeaderKeyPolicyMustAccept(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey(privateKey.Public())))

	refuse := func(*jwk.Key, *header.Header) error { return errors.New("no") }

	for name, config := range map[string]jwt.VerificationConfig{
		"TheFirstRefuses": jwt.NewVerificationConfig(
			jwt.WithHeaderKey(refuse), jwt.WithHeaderKey(accept),
		),
		"TheSecondRefuses": jwt.NewVerificationConfig(
			jwt.WithHeaderKey(accept), jwt.WithHeaderKey(refuse),
		),
	} {
		t.Run(name, func(t *testing.T) {
			if err := token.Verify(t.Context(), nil, config); !errors.Is(err, jwt.ErrHeaderKeyRefused) {
				t.Errorf("got error %v, want ErrHeaderKeyRefused", err)
			}
		})
	}
}

func TestTheHeaderKeyRefusalsPrecedeThePolicy(t *testing.T) {
	privateKey := generateKey(t)

	t.Run("PrivateMaterial", func(t *testing.T) {
		token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey(privateKey)))

		consulted := false
		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(
			func(*jwk.Key, *header.Header) error { consulted = true; return nil },
		))

		if err := token.Verify(t.Context(), nil, config); !errors.Is(err, jwt.ErrPrivateHeaderKey) {
			t.Errorf("got error %v, want ErrPrivateHeaderKey", err)
		}

		if consulted {
			t.Error("the policy was consulted about a private key")
		}
	})

	t.Run("SymmetricMaterial", func(t *testing.T) {
		token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey([]byte("a shared secret!"))))

		consulted := false
		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(
			func(*jwk.Key, *header.Header) error { consulted = true; return nil },
		))

		if err := token.Verify(t.Context(), nil, config); !errors.Is(err, jwt.ErrSymmetricHeaderKey) {
			t.Errorf("got error %v, want ErrSymmetricHeaderKey", err)
		}

		if consulted {
			t.Error("the policy was consulted about a symmetric key")
		}
	})

	t.Run("UnsuitableForThisSignature", func(t *testing.T) {
		token := tokenCarrying(t, privateKey, header.WithJWK(
			jwk.NewKey(privateKey.Public(), jwk.WithPublicKeyUse(jwk.Encryption)),
		))

		consulted := false
		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(
			func(*jwk.Key, *header.Header) error { consulted = true; return nil },
		))

		if err := token.Verify(t.Context(), nil, config); !errors.Is(err, jwk.ErrNoSuitableKey) {
			t.Errorf("got error %v, want ErrNoSuitableKey", err)
		}

		if consulted {
			t.Error("the policy was consulted about a key unusable for this signature")
		}
	})
}

func TestTheHeaderKeyComesFromTheCertificateChain(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(t, privateKey, header.WithX509CertificateChain(
		selfSignedCertificate(t, privateKey),
	))

	config := jwt.NewVerificationConfig(jwt.WithHeaderKey(accept))

	if err := token.Verify(t.Context(), nil, config); err != nil {
		t.Errorf("a token carrying only its certificate did not verify: %v", err)
	}
}

func TestTheHeaderKeyMustMatchItsCertificateChain(t *testing.T) {
	privateKey := generateKey(t)
	other := generateKey(t)

	token := tokenCarrying(
		t, privateKey,
		header.WithJWK(jwk.NewKey(other.Public())),
		header.WithX509CertificateChain(selfSignedCertificate(t, privateKey)),
	)

	config := jwt.NewVerificationConfig(jwt.WithHeaderKey(accept))

	if err := token.Verify(t.Context(), nil, config); !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
		t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
	}
}

func TestThePolicySeesTheWholeHeader(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(
		t, privateKey,
		header.WithJWK(jwk.NewKey(privateKey.Public(), jwk.WithID("pinned"))),
		header.WithKeyID("pinned"),
	)

	pinned := func(_ *jwk.Key, protected *header.Header) error {
		if protected.KeyID != "pinned" {
			return errors.New("unpinned key id")
		}

		return nil
	}

	if err := token.Verify(t.Context(), nil, jwt.NewVerificationConfig(jwt.WithHeaderKey(pinned))); err != nil {
		t.Errorf("a pinned key id was not accepted: %v", err)
	}
}

func TestANilHeaderKeyPolicyIsNoPolicy(t *testing.T) {
	privateKey := generateKey(t)
	token := tokenCarrying(t, privateKey, header.WithJWK(jwk.NewKey(privateKey.Public())))

	t.Run("Alone", func(t *testing.T) {
		if err := token.Verify(t.Context(),
			jwk.NewKeySet(), jwt.NewVerificationConfig(jwt.WithHeaderKey(nil)),
		); !errors.Is(err, jwk.ErrNoSuitableKey) {
			t.Errorf("got error %v, want ErrNoSuitableKey", err)
		}
	})

	t.Run("BesideAPolicyThatAccepts", func(t *testing.T) {
		if err := token.Verify(t.Context(), nil, jwt.NewVerificationConfig(
			jwt.WithHeaderKey(nil), jwt.WithHeaderKey(accept),
		)); err != nil {
			t.Errorf("the token did not verify: %v", err)
		}
	})
}
