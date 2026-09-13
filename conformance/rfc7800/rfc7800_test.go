package rfc7800_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func signingKey(t *testing.T) *jwk.Key {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return jwk.NewKey(privateKey)
}

func presenterKey(t *testing.T) *jwk.Key {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return jwk.NewKey(privateKey.Public())
}

var expirationTime = time.Now().Add(time.Hour)

func issue(t *testing.T, options ...func(*jwt.Token) error) (string, error) {
	t.Helper()

	key := signingKey(t)

	token, err := jwt.NewToken(append([]func(*jwt.Token) error{
		jwt.WithExpirationTime(&expirationTime),
		jwt.WithSignature(jwa.ES256(), key),
	}, options...)...)
	if err != nil {
		return "", err
	}

	return token.Marshal()
}

func carrying(t *testing.T, members any) *jwt.Token {
	t.Helper()

	encoded, err := issue(t,
		jwt.WithIssuer("https://server.example.com"),
		jwt.WithPrivateClaim(jwt.ConfirmationClaim, members),
	)
	if err != nil {
		t.Fatalf("cannot issue the token: %v", err)
	}

	token, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}

	return token
}

// rfc-req: RFC7800-S3-R00
//
// RFC 7800 section 3, keyword-free but normative: "The value of the "cnf" claim
// is a JSON object and the members of that object identify the proof-of-
// possession key."
//
// Refused rather than ignored when it is not an object. The claim is the issuer
// stating a key requirement, so a "cnf" that cannot be read is a requirement
// that cannot be met; treating it as absent would silently turn a
// proof-of-possession token into a bearer token.
func TestTheConfirmationClaimIsAJSONObject(t *testing.T) {
	t.Run("AnObjectIsRead", func(t *testing.T) {
		token := carrying(t, map[string]any{"kid": "dfd1aa97-6d8d-4575-a0fe-34b96de2bfad"})

		confirmation, err := token.Confirmation()
		if err != nil {
			t.Fatalf("got error %v, want nil", err)
		}

		if confirmation.KeyID != "dfd1aa97-6d8d-4575-a0fe-34b96de2bfad" {
			t.Errorf("got kid %q, want the one the token carried", confirmation.KeyID)
		}
	})

	for name, members := range map[string]any{
		"AString": "dfd1aa97-6d8d-4575-a0fe-34b96de2bfad",
		"AnArray": []any{"jwk"},
		"ANumber": 1361398824,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := carrying(t, members).Confirmation()

			if !errors.Is(err, jwt.ErrMalformedConfirmation) {
				t.Errorf("got error %v, want ErrMalformedConfirmation", err)
			}
		})
	}
}

// rfc-req: RFC7800-S3-R01
//
// RFC 7800 section 3, MUST: "At least one of the "sub" and "iss" claims MUST be
// present in the JWT."
//
// The claim says a presenter holds a key; a token naming no presenter has
// asserted possession by nobody. Checked at issue because it binds the issuer --
// a recipient handed such a token has a malformed assertion, not a policy
// decision to make.
func TestConfirmationRequiresAPresenter(t *testing.T) {
	confirmation := jwt.Confirmation{KeyID: "2015-08-28"}

	t.Run("NeitherIsPresent", func(t *testing.T) {
		_, err := issue(t, jwt.WithConfirmation(confirmation))

		if !errors.Is(err, jwt.ErrUnidentifiedPresenter) {
			t.Errorf("got error %v, want ErrUnidentifiedPresenter", err)
		}
	})

	for name, option := range map[string]func(*jwt.Token) error{
		"OnlyTheSubject": jwt.WithSubject("someone@example.com"),
		"OnlyTheIssuer":  jwt.WithIssuer("https://server.example.com"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issue(t, option, jwt.WithConfirmation(confirmation)); err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}

// rfc-req: RFC7800-S3_1-R01
//
// RFC 7800 section 3.1, MUST: "However, in the absence of such requirements, all
// confirmation members that are not understood by implementations MUST be
// ignored."
//
// Section 3.1 says other members may be defined and section 6.2 establishes a
// registry for them, so an unknown member is the expected case rather than an
// error.
//
// Note the sentence's own condition, "in the absence of such requirements": an
// application profile that requires a member to be understood -- as RFC 9449
// does of "jkt" -- is not violating this by refusing a token without it.
func TestUnknownConfirmationMembersAreIgnored(t *testing.T) {
	token := carrying(t, map[string]any{
		"kid":                       "2015-08-28",
		"urn:example:not-a-method":  "whatever this is",
		"another-unregistered-name": map[string]any{"nested": true},
	})

	confirmation, err := token.Confirmation()
	if err != nil {
		t.Fatalf("an unknown confirmation member was refused: %v", err)
	}

	if confirmation.KeyID != "2015-08-28" {
		t.Errorf("got kid %q, want the one beside the unknown members", confirmation.KeyID)
	}
}

// rfc-req: RFC7800-S3_1-R02
//
// RFC 7800 section 3.1, MUST: "The "cnf" claim value MUST represent only a
// single proof-of-possession key; thus, at most one of the "jwk", "jwe", and
// "jku" (JWK Set URL) confirmation values defined below may be present."
//
// Enforced in both directions. A rule only the producer obeyed would let this
// package accept tokens it would not itself issue.
//
// "kid" is deliberately outside the mutually exclusive set: section 3.5 requires
// it beside a "jku" whose set holds more than one key, so the pair must stay well
// formed. The last subtest is what keeps a future tightening from breaking that.
func TestConfirmationNamesOneKey(t *testing.T) {
	presenter := presenterKey(t)
	reference, err := url.Parse("https://keys.example.net/pop-keys.json")
	if err != nil {
		t.Fatalf("cannot parse the URL: %v", err)
	}

	t.Run("Issuing", func(t *testing.T) {
		for name, confirmation := range map[string]jwt.Confirmation{
			"AKeyAndAnEncryptedKey": {JWK: presenter, EncryptedKey: "eyJhbGciOiJBMTI4S1cifQ.."},
			"AKeyAndAReference":     {JWK: presenter, KeySetURL: reference},
			"AllThree":              {JWK: presenter, EncryptedKey: "eyJhbGciOiJBMTI4S1cifQ..", KeySetURL: reference},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := issue(t, jwt.WithIssuer("https://server.example.com"), jwt.WithConfirmation(confirmation))

				if !errors.Is(err, jwt.ErrMultipleConfirmationKeys) {
					t.Errorf("got error %v, want ErrMultipleConfirmationKeys", err)
				}
			})
		}
	})

	t.Run("Reading", func(t *testing.T) {
		encodedKey, err := json.Marshal(presenter)
		if err != nil {
			t.Fatalf("cannot encode the key: %v", err)
		}

		var key map[string]any
		if err := json.Unmarshal(encodedKey, &key); err != nil {
			t.Fatalf("cannot decode the key: %v", err)
		}

		token := carrying(t, map[string]any{"jwk": key, "jku": reference.String()})

		if _, err := token.Confirmation(); !errors.Is(err, jwt.ErrMultipleConfirmationKeys) {
			t.Errorf("got error %v, want ErrMultipleConfirmationKeys", err)
		}
	})

	t.Run("EachOneAloneIsAccepted", func(t *testing.T) {
		for name, confirmation := range map[string]jwt.Confirmation{
			"AKey":                {JWK: presenter},
			"AnEncryptedKey":      {EncryptedKey: "eyJhbGciOiJBMTI4S1cifQ.."},
			"AReference":          {KeySetURL: reference},
			"AReferenceAndAKeyID": {KeySetURL: reference, KeyID: "2015-08-28"},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := issue(
					t, jwt.WithIssuer("https://server.example.com"), jwt.WithConfirmation(confirmation),
				); err != nil {
					t.Errorf("got error %v, want nil", err)
				}
			})
		}
	})
}

// rfc-req: RFC7800-S3_2-R01a
//
// RFC 7800 section 3.2, MUST: "The JWK MUST contain the required key members for
// a JWK of that key type and MAY contain other JWK members, including the "kid"
// (Key ID) member."
//
// The rule is RFC 7517's, and it is enforced where every JWK in this module is:
// jwk.Key.UnmarshalJSON refuses a key missing a parameter its "kty" requires.
// The paired MAY of the same sentence is RFC7800-S3_2-R01b.
func TestTheConfirmationKeyIsAWellFormedJWK(t *testing.T) {
	complete := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
		"y":   "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA",
	}

	t.Run("Complete", func(t *testing.T) {
		confirmation, err := carrying(t, map[string]any{"jwk": complete}).Confirmation()
		if err != nil {
			t.Fatalf("got error %v, want nil", err)
		}

		if _, ok := confirmation.JWK.Material().(*ecdsa.PublicKey); !ok {
			t.Errorf("got material %T, want *ecdsa.PublicKey", confirmation.JWK.Material())
		}
	})

	for _, missing := range []string{"crv", "x", "y"} {
		t.Run("Without_"+missing, func(t *testing.T) {
			incomplete := make(map[string]any, len(complete))

			for name, value := range complete {
				if name != missing {
					incomplete[name] = value
				}
			}

			_, err := carrying(t, map[string]any{"jwk": incomplete}).Confirmation()

			if !errors.Is(err, jwt.ErrMalformedConfirmation) {
				t.Errorf("got error %v, want ErrMalformedConfirmation", err)
			}
		})
	}
}

// rfc-req: RFC7800-S3_2-R01b
//
// RFC 7800 section 3.2, MAY: "The JWK ... MAY contain other JWK members,
// including the "kid" (Key ID) member."
//
// The interop obligation is the half of a MAY worth testing: a recipient must
// accept the JWK whether or not the optional members are there. Section 3.4
// notes that some applications use a JWK Thumbprint as the "kid" value, which is
// what jwk.Key.ThumbprintID produces, so that is the value used here.
func TestTheConfirmationKeyMayCarryOptionalMembers(t *testing.T) {
	presenter := presenterKey(t)

	thumbprint, err := presenter.ThumbprintID(crypto256())
	if err != nil {
		t.Fatalf("cannot take the thumbprint: %v", err)
	}

	for name, key := range map[string]*jwk.Key{
		"OnlyTheRequiredMembers": presenter,
		"WithTheOptionalOnes": jwk.NewKey(
			presenter.Material(),
			jwk.WithID(thumbprint),
			jwk.WithPublicKeyUse(jwk.Signature),
			jwk.WithAlgorithm(jwa.ES256()),
		),
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := issue(t,
				jwt.WithIssuer("https://server.example.com"),
				jwt.WithConfirmation(jwt.Confirmation{JWK: key}),
			)
			if err != nil {
				t.Fatalf("got error %v, want nil", err)
			}

			token, err := jwt.Unmarshal(encoded)
			if err != nil {
				t.Fatalf("cannot parse the token: %v", err)
			}

			confirmation, err := token.Confirmation()
			if err != nil {
				t.Fatalf("got error %v, want nil", err)
			}

			if _, ok := confirmation.JWK.Material().(*ecdsa.PublicKey); !ok {
				t.Errorf("got material %T, want *ecdsa.PublicKey", confirmation.JWK.Material())
			}
		})
	}
}

// RFC 7800 section 3.2, MAY: "The "jwk" member MAY also be used for a JWK
// representing a symmetric key, provided that the JWT is encrypted so that the
// key is not revealed to unintended parties."
//
// RFC 7800 section 3.2, MUST: "If the JWT is not encrypted, the symmetric key
// MUST be encrypted as described below."
//
// One test for both, because the permission and the prohibition are the same
// condition read from either side, and asserting only one of them would pass
// against a package that always allowed it or always refused it.
//
// The failure the MUST prevents: a signed, world-readable JWT publishing the very
// secret whose possession it asks someone to prove, after which the proof proves
// nothing -- everyone who read the token can produce it.
//
// rfc-req: RFC7800-S3_2-R02, RFC7800-S3_2-R03
func TestASymmetricConfirmationKeyNeedsAnEncryptedToken(t *testing.T) {
	symmetric := jwk.NewKey(secret())
	confirmation := jwt.WithConfirmation(jwt.Confirmation{JWK: symmetric})
	issuer := jwt.WithIssuer("https://server.example.com")

	t.Run("Encrypted", func(t *testing.T) {
		if _, err := issue(t, issuer, confirmation, jwt.WithEncryption(
			jwa.A128KW(), jwa.A128GCM(), jwk.NewKey(secret()[:16]),
		)); err != nil {
			t.Errorf("got error %v, want nil", err)
		}
	})

	t.Run("Unencrypted", func(t *testing.T) {
		_, err := issue(t, issuer, confirmation)

		if !errors.Is(err, jwt.ErrUnprotectedConfirmationKey) {
			t.Errorf("got error %v, want ErrUnprotectedConfirmationKey", err)
		}
	})

	t.Run("OrCarriedInJWEInstead", func(t *testing.T) {
		if _, err := issue(t, issuer, jwt.WithConfirmation(jwt.Confirmation{
			EncryptedKey: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0..",
		})); err != nil {
			t.Errorf("got error %v, want nil", err)
		}
	})
}
