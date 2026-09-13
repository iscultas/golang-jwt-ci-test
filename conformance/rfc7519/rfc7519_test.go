package rfc7519_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

// rfc-req: RFC7519-S3-R01
// rfc-req: RFC7519-S3-R02
func TestDuplicateAndUnrecognizedClaimNames(t *testing.T) {
	t.Run("DuplicateClaimNameIsRejected", func(t *testing.T) {
		_, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{"iss":"first","iss":"second"}`))
		if !errors.Is(err, jsontext.ErrDuplicateName) {
			t.Errorf("got %v, want an error wrapping jsontext.ErrDuplicateName", err)
		}
	})

	t.Run("UnrecognizedClaimIgnored", func(t *testing.T) {
		tok, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{"iss":"joe","x-vendor-claim":"anything"}`))
		if err != nil {
			t.Fatalf("decoding a claims set with an unrecognized member: %v", err)
		}
		if err := tok.Verify(t.Context(), noneKeySet(), jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))); err != nil {
			t.Errorf("verifying a token with an unrecognized claim: %v, want nil", err)
		}
		if got := tok.PrivateClaim("x-vendor-claim"); got != "anything" {
			t.Errorf("got private claim %v, want %q (carried through, not dropped)", got, "anything")
		}
	})
}

// rfc-req: RFC7519-S4_1_1-R01
// rfc-req: RFC7519-S4_1_2-R02
// rfc-req: RFC7519-S4_1_3-R04
// rfc-req: RFC7519-S4_1_4-R05
// rfc-req: RFC7519-S4_1_5-R05
// rfc-req: RFC7519-S4_1_6-R02
// rfc-req: RFC7519-S4_1_7-R02
//
// RFC 7519 states, of each of the seven registered claims in turn: "Use of
// this claim is OPTIONAL." A token that sets none of them is not itself
// invalid: it builds, serializes, and verifies like any other.
//
// capabilities: jwt-iss-claim, jwt-sub-claim, jwt-aud-claim, jwt-exp-claim,
// jwt-nbf-claim, jwt-iat-claim and jwt-jti-claim -- each independently
// optional. This is the interop half for all seven at once, and is never
// skipped: a token setting none of them is exactly what a peer using none of
// them emits.
func TestAllRegisteredClaimsAreOptional(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	tok, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("building a token with no registered claims set: %v", err)
	}

	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("serializing a token with no registered claims set: %v", err)
	}

	parsed, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("parsing back: %v", err)
	}

	if got := parsed.Issuer(); got != "" {
		t.Errorf("got iss %q, want empty", got)
	}
	if got := parsed.Subject(); got != "" {
		t.Errorf("got sub %q, want empty", got)
	}
	if got := parsed.Audience(); got != nil {
		t.Errorf("got aud %v, want nil", got)
	}
	if got := parsed.ExpirationTime(); got != nil {
		t.Errorf("got exp %v, want nil", got)
	}
	if got := parsed.NotBefore(); got != nil {
		t.Errorf("got nbf %v, want nil", got)
	}
	if got := parsed.IssuedAt(); got != nil {
		t.Errorf("got iat %v, want nil", got)
	}
	if got := parsed.ID(); got != "" {
		t.Errorf("got jti %q, want empty", got)
	}

	if err := parsed.Verify(t.Context(), jwk.NewKeySet(key), jwt.DefaultVerificationConfig); err != nil {
		t.Errorf("verifying a token with no registered claims set: %v, want nil", err)
	}
}

// rfc-req: RFC7519-S4_1_2-R01
//
// RFC 7519 section 4.1.2: "The subject value MUST either be scoped to be
// locally unique in the context of the issuer or be globally unique."
//
// Not independently testable: uniqueness of a chosen identifier cannot be
// checked by a library with no knowledge of the issuer's namespace. sub is
// carried as an opaque string. Recorded here rather than silently omitted.
func TestSubjectUniquenessIsAnApplicationObligation(t *testing.T) {
	t.Skip("not-testable: sub uniqueness is a naming-scheme obligation on the issuer, unobservable by a library holding no namespace knowledge (see RFC7519-S4_1_2-R01 in the IR)")
}

// RFC 7519 section 4.1.3: "If the principal processing the claim does not
// identify itself with a value in the "aud" claim when this claim is
// present, then the JWT MUST be rejected."
//
// rfc-req: RFC7519-S4_1_3-R02
func TestAudienceMismatchIsRejected(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	keySet := jwk.NewKeySet(key)

	t.Run("MismatchedAudienceRejected", func(t *testing.T) {
		tok, err := jwt.NewToken(jwt.WithAudience("service-a", "service-b"), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		config := jwt.NewVerificationConfig(jwt.WithExpectedAudience("service-c"))
		if err := tok.Verify(t.Context(), keySet, config); !errors.Is(err, jwt.ErrUnexpectedAudience) {
			t.Errorf("got %v, want %v", err, jwt.ErrUnexpectedAudience)
		}
	})

	t.Run("MatchingAudienceAccepted", func(t *testing.T) {
		tok, err := jwt.NewToken(jwt.WithAudience("service-a", "service-b"), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		config := jwt.NewVerificationConfig(jwt.WithExpectedAudience("service-b"))
		if err := tok.Verify(t.Context(), keySet, config); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("NoExpectedAudienceConfiguredSkipsCheck", func(t *testing.T) {
		tok, err := jwt.NewToken(jwt.WithAudience("service-a"), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil (no audience policy configured)", err)
		}
	})
}

// rfc-req: RFC7519-S4_1_3-R03
//
// RFC 7519 section 4.1.3: "In the general case, the "aud" value is an array
// of case-sensitive strings, each containing a StringOrURI value.  In the
// special case when the JWT has one audience, the "aud" value MAY be a
// single case-sensitive string containing a StringOrURI value."
//
// capability: aud-as-bare-string -- present on both sides. The interop
// obligation is the consuming one: a peer taking the special case must be
// understood by a consumer that always writes the array form.
func TestAudienceAcceptsBothArrayAndBareStringForms(t *testing.T) {
	t.Run("SingleAudienceMarshalsAsBareString", func(t *testing.T) {
		tok, err := jwt.NewToken(jwt.WithAudience("only-one"), jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("k"))))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		encoded, err := tok.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		_, payloadPart, _ := strings.Cut(encoded, ".")
		payloadPart, _, _ = strings.Cut(payloadPart, ".")
		payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadPart)
		if err != nil {
			t.Fatalf("decoding payload: %v", err)
		}

		var claims map[string]any
		if err := json.Unmarshal(payloadJSON, &claims); err != nil {
			t.Fatalf("unmarshaling payload: %v", err)
		}
		if _, ok := claims["aud"].(string); !ok {
			t.Errorf("got aud of type %T, want a bare JSON string", claims["aud"])
		}
	})

	t.Run("BareStringDecodesToOneElement", func(t *testing.T) {
		tok, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{"aud":"single"}`))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, want := tok.Audience(), []string{"single"}; !slicesEqual(got, want) {
			t.Errorf("got aud %v, want %v", got, want)
		}
	})

	t.Run("SingleElementArrayDecodesToOneElement", func(t *testing.T) {
		tok, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{"aud":["single"]}`))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, want := tok.Audience(), []string{"single"}; !slicesEqual(got, want) {
			t.Errorf("got aud %v, want %v", got, want)
		}
	})

	t.Run("MultiElementArrayDecodesInOrder", func(t *testing.T) {
		tok, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{"aud":["a","b"]}`))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, want := tok.Audience(), []string{"a", "b"}; !slicesEqual(got, want) {
			t.Errorf("got aud %v, want %v", got, want)
		}
	})
}

// rfc-req: RFC7519-S4_1_4-R01
// rfc-req: RFC7519-S4_1_4-R02
//
// RFC 7519 section 4.1.4: "The "exp" (expiration time) claim identifies the
// expiration time on or after which the JWT MUST NOT be accepted for
// processing. ... the current date/time MUST be before the expiration
// date/time listed in the "exp" claim."
func TestExpirationTimeIsEnforced(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	keySet := jwk.NewKeySet(key)
	now := time.Now()

	t.Run("PastExpirationRejected", func(t *testing.T) {
		past := now.Add(-time.Hour)
		tok, err := jwt.NewToken(jwt.WithExpirationTime(&past), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrExpired) {
			t.Errorf("got %v, want %v", err, jwt.ErrExpired)
		}
	})

	t.Run("FutureExpirationAccepted", func(t *testing.T) {
		future := now.Add(time.Hour)
		tok, err := jwt.NewToken(jwt.WithExpirationTime(&future), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
}

// rfc-req: RFC7519-S4_1_4-R03
// rfc-req: RFC7519-S4_1_5-R03
//
// RFC 7519 sections 4.1.4 and 4.1.5, identical sentence in both: "Implementers
// MAY provide for some small leeway, usually no more than a few minutes, to
// account for clock skew."
//
// This library implements the capability (jwt.WithLeeway); the MAY-interop
// obligation is to exercise it, not to skip it since it is present.
func TestLeewayToleratesClockSkew(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	keySet := jwk.NewKeySet(key)
	now := time.Now()
	leewayConfig := jwt.NewVerificationConfig(jwt.WithLeeway(5 * time.Second))

	t.Run("RecentlyExpiredAcceptedWithinLeeway", func(t *testing.T) {
		justPast := now.Add(-2 * time.Second)
		tok, err := jwt.NewToken(jwt.WithExpirationTime(&justPast), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, leewayConfig); err != nil {
			t.Errorf("got %v, want nil (within 5s leeway)", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrExpired) {
			t.Errorf("without leeway: got %v, want %v", err, jwt.ErrExpired)
		}
	})

	t.Run("SlightlyFutureNotBeforeAcceptedWithinLeeway", func(t *testing.T) {
		justFuture := now.Add(2 * time.Second)
		tok, err := jwt.NewToken(jwt.WithNotBefore(&justFuture), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, leewayConfig); err != nil {
			t.Errorf("got %v, want nil (within 5s leeway)", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrNotYetValid) {
			t.Errorf("without leeway: got %v, want %v", err, jwt.ErrNotYetValid)
		}
	})
}

// rfc-req: RFC7519-S4_1_4-R04
// rfc-req: RFC7519-S4_1_5-R04
// rfc-req: RFC7519-S4_1_6-R01
//
// RFC 7519, identical sentence in sections 4.1.4, 4.1.5 and 4.1.6: "Its value
// MUST be a number containing a NumericDate value."
func TestNumericDateClaimsRejectNonNumericValues(t *testing.T) {
	for _, claim := range []string{"exp", "nbf", "iat"} {
		t.Run(claim, func(t *testing.T) {
			payloadJSON := `{"` + claim + `":"not-a-number"}`
			_, err := jwt.Unmarshal(compact(`{"alg":"none"}`, payloadJSON))
			if !errors.Is(err, jwt.ErrMalformedClaim) {
				t.Errorf("got %v, want %v", err, jwt.ErrMalformedClaim)
			}
		})
	}

	t.Run("FractionalNumericDateAccepted", func(t *testing.T) {
		tok, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{"exp":1300819380.5}`))
		if err != nil {
			t.Fatalf("decoding a fractional NumericDate: %v", err)
		}
		if tok.ExpirationTime() == nil {
			t.Fatal("got nil ExpirationTime for a present, fractional exp")
		}
	})
}

// rfc-req: RFC7519-S4_1_5-R01
// rfc-req: RFC7519-S4_1_5-R02
//
// RFC 7519 section 4.1.5: "The "nbf" (not before) claim identifies the time
// before which the JWT MUST NOT be accepted for processing. ... the current
// date/time MUST be after or equal to the not-before date/time listed in the
// "nbf" claim."
func TestNotBeforeIsEnforced(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	keySet := jwk.NewKeySet(key)
	now := time.Now()

	t.Run("FutureNotBeforeRejected", func(t *testing.T) {
		future := now.Add(time.Hour)
		tok, err := jwt.NewToken(jwt.WithNotBefore(&future), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrNotYetValid) {
			t.Errorf("got %v, want %v", err, jwt.ErrNotYetValid)
		}
	})

	t.Run("PastNotBeforeAccepted", func(t *testing.T) {
		past := now.Add(-time.Hour)
		tok, err := jwt.NewToken(jwt.WithNotBefore(&past), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("NotBeforeInThePastByASecondAccepted", func(t *testing.T) {
		justPast := now.Add(-time.Second)
		tok, err := jwt.NewToken(jwt.WithNotBefore(&justPast), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		if err := tok.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
}

// rfc-req: RFC7519-S4_1_6-R03
//
// RFC 7519 section 4.1.6 (per errata eid7720, Reported): "Implementors MUST
// NOT reject otherwise-valid JWTs with "iat" claims that appear to be from
// the future; token issuers desiring this behavior may require it by
// including an "nbf" claim."
func TestFutureIssuedAtIsNotRejected(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	future := time.Now().Add(24 * time.Hour)

	tok, err := jwt.NewToken(jwt.WithIssuedAt(&future), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}

	if err := tok.Verify(t.Context(), jwk.NewKeySet(key), jwt.DefaultVerificationConfig); err != nil {
		t.Errorf("got %v, want nil (a future iat alone must not cause rejection)", err)
	}
}

// rfc-req: RFC7519-S4_1_7-R01
//
// RFC 7519 section 4.1.7: "The identifier value MUST be assigned in a manner
// that ensures that there is a negligible probability that the same value
// will be accidentally assigned to a different data object; if the
// application uses multiple issuers, collisions MUST be prevented among
// values produced by different issuers as well."
//
// Not independently testable: this library has no jti-generation function of
// its own (WithID accepts any caller-supplied string), so there is no
// generation-quality behavior to hold to a collision-resistance standard.
//
// jwt.WithReplayCheck does not change this. That option gives an accepted
// identifier to a store of the caller's, which is the replay half of section
// 4.1.7. It reads the value; it does not produce one, and it cannot make a
// value that the issuer chose badly collision-resistant.
func TestJTICollisionResistanceIsAnApplicationObligation(t *testing.T) {
	t.Skip("not-testable: jti collision-resistance is a value-generation obligation on the issuer; this library carries whatever string WithID is given (see RFC7519-S4_1_7-R01 in the IR)")
}

// rfc-req: RFC7519-S4_3-R01
//
// RFC 7519 section 4.3: "A producer and consumer of a JWT MAY agree to use
// Claim Names that are Private Names: names that are not Registered Claim
// Names (Section 4.1) or Public Claim Names (Section 4.2)."
//
// capability: jwt-private-claim-names -- present on both sides, so this test
// never skips. The producing half is jwt.WithPrivateClaim and the consuming
// half is jwt.Token.PrivateClaim; the name below is the one RFC 7519 section
// 3.1 uses for exactly this purpose in its own example claims set.
//
// The permission is what is under test, not the collision policy this module
// puts around it: section 4.3 says only that the two parties may agree on a
// name of their own, and this asserts that such a name survives the round
// trip whole.
func TestPrivateClaimNamesRoundTrip(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	const (
		name  = "http://example.com/is_root"
		value = "the agreed value"
	)

	tok, err := jwt.NewToken(jwt.WithPrivateClaim(name, value), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("building a token with a private claim name: %v", err)
	}

	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Verify(t.Context(), jwk.NewKeySet(key), jwt.DefaultVerificationConfig); err != nil {
		t.Errorf("got %v, want nil (a private claim name must not make a token unverifiable)", err)
	}
	if got := decoded.PrivateClaim(name); got != value {
		t.Errorf("got private claim %v, want %q (the agreed name must read back what was written)", got, value)
	}
}

// RFC 7519 section 5.1: "If present, it is RECOMMENDED that its value be
// "JWT" ... it is RECOMMENDED that "JWT" always be spelled using uppercase
// characters for compatibility with legacy implementations."
//
// rfc-req: RFC7519-S5_1-R01
// rfc-req: RFC7519-S5_1-R02
func TestSignedTokenAlwaysDeclaresTypJWT(t *testing.T) {
	tok, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("k"))))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := protectedHeaderOf(t, serialized).Type
	if got != "JWT" {
		t.Errorf("got typ %q, want %q", got, "JWT")
	}
}

// rfc-req: RFC7519-S5_1-R03
//
// RFC 7519 section 5.1: "Use of this Header Parameter is OPTIONAL."
//
// This library always writes typ on its own signing path (see
// RFC7519-S5_1-R01/R02); the OPTIONAL half this requirement needs tested is
// the reading side: a consumer must tolerate a token that omits typ, since a
// producer is entitled to.
//
// capability: jwt-typ-header -- absent from the header this test builds; the
// obligation is that a consumer must not require its presence.
func TestTypAbsenceIsTolerated(t *testing.T) {
	tok, err := jwt.Unmarshal(compact(`{"alg":"none"}`, `{}`))
	if err != nil {
		t.Fatalf("decoding a protected header without typ: %v", err)
	}
	if err := tok.Verify(t.Context(), noneKeySet(), jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))); err != nil {
		t.Errorf("got %v, want nil (typ is optional)", err)
	}
}

// rfc-req: RFC7519-S5_2-R01
//
// RFC 7519 section 5.2: "In the normal case in which nested signing or
// encryption operations are not employed, the use of this Header Parameter is
// NOT RECOMMENDED."
func TestOrdinaryTokenNeverSetsCty(t *testing.T) {
	tok, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("k"))))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if got := protectedHeaderOf(t, serialized).ContentType; got != "" {
		t.Errorf("got cty %q, want empty (never volunteered for an ordinary token)", got)
	}

	custom, err := jwt.NewToken(
		jwt.WithSignature(
			jwa.HS256(), jwk.NewKey(secret("k")),
			jwsWithContentType("JWT"),
		),
	)
	if err != nil {
		t.Fatalf("building token with explicit cty: %v", err)
	}
	customSerialized, err := custom.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := protectedHeaderOf(t, customSerialized).ContentType; got != "JWT" {
		t.Errorf("got cty %q, want %q (explicit opt-in honored)", got, "JWT")
	}
}

// rfc-req: RFC7519-S7_1-R01
// rfc-req: RFC7519-S7_1-R02
//
// RFC 7519 section 7.1: "Create a JOSE Header containing the desired set of
// Header Parameters.  The JWT MUST conform to either the [JWS] or [JWE]
// specification. ... If the JWT is a JWS, create a JWS using the Message as
// the JWS Payload; all steps specified in [JWS] for creating a JWS MUST be
// followed."
//
// The JWS-creation steps themselves are fully covered by
// rfc-conformance/ir/rfc7515.json and conformance/rfc7515/; not duplicated
// here. This smoke test ties the two suites together: a signed jwt.Token's
// compact serialization is a well formed JWS by RFC 7515's own rules.
func TestSignedTokenIsAWellFormedJWS(t *testing.T) {
	tok, err := jwt.NewToken(jwt.WithIssuer("rfc7519-conformance"), jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("k"))))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}
}

// rfc-req: RFC7519-S7_2-R01
// rfc-req: RFC7519-S7_2-R02
//
// RFC 7519 section 7.2 step 5 (umbrella, R01): "If any of the listed steps
// fail, then the JWT MUST be rejected." Every negative-case test in this file
// and in rfc-conformance/ir/rfc7515.json demonstrates this for its own
// failing step; marked here, on the algorithm-acceptability case, as one
// representative instance rather than duplicated on every other one.
//
// RFC 7519 section 7.2 final paragraph (R02): "...unless the algorithms used
// in the JWT are acceptable to the application, it SHOULD reject the JWT."
// (Errata eid5906, Reported, proposes MUST; should_policy: strict already
// treats this SHOULD as a hard assertion.)
func TestUnacceptableAlgorithmIsRejectedEvenIfSignatureValid(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	tok, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	config := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.RS256()))
	if err := parsed.Verify(t.Context(), jwk.NewKeySet(key), config); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
		t.Errorf("got %v, want %v", err, jwt.ErrForbiddenAlgorithm)
	}
}

// rfc-req: RFC7519-S7_2-R03
//
// RFC 7519 section 7.2 step 4: "Verify that the resulting octet sequence is a
// UTF-8-encoded representation of a completely valid JSON object conforming
// to RFC 7159 [RFC7159]; let the JOSE Header be this JSON object."
func TestHeaderSegmentMustDecodeToAJSONObject(t *testing.T) {
	t.Run("JSONArrayRejected", func(t *testing.T) {
		malformed := b64(`[]`) + "." + b64(`{}`) + "."
		if _, err := jwt.Unmarshal(malformed); err == nil {
			t.Error("got nil error decoding a header segment that is a JSON array, want an error")
		}
	})

	t.Run("InvalidJSONRejected", func(t *testing.T) {
		malformed := b64(`not json at all`) + "." + b64(`{}`) + "."
		if _, err := jwt.Unmarshal(malformed); err == nil {
			t.Error("got nil error decoding an invalid-JSON header segment, want an error")
		}
	})
}

// rfc-req: RFC7519-S7_2-R04
//
// RFC 7519 section 7.2 (step 9 per the corrected numbering in errata
// eid8225, Reported): "Verify that the resulting octet sequence is a
// UTF-8-encoded representation of a completely valid JSON object conforming
// to RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object."
func TestPayloadSegmentMustDecodeToAJSONObject(t *testing.T) {
	t.Run("JSONArrayRejected", func(t *testing.T) {
		malformed := b64(`{"alg":"none"}`) + "." + b64(`[]`) + "."
		if _, err := jwt.Unmarshal(malformed); err == nil {
			t.Error("got nil error decoding a payload segment that is a JSON array, want an error")
		}
	})

	t.Run("InvalidJSONRejected", func(t *testing.T) {
		malformed := b64(`{"alg":"none"}`) + "." + b64(`not json at all`) + "."
		if _, err := jwt.Unmarshal(malformed); err == nil {
			t.Error("got nil error decoding an invalid-JSON payload segment, want an error")
		}
	})
}

// rfc-req: RFC7519-S7_2-R05
//
// RFC 7519 section 7.2 step 5, as corrected by errata eid8060 (Verified),
// which replaces the originally published, internally contradictory text
// (it conflicted with step 7's instruction to follow RFC 7515, since RFC 7515
// requires ignoring every non-critical unrecognized parameter unconditionally,
// not only when "specified as being ignored") with a direct deferral to RFC
// 7515's own header-processing rules.
func TestUnrecognizedHeaderParameterIsIgnoredNotRejected(t *testing.T) {
	tok, err := jwt.Unmarshal(compact(`{"alg":"none","x-vendor-ext":"anything"}`, `{}`))
	if err != nil {
		t.Fatalf("decoding a header with an unrecognized non-critical parameter: %v", err)
	}
	if err := tok.Verify(t.Context(), noneKeySet(), jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))); err != nil {
		t.Errorf("got %v, want nil (unrecognized parameter must be ignored, per RFC 7515 as step 7 requires following)", err)
	}
}

// rfc-req: RFC7519-S7_3-R01
//
// RFC 7519 section 7.3: "These comparison rules MUST be used for all JSON
// string comparisons except in cases where the definition of the member
// explicitly calls out that a different comparison rule is to be used for
// that member value.  In this specification, only the "typ" and "cty" member
// values do not use these comparison rules."
func TestStringClaimComparisonsAreCaseSensitive(t *testing.T) {
	key := jwk.NewKey(secret("shared secret"))
	tok, err := jwt.NewToken(jwt.WithIssuer("example"), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}

	config := jwt.NewVerificationConfig(jwt.WithExpectedIssuer("Example"))
	if err := tok.Verify(t.Context(), jwk.NewKeySet(key), config); !errors.Is(err, jwt.ErrUnexpectedIssuer) {
		t.Errorf("got %v, want %v (case-insensitive match must not satisfy a case-sensitive comparison)", err, jwt.ErrUnexpectedIssuer)
	}
}

// rfc-req: RFC7519-S8-R01
//
// RFC 7519 section 8: "Of the signature and MAC algorithms specified in JSON
// Web Algorithms [JWA], only HMAC SHA-256 ("HS256") and "none" MUST be
// implemented by conforming JWT implementations."
func TestBaselineAlgorithmsHS256AndNoneAreImplemented(t *testing.T) {
	t.Run("HS256", func(t *testing.T) {
		key := jwk.NewKey(secret("shared secret"))
		tok, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		serialized, err := tok.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(t.Context(), jwk.NewKeySet(key), jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("None", func(t *testing.T) {
		tok, err := jwt.NewToken(jwt.WithSignature(jwa.None(), nil))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		serialized, err := tok.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		config := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))
		if err := parsed.Verify(t.Context(), noneKeySet(), config); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
}

// rfc-req: RFC7519-S8-R02
//
// RFC 7519 section 8: "It is RECOMMENDED that implementations also support
// RSASSA-PKCS1-v1_5 with the SHA-256 hash algorithm ("RS256") and ECDSA using
// the P-256 curve and the SHA-256 hash algorithm ("ES256")."
func TestRecommendedAlgorithmsRS256AndES256AreImplemented(t *testing.T) {
	t.Run("RS256", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating RSA key: %v", err)
		}
		signingKey := jwk.NewKey(privateKey)
		verifyingKey := jwk.NewKey(&privateKey.PublicKey)

		tok, err := jwt.NewToken(jwt.WithSignature(jwa.RS256(), signingKey))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		serialized, err := tok.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(t.Context(), jwk.NewKeySet(verifyingKey), jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("ES256", func(t *testing.T) {
		privateKey := generateES256Key(t)
		signingKey := jwk.NewKey(privateKey)
		verifyingKey := jwk.NewKey(&privateKey.PublicKey)

		tok, err := jwt.NewToken(jwt.WithSignature(jwa.ES256(), signingKey))
		if err != nil {
			t.Fatalf("building token: %v", err)
		}
		serialized, err := tok.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := parsed.Verify(t.Context(), jwk.NewKeySet(verifyingKey), jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
}

// rfc-req: RFC7519-S6-R01
// rfc-req: RFC7519-S6-R02
//
// RFC 7519 section 6: "An Unsecured JWT is a JWS using the "alg" Header
// Parameter value "none" and with the empty string for its JWS Signature
// value, as defined in the JWA specification [JWA]; it is an Unsecured JWS
// with the JWT Claims Set as its JWS Payload."
func TestUnsecuredJWTUsesNoneAlgorithmAndEmptySignature(t *testing.T) {
	tok, err := jwt.NewToken(jwt.WithIssuer("joe"), jwt.WithSignature(jwa.None(), nil))
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	serialized, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if got := protectedHeaderOf(t, serialized).Algorithm; got != jwa.None() {
		t.Errorf("got alg %v, want none", got)
	}

	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}
	if parts[2] != "" {
		t.Errorf("got JWS Signature part %q, want empty string", parts[2])
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func compact(headerJSON, payloadJSON string) string {
	return b64(headerJSON) + "." + b64(payloadJSON) + "."
}

func protectedHeaderOf(t *testing.T, serialized string) *header.Header {
	t.Helper()

	encodedProtectedHeader, _, _ := strings.Cut(serialized, ".")

	protectedHeader := new(header.Header)
	if err := protectedHeader.Unmarshal(encodedProtectedHeader); err != nil {
		t.Fatalf("cannot parse protected header: %v", err)
	}

	return protectedHeader
}

func noneKeySet() *jwk.KeySet {
	return jwk.NewKeySet(jwk.NewKey(secret("unused")))
}

func generateES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ES256 key: %v", err)
	}

	return privateKey
}

func jwsWithContentType(contentType string) func(*jws.Signature) {
	return jws.WithProtectedHeader(func(h *header.Header) { h.ContentType = contentType })
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func secret(seed string) []byte {
	key := sha512.Sum512([]byte(seed))

	return key[:]
}

// TestOptionalSignatureAlgorithms is TestOptionalEncryptionAlgorithms for the
// other half of §8.
//
// MAY — "Support for other algorithms and key sizes is OPTIONAL."
//
// capability: optional-jws-algorithms. Section 8 states this sentence twice,
// once after the signature and MAC baseline and once after the encryption one.
// The encryption occurrence was asserted; this one was excluded as "a pure
// permission grant with no library-observable consequence". Both readings cannot
// be right about the same words, and the interop obligation is the real one: an
// identifier this module does not implement must be reported unsupported, never
// quietly answered with an algorithm it does implement, because a verifier that
// substituted one would be reading a token that says something else.
//
// rfc-req: RFC7519-S8-R03
func TestOptionalSignatureAlgorithms(t *testing.T) {
	for _, name := range []string{
		"HS384", "HS512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
		"EdDSA", "Ed25519",
	} {
		if _, ok := jwa.ByName(name); !ok {
			t.Logf("%s is not implemented, which is conformant", name)
		}
	}

	for _, unregistered := range []string{"HS128", "RS1024", "ES256K", "NOTAREALALG", ""} {
		if algorithm, ok := jwa.ByName(unregistered); ok {
			t.Errorf("%q resolved to %s", unregistered, algorithm)
		}
	}

	for _, unregistered := range []string{"HS128", "ES256K"} {
		encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + unregistered + `"}`))

		if err := new(header.Header).Unmarshal(encodedHeader); !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
			t.Errorf("a header naming %q: got %v, want ErrUnsupportedAlgorithm", unregistered, err)
		}
	}
}
