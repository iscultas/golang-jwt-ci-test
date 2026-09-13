package rfc7515_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

// rfc-req: RFC7515-S3-R01
//
// capability: whitespace-in-json-serialization -- this package never emits it,
// so the producing half is absent. The consuming half is the interop
// obligation and is asserted: a peer that does emit whitespace is understood.
func TestJSONSerializationToleratesInsignificantWhitespace(t *testing.T) {
	t.Run("ProtectedHeaderWithInsertedWhitespace", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString(
			[]byte("{\n  \"alg\" : \"HS256\" ,\n  \"typ\":\"JWT\"\n}\n"),
		)

		h := new(header.Header)
		if err := h.Unmarshal(encoded); err != nil {
			t.Fatalf("expected whitespace-padded header to decode, got %v", err)
		}
		if h.Algorithm != jwa.HS256() {
			t.Fatalf("got algorithm %v, want HS256", h.Algorithm)
		}
	})

	t.Run("JSONSerializationEnvelopeWithInsertedWhitespace", func(t *testing.T) {
		key := hmacKey("secret-key-material-0123456789")
		tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatal(err)
		}
		compact, err := json.Marshal(tok)
		if err != nil {
			t.Fatal(err)
		}

		pretty := jsontext.Value(compact)
		if err := pretty.Indent(jsontext.WithIndent("  ")); err != nil {
			t.Fatal(err)
		}

		tok2 := new(jwt.Token)
		if err := json.Unmarshal(pretty, tok2); err != nil {
			t.Fatalf("expected pretty-printed JWS JSON Serialization to decode, got %v", err)
		}
		if err := tok2.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig()); err != nil {
			t.Fatalf("expected whitespace-padded envelope to verify, got %v", err)
		}
	})
}

// rfc-req: RFC7515-S3_2-R01, RFC7515-S7_2_1-R06
func TestJSONSerializationRequiresAtLeastOneHeaderMember(t *testing.T) {
	sig := new(jws.Signature)
	err := sig.UnmarshalJSON([]byte(`{"signature":"AA"}`))
	if err == nil {
		t.Fatal("expected an error decoding a signature entry with neither protected nor header present")
	}
}

// rfc-req: RFC7515-S4-R01, RFC7515-S10_12-R03
//
// RFC 7515 section 4: "The Header Parameter names within the JOSE Header MUST be
// unique; JWS parsers MUST either reject JWSs with duplicate Header Parameter
// names or use a JSON parser that returns only the lexically last duplicate
// member name". This package takes the first of the two: it rejects. A header
// that names "alg" two times can make a verifier and a consumer read different
// algorithms out of one token, and no reader of the header can tell which one
// the producer signed.
func TestDuplicateHeaderParameterNameIsRejected(t *testing.T) {
	document := []byte(`{"alg":"HS256","alg":"RS256"}`)

	t.Run("Unmarshal", func(t *testing.T) {
		err := new(header.Header).Unmarshal(base64.RawURLEncoding.EncodeToString(document))
		if !errors.Is(err, jsontext.ErrDuplicateName) {
			t.Errorf("got %v, want an error wrapping jsontext.ErrDuplicateName", err)
		}
	})

	for name, unmarshal := range map[string]func([]byte, any) error{
		"encoding/json/v2": func(document []byte, into any) error { return json.Unmarshal(document, into) },
		"encoding/json":    jsonv1.Unmarshal,
	} {
		t.Run(name, func(t *testing.T) {
			err := unmarshal(document, new(header.Header))
			if !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Errorf("got %v, want an error wrapping jsontext.ErrDuplicateName", err)
			}
		})
	}
}

// rfc-req: RFC7515-S4-R04
func TestUnknownHeaderParameterIsIgnored(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","x-custom":"value"}`))

	h := new(header.Header)
	if err := h.Unmarshal(encoded); err != nil {
		t.Fatalf("expected header with an unrecognized member to decode, got %v", err)
	}
	if h.Algorithm != jwa.HS256() {
		t.Fatalf("got algorithm %v, want HS256", h.Algorithm)
	}
}

// rfc-req: RFC7515-S4_1_1-R01
func TestAlgorithmHeaderParameterRequired(t *testing.T) {
	t.Run("AlwaysPresentWhenSigning", func(t *testing.T) {
		key := hmacKey("secret-key-material-0123456789")
		tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(jwa.HS256(), key))
		if err != nil {
			t.Fatal(err)
		}
		compact, err := tok.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		decoded, err := jwt.Unmarshal(compact)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"protected"`) {
			t.Fatal("expected a protected header to be present")
		}
	})

	t.Run("VerificationFailsWhenAlgAbsent", func(t *testing.T) {
		key := hmacKey("secret-key-material-0123456789")
		h := &header.Header{Type: "JWT"}
		encodedHeader, err := h.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"s"}`))
		compact := encodedHeader + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))

		tok, err := jwt.Unmarshal(compact)
		if err != nil {
			t.Fatal(err)
		}
		err = tok.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig())
		if err == nil {
			t.Fatal("expected verification to fail for a header carrying no alg")
		}
	})
}

// rfc-req: RFC7515-S4_1_2-R04, RFC7515-S4_1_3-R01, RFC7515-S4_1_4-R02, RFC7515-S4_1_5-R05, RFC7515-S4_1_6-R04, RFC7515-S4_1_7-R01, RFC7515-S4_1_8-R01, RFC7515-S4_1_9-R01, RFC7515-S4_1_10-R01, RFC7515-S4_1_11-R06
//
// capabilities: jws-jku-header, jws-jwk-header, jws-kid-header, jws-x5u-header,
// jws-x5c-header, jws-x5t-header, jws-x5t-s256-header, jws-typ-header,
// jws-cty-header and jws-crit-header -- each independently optional. This is
// the interop half for all ten at once, and is never skipped: a header
// carrying none of them is exactly what a peer implementing none of them sends.
func TestOptionalHeaderParametersMayBeOmitted(t *testing.T) {
	key := hmacKey("secret-key-material-0123456789")
	sig := &jws.Signature{ProtectedHeader: &header.Header{Algorithm: jwa.HS256()}}

	encodedProtected, err := sig.ProtectedHeader.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"s"}`))
	signingInput := encodedProtected + "." + payload

	rawSig, err := jwa.HS256().Sign([]byte(signingInput), key.Material())
	if err != nil {
		t.Fatal(err)
	}
	compact := signingInput + "." + base64.RawURLEncoding.EncodeToString(rawSig)

	tok, err := jwt.Unmarshal(compact)
	if err != nil {
		t.Fatalf("expected a header with no optional parameters to decode, got %v", err)
	}
	if err := tok.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig()); err != nil {
		t.Fatalf("expected a header with no optional parameters to verify, got %v", err)
	}
}

// rfc-req: RFC7515-S4_1_4-R01
func TestKeyIDIsCaseSensitive(t *testing.T) {
	keyLower := jwk.NewKey(secret("secret-key-material-lower00000"), jwk.WithID("key1"))
	keyUpper := jwk.NewKey(secret("secret-key-material-upper00000"), jwk.WithID("Key1"))
	keySet := jwk.NewKeySet(keyLower, keyUpper)

	found, err := keySet.Key(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.HS256(), "Key1")
	if err != nil {
		t.Fatal(err)
	}
	if found != keyUpper {
		t.Fatal("expected lookup of \"Key1\" to resolve to the exact-case key, not the lowercase one")
	}

	found2, err := keySet.Key(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.HS256(), "key1")
	if err != nil {
		t.Fatal(err)
	}
	if found2 != keyLower {
		t.Fatal("expected lookup of \"key1\" to resolve to the exact-case key, not the uppercase one")
	}
}

// rfc-req: RFC7515-S4_1_11-R01, RFC7515-S4_1_11-R04, RFC7515-S4_1_11-R05, RFC7515-S4_1_11-R07
//
// capability: strict-crit-validation -- present. §4.1.11 permits, but does not
// require, a recipient to reject a "crit" list naming parameters this
// specification already defines; this package takes the option, so the
// stricter behaviour is asserted rather than skipped.
func TestCriticalHeaderParameterIsRejected(t *testing.T) {
	t.Run("AppendixENegativeTestVector", func(t *testing.T) {
		critHeader := `{"alg":"none","crit":["http://example.invalid/UNDEFINED"],"http://example.invalid/UNDEFINED":true}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(critHeader))

		h := new(header.Header)
		err := h.Unmarshal(encoded)
		if err == nil {
			t.Fatal("expected a header naming an unrecognized critical extension to be rejected")
		}
	})

	t.Run("RejectedRegardlessOfWhichHeaderCarriesIt", func(t *testing.T) {
		unprotected := &header.Header{Critical: []string{"exp"}}
		if _, err := unprotected.MarshalJSON(); err == nil {
			t.Fatal("expected an unprotected header carrying crit to be rejected on marshal")
		}

		encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"crit":["exp"],"exp":1363284000}`))
		if err := new(header.Header).Unmarshal(encoded); err == nil {
			t.Fatal("expected a header carrying crit to be rejected on unmarshal")
		}
	})
}

// rfc-req: RFC7515-S4_1_11-R02a, RFC7515-S4_1_11-R02b, RFC7515-S4_1_11-R02c
func TestTheCriticalListIsWellFormed(t *testing.T) {
	base64URLEncodePayload := true

	t.Run("NoSpecificationDefinedName", func(t *testing.T) {
		if _, err := json.Marshal(&header.Header{Critical: []string{"alg"}}); err == nil {
			t.Fatal("expected crit naming a specification-defined parameter to be refused")
		}
	})

	t.Run("NoDuplicateName", func(t *testing.T) {
		duplicate := &header.Header{
			Critical:               []string{"b64", "b64"},
			Base64URLEncodePayload: &base64URLEncodePayload,
		}
		if _, err := json.Marshal(duplicate); !errors.Is(err, header.ErrDuplicateCriticalParameter) {
			t.Fatalf("got error %v, want %v", err, header.ErrDuplicateCriticalParameter)
		}

		encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"crit":["b64","b64"],"b64":true}`))
		if err := new(header.Header).Unmarshal(encoded); !errors.Is(err, header.ErrDuplicateCriticalParameter) {
			t.Fatalf("got error %v, want %v", err, header.ErrDuplicateCriticalParameter)
		}
	})

	t.Run("NoNameAbsentFromTheHeader", func(t *testing.T) {
		absent := &header.Header{Critical: []string{"b64"}}
		if _, err := json.Marshal(absent); !errors.Is(err, header.ErrCriticalParameterMismatch) {
			t.Fatalf("got error %v, want %v", err, header.ErrCriticalParameterMismatch)
		}
	})
}

// rfc-req: RFC7515-S5_1-R01
func TestSigningAlwaysSetsAccurateAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  jwa.Signer
		key  *jwk.Key
	}{
		{"HS256", jwa.HS256(), hmacKey("secret-key-material-0123456789")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(tc.alg, tc.key))
			if err != nil {
				t.Fatal(err)
			}
			compact, err := tok.Marshal()
			if err != nil {
				t.Fatal(err)
			}

			decoded, err := jwt.Unmarshal(compact)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), `"protected"`) {
				t.Fatal("expected a protected header")
			}

			parts := strings.Split(compact, ".")
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(headerJSON), `"alg":"`+tc.name+`"`) {
				t.Fatalf("expected header to name %s, got %s", tc.name, headerJSON)
			}
		})
	}
}

// rfc-req: RFC7515-S5_2-R01
func TestAtLeastOneSignatureMustValidate(t *testing.T) {
	key1 := jwk.NewKey(secret("secret-key-material-AAAAAAAAAA"), jwk.WithID("k1"))
	key2 := jwk.NewKey(secret("secret-key-material-BBBBBBBBBB"), jwk.WithID("k2"))
	wrongKey2 := jwk.NewKey(secret("totally-different-secret-XXXXX"))

	buildToken := func(secondKey *jwk.Key) *jwt.Token {
		tok, err := jwt.NewToken(
			jwt.WithSubject("s"),
			jwt.WithSignature(jwa.HS256(), key1, jws.WithProtectedHeader(header.WithKeyID("k1"))),
			jwt.WithSignature(jwa.HS256(), secondKey, jws.WithProtectedHeader(header.WithKeyID("k2"))),
		)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(tok)
		if err != nil {
			t.Fatal(err)
		}
		decoded := new(jwt.Token)
		if err := json.Unmarshal(raw, decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}

	keySet := jwk.NewKeySet(key1, key2)

	t.Run("DefaultPolicyAcceptsWhenAnyOneValidates", func(t *testing.T) {
		tok := buildToken(wrongKey2)
		if err := tok.Verify(t.Context(), keySet, jwt.NewVerificationConfig()); err != nil {
			t.Fatalf("expected verification with one valid signature to succeed, got %v", err)
		}
	})

	t.Run("DefaultPolicyRejectsWhenNoneValidate", func(t *testing.T) {
		wrongKey1 := jwk.NewKey(secret("another-wrong-secret-YYYYYYYYY"))
		tok, err := jwt.NewToken(
			jwt.WithSubject("s"),
			jwt.WithSignature(jwa.HS256(), wrongKey1, jws.WithProtectedHeader(header.WithKeyID("k1"))),
			jwt.WithSignature(jwa.HS256(), wrongKey2, jws.WithProtectedHeader(header.WithKeyID("k2"))),
		)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(tok)
		if err != nil {
			t.Fatal(err)
		}
		decoded := new(jwt.Token)
		if err := json.Unmarshal(raw, decoded); err != nil {
			t.Fatal(err)
		}
		if err := decoded.Verify(t.Context(), keySet, jwt.NewVerificationConfig()); err == nil {
			t.Fatal("expected verification to fail when no signature validates")
		}
	})

	t.Run("AllSignaturesPolicyRejectsWhenOneFails", func(t *testing.T) {
		tok := buildToken(wrongKey2)
		if err := tok.Verify(t.Context(), keySet, jwt.NewVerificationConfig(jwt.WithAllSignatures())); err == nil {
			t.Fatal("expected WithAllSignatures to reject a token with any invalid signature")
		}
	})
}

// rfc-req: RFC7515-S5_2-R02, RFC7515-S7_2_1-R08
func TestDuplicateHeaderParameterAcrossProtectedAndUnprotectedIsRejected(t *testing.T) {
	t.Run("DirectSignatureMarshal", func(t *testing.T) {
		sig := &jws.Signature{
			ProtectedHeader: &header.Header{Algorithm: jwa.HS256(), KeyID: "dup"},
			Header:          &header.Header{KeyID: "dup"},
			Signature:       []byte("x"),
		}
		if _, err := json.Marshal(sig); err == nil {
			t.Fatal("expected marshaling a signature with the same header parameter in both locations to fail")
		}
	})

	t.Run("GeneralMultiSignatureFormMarshal", func(t *testing.T) {
		key1 := hmacKey("secret-key-material-AAAAAAAAAA")
		key2 := hmacKey("secret-key-material-BBBBBBBBBB")
		tok, err := jwt.NewToken(
			jwt.WithSubject("s"),
			jwt.WithSignature(jwa.HS256(), key1,
				jws.WithProtectedHeader(header.WithKeyID("dup")),
				jws.WithHeader(header.WithKeyID("dup")),
			),
			jwt.WithSignature(jwa.HS256(), key2, jws.WithProtectedHeader(header.WithKeyID("k2"))),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := json.Marshal(tok); err == nil {
			t.Fatal("expected marshaling a multi-signature token with a duplicated header parameter to fail")
		}
	})

	t.Run("FlattenedSingleSignatureFormMarshal", func(t *testing.T) {
		tok, err := jwt.NewToken(
			jwt.WithSubject("s"),
			jwt.WithSignature(jwa.HS256(), hmacKey("secret-key-material-0123456789"),
				jws.WithProtectedHeader(header.WithKeyID("dup")),
				jws.WithHeader(header.WithKeyID("dup")),
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := json.Marshal(tok); !errors.Is(err, jws.ErrDuplicateHeaderParameter) {
			t.Fatalf("got error %v, want one wrapping %v", err, jws.ErrDuplicateHeaderParameter)
		}
	})

	t.Run("FlattenedSingleSignatureFormUnmarshal", func(t *testing.T) {
		protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"dup"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"s"}`))
		doc := `{"payload":"` + payload + `","protected":"` + protected +
			`","header":{"kid":"dup"},"signature":"AA"}`

		err := json.Unmarshal([]byte(doc), new(jwt.Token))
		if !errors.Is(err, jws.ErrDuplicateHeaderParameter) {
			t.Fatalf("got error %v, want one wrapping %v", err, jws.ErrDuplicateHeaderParameter)
		}
	})

	t.Run("ValidationRejectsDuplicate", func(t *testing.T) {
		key := hmacKey("secret-key-material-0123456789")
		tok, err := jwt.NewToken(
			jwt.WithSubject("s"),
			jwt.WithSignature(jwa.HS256(), key,
				jws.WithProtectedHeader(header.WithKeyID("dup")),
				jws.WithHeader(header.WithKeyID("dup")),
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		err = tok.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig())
		if !errors.Is(err, jws.ErrDuplicateHeaderParameter) {
			t.Fatalf("got error %v, want one wrapping %v", err, jws.ErrDuplicateHeaderParameter)
		}
	})
}

// rfc-req: RFC7515-S7_2_1-R04
func TestUnprotectedHeaderMemberPresentOnlyWhenNonEmpty(t *testing.T) {
	key := hmacKey("secret-key-material-0123456789")

	memberOf := func(t *testing.T, options ...func(*jws.Signature)) (jsontext.Value, bool) {
		t.Helper()

		tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(jwa.HS256(), key, options...))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(tok)
		if err != nil {
			t.Fatal(err)
		}

		var members map[string]jsontext.Value
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatal(err)
		}
		member, ok := members["header"]

		return member, ok
	}

	t.Run("PresentWhenNonEmpty", func(t *testing.T) {
		member, ok := memberOf(t, jws.WithHeader(header.WithKeyID("2010-12-29")))
		if !ok {
			t.Fatal("expected a header member when the unprotected header is non-empty")
		}
		if string(member) != `{"kid":"2010-12-29"}` {
			t.Fatalf("got header member %s, want %s", member, `{"kid":"2010-12-29"}`)
		}
	})

	t.Run("AbsentWhenUnset", func(t *testing.T) {
		if _, ok := memberOf(t); ok {
			t.Fatal("expected no header member when no unprotected header was set")
		}
	})

	t.Run("AbsentWhenEmpty", func(t *testing.T) {
		if _, ok := memberOf(t, jws.WithHeader()); ok {
			t.Fatal("expected no header member when the unprotected header is empty")
		}
	})
}

// rfc-req: RFC7515-S7_2_2-R01
func TestMixedFlattenedAndGeneralSyntaxIsRejected(t *testing.T) {
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"s"}`))
	doc := `{"payload":"` + payload + `","protected":"` + protected + `","signature":"AA"` +
		`,"signatures":[{"protected":"` + protected + `","signature":"AA"}]}`

	err := json.Unmarshal([]byte(doc), new(jwt.Token))
	if err == nil {
		t.Fatal("expected a document using both the flattened and general syntax to be rejected")
	}
}

// rfc-req: RFC7515-S5_2-R03
func TestValidationRequiresSuccessfulSignatureCheck(t *testing.T) {
	key := hmacKey("secret-key-material-0123456789")
	tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("UnmodifiedTokenVerifies", func(t *testing.T) {
		decoded, err := jwt.Unmarshal(compact)
		if err != nil {
			t.Fatal(err)
		}
		if err := decoded.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig()); err != nil {
			t.Fatalf("expected a correctly signed token to verify, got %v", err)
		}
	})

	t.Run("TamperedSignatureIsRejected", func(t *testing.T) {
		parts := strings.Split(compact, ".")
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		sigBytes[len(sigBytes)-1] ^= 0xFF
		tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

		decoded, err := jwt.Unmarshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		err = decoded.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig())
		if err == nil {
			t.Fatal("expected a tampered signature to be rejected")
		}
	})
}

// rfc-req: RFC7515-S5_2-R05
func TestAlgorithmAcceptabilityIsCallerConfigurable(t *testing.T) {
	key := hmacKey("secret-key-material-0123456789")
	tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := jwt.Unmarshal(compact)
	if err != nil {
		t.Fatal(err)
	}

	config := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.ES256()))
	err = decoded.Verify(t.Context(), jwk.NewKeySet(key), config)
	if err == nil {
		t.Fatal("expected a cryptographically valid signature to be rejected when its algorithm is not acceptable to the caller")
	}
}

// rfc-req: RFC7515-S5_3-R01
func TestStringComparisonIsCaseSensitiveAndEscapeNormalized(t *testing.T) {
	t.Run("CaseSensitive", func(t *testing.T) {
		if _, ok := jwa.ByName("hs256"); ok {
			t.Fatal("expected lowercase \"hs256\" to not resolve to any registered algorithm")
		}
		if _, ok := jwa.ByName("HS256"); !ok {
			t.Fatal("expected \"HS256\" to resolve")
		}

		encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"hs256"}`))
		if err := new(header.Header).Unmarshal(encoded); err == nil {
			t.Fatal("expected a header naming a lowercase algorithm to be rejected, not case-folded")
		}
	})

	t.Run("EscapeNormalized", func(t *testing.T) {
		escapedAlg := "\\u0048\\u0053\\u0032\\u0035\\u0036"
		encoded := base64.RawURLEncoding.EncodeToString(
			[]byte(`{"alg":"` + escapedAlg + `"}`),
		)
		h := new(header.Header)
		if err := h.Unmarshal(encoded); err != nil {
			t.Fatalf("expected escaped algorithm name to decode, got %v", err)
		}
		if h.Algorithm != jwa.HS256() {
			t.Fatalf("got algorithm %v, want HS256", h.Algorithm)
		}
	})
}

// rfc-req: RFC7515-S7_2_1-R01, RFC7515-S7_2_1-R03, RFC7515-S7_2_1-R05
func TestGeneralJSONSerializationMemberPresence(t *testing.T) {
	key := hmacKey("secret-key-material-0123456789")
	tok, err := jwt.NewToken(jwt.WithSubject("s"), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}

	var members map[string]jsontext.Value
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"payload", "protected", "signature"} {
		if _, ok := members[name]; !ok {
			t.Fatalf("expected %q member to be present in %s", name, raw)
		}
	}

	var payload, protected, signature string
	if err := json.Unmarshal(members["payload"], &payload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(members["protected"], &protected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(members["signature"], &signature); err != nil {
		t.Fatal(err)
	}

	decoded, err := jwt.Unmarshal(protected + "." + payload + "." + signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(t.Context(), jwk.NewKeySet(key), jwt.NewVerificationConfig()); err != nil {
		t.Fatalf("expected the general-form document's members to reconstruct a valid compact token, got %v", err)
	}
}

// rfc-req: RFC7515-S7_2_1-R02
//
// The document carries a payload, because [jwt.Token.UnmarshalJSON] reads that
// member before it reads "signatures". A document without one is refused for the
// payload it does not have, which proves nothing about the type of "signatures".
func TestSignaturesMemberMustBeArray(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"s"}`))
	doc := `{"payload":"` + payload + `","signatures":"not-an-array"}`

	err := json.Unmarshal([]byte(doc), new(jwt.Token))
	if err == nil {
		t.Fatal("expected a non-array \"signatures\" value to be rejected")
	}
}

// rfc-req: RFC7515-S7_2_1-R07
func TestUnknownMemberInSignatureObjectIsIgnored(t *testing.T) {
	key := hmacKey("secret-key-material-0123456789")
	sig := &jws.Signature{ProtectedHeader: &header.Header{Algorithm: jwa.HS256()}}
	encodedProtected, err := sig.ProtectedHeader.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := jwa.HS256().Sign([]byte(encodedProtected+".payload"), key.Material())
	if err != nil {
		t.Fatal(err)
	}

	doc := `{"protected":"` + encodedProtected + `","signature":"` +
		base64.RawURLEncoding.EncodeToString(rawSig) + `","x-extra":"value"}`

	decoded := new(jws.Signature)
	if err := json.Unmarshal([]byte(doc), decoded); err != nil {
		t.Fatalf("expected a signature object with an unrecognized member to decode, got %v", err)
	}
	if decoded.ProtectedHeader.Algorithm != jwa.HS256() {
		t.Fatal("expected the recognized members to still be parsed correctly")
	}
}

// rfc-req: RFC7515-S10_6-R01
func TestAlgorithmConfusionAcrossHashSizesFailsClosed(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signing input")

	sig, err := jwa.RS384().Sign(msg, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := jwa.RS256().Verify(msg, sig, &key.PublicKey); err == nil {
		t.Fatal("expected an RS384 signature to fail RS256 verification against the correct key")
	}
}

// rfc-req: RFC7515-S10_12-R01
func TestMalformedJSONIsRejected(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256",}`))
	if err := new(header.Header).Unmarshal(encoded); err == nil {
		t.Fatal("expected malformed JSON (trailing comma) to be rejected")
	}
}

// rfc-req: RFC7515-S10_12-R05
func TestTrailingDataAfterValidJSONIsRejected(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}TRAILING`))
	if err := new(header.Header).Unmarshal(encoded); err == nil {
		t.Fatal("expected valid JSON followed by trailing data to be rejected")
	}
}

// rfc-req: RFC7515-S10_13-R01
func TestAstralPlaneCharactersPreservedInComparison(t *testing.T) {
	const gClef = "\U0001D11E"

	h := &header.Header{Algorithm: jwa.HS256(), KeyID: gClef + "-key"}
	encoded, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	decoded := new(header.Header)
	if err := decoded.Unmarshal(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.KeyID != gClef+"-key" {
		t.Fatalf("got kid %q, want %q", decoded.KeyID, gClef+"-key")
	}
}

// rfc-req: RFC7515-S10_9-R01
func TestHMACComparisonUsesConstantTimeEquality(t *testing.T) {
	source, err := os.ReadFile("../../jwa/hmac_sha_2.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "hmac.Equal(") {
		t.Fatal("expected HMAC verification to use hmac.Equal (constant-time comparison)")
	}
	if strings.Contains(string(source), "bytes.Equal(mac") {
		t.Fatal("expected HMAC verification not to fall back to a non-constant-time comparison")
	}
}

// TestContentTypeIsReadAsAMediaType covers §4.1.10's rule for a recipient, which
// this suite could not test until one existed.
//
// MUST — "A recipient using the media type value MUST treat it as if
// 'application/' were prepended to any 'cty' value not containing a '/'."
//
// The exclusion recorded against this requirement said there was no
// library-level actor for the MUST to bind to: "cty" was carried as an opaque
// string and never compared with anything. That stopped being true when Nested
// JWT support arrived — jwt.Token.Decrypt compares the outer "cty" against
// "JWT" to decide whether the plaintext holds another JWT — and the comparison
// is exactly the "recipient using the media type value" this sentence is about.
//
// So the two spellings must be one media type: "JWT" and "application/JWT" name
// the same thing, and a Nested JWT labelled either way is a Nested JWT. Case is
// RFC 7519 §7.3's rule and is asserted in conformance/rfc7519; what is asserted
// here is the prefix.
//
// The negative cases are what give the rule content. The prepending is defined
// only for a value with no '/', so "jwt+json" and "application/jwt+x" already
// contain one and are left alone — they are other media types, and a plaintext
// under them is not a JWT.
//
// rfc-req: RFC7515-S4_1_10-R03
func TestContentTypeIsReadAsAMediaType(t *testing.T) {
	signing := jwk.NewKey(
		secret("inner signature"),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
	)
	wrapping := jwk.NewKey(
		bytes.Repeat([]byte{7}, 16),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithSignature(jwa.HS256(), signing),
		jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), wrapping),
	)
	if err != nil {
		t.Fatalf("cannot build a Nested JWT: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	message, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse the JWE: %v", err)
	}

	innerJWS, err := message.Decrypt(wrapping.Material())
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	reencrypt := func(t *testing.T, contentType string) string {
		t.Helper()

		rewritten := &jwe.Message{ProtectedHeader: &header.Header{
			Type:                "JWT",
			ContentType:         contentType,
			Algorithm:           jwa.A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
		}}

		if err := rewritten.Encrypt(innerJWS, wrapping.Material()); err != nil {
			t.Fatalf("cannot encrypt: %v", err)
		}

		serialized, err := rewritten.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize: %v", err)
		}

		return serialized
	}

	keySet := jwk.NewKeySet(signing, wrapping)
	config := jwt.NewDecryptionConfig(jwt.WithRequiredNestedToken())

	for _, contentType := range []string{"JWT", "application/JWT"} {
		t.Run(contentType, func(t *testing.T) {
			read, err := jwt.Unmarshal(reencrypt(t, contentType))
			if err != nil {
				t.Fatalf("cannot parse: %v", err)
			}

			if err := read.Decrypt(t.Context(), keySet, config); err != nil {
				t.Fatalf("cty %q was not read as the media type it names: %v", contentType, err)
			}

			if read.Issuer() != "joe" {
				t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
			}
		})
	}

	for _, contentType := range []string{"jwt+json", "application/jwt+x", "text/plain"} {
		t.Run(contentType, func(t *testing.T) {
			read, err := jwt.Unmarshal(reencrypt(t, contentType))
			if err != nil {
				t.Fatalf("cannot parse: %v", err)
			}

			if err := read.Decrypt(t.Context(), keySet, config); !errors.Is(err, jwt.ErrUnsigned) {
				t.Errorf("cty %q was read as a JWT: %v", contentType, err)
			}
		})
	}
}

func hmacKey(seed string) *jwk.Key { return jwk.NewKey(secret(seed)) }

func secret(seed string) []byte {
	key := sha512.Sum512([]byte(seed))

	return key[:]
}

// RFC 7515 section 4.1.6, MUST: "The certificate containing the public key
// corresponding to the key used to digitally sign the JWS MUST be the first
// certificate."
//
// Enforced at signing time, which is the only point where both halves are in
// hand: the header package holds "x5c" as the strings it was handed and knows no
// key, and jws holds no key either.
//
// The sentence that follows it in the same section -- "The recipient MUST
// validate the certificate chain according to RFC 5280" -- is a different kind
// of obligation and stays out of scope; it is recorded as RFC7515-S4_1_6-R01b.
// Path validation needs a trust anchor and a policy this package does not have.
// This one needs neither.
//
// In the ordinary case nothing downstream would catch a violation: a recipient
// resolving keys from a JWK Set never reads "x5c" at all, so a token naming
// someone else's certificate verifies and misleads only consumers that do read
// it. jwt.WithHeaderKey is the one path that reads it, and applies the same
// rule there -- see TestTheJWKHeaderParameterIsThePublicSigningKey -- but it is
// opt-in, so the signing-time check stays the only one every token passes.
//
// rfc-req: RFC7515-S4_1_6-R01a
func TestSigningRefusesACertificateForAnotherKey(t *testing.T) {
	signingKey := generateSigningKey(t)
	other := generateSigningKey(t)

	for name, certificate := range map[string]*ecdsa.PrivateKey{
		"the signing key's own certificate": signingKey,
		"a certificate for another key":     other,
	} {
		t.Run(name, func(t *testing.T) {
			token, err := jwt.NewToken(
				jwt.WithIssuer("conformance"),
				jwt.WithSignature(
					jwa.ES256(),
					jwk.NewKey(signingKey),
					jws.WithProtectedHeader(
						header.WithX509CertificateChain(certificateOf(t, certificate)),
					),
				),
			)
			if err != nil {
				t.Fatalf("cannot build the token: %v", err)
			}

			_, err = token.Marshal()

			if certificate == signingKey {
				if err != nil {
					t.Errorf("got error %v, want nil", err)
				}

				return
			}

			if !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
				t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
			}
		})
	}
}

// RFC 7515 section 4.1.3, keyword-free but normative: "The "jwk" (JSON Web Key)
// Header Parameter is the public key that corresponds to the key used to
// digitally sign the JWS. This key is represented as a JSON Web Key [JWK]."
//
// Two halves, asserted separately. That the parameter is *the verification key*:
// with no JWK Set passed at all, the header is the only place a key could come
// from, so a token that verifies proves the parameter was used as one. That it
// is the *public* key: private and symmetric material are refused before any
// policy is consulted.
//
// Assumption stated, because the sentence read literally would be a
// vulnerability: this package uses the parameter only for a recipient who asked
// for it with jwt.WithHeaderKey. Believing a token-supplied key by default is
// the JWS key-substitution forgery -- anyone may replace the key and re-sign --
// so the sentence is implemented as "is the key, for a recipient who has decided
// to accept it". The first subtest below is the record of that decision.
//
// rfc-req: RFC7515-S4_1_3-R02
func TestTheJWKHeaderParameterIsThePublicSigningKey(t *testing.T) {
	signingKey := generateSigningKey(t)

	carrying := func(t *testing.T, key *jwk.Key) *jwt.Token {
		t.Helper()

		token, err := jwt.NewToken(
			jwt.WithIssuer("conformance"),
			jwt.WithSignature(
				jwa.ES256(), jwk.NewKey(signingKey),
				jws.WithProtectedHeader(header.WithJWK(key)),
			),
		)
		if err != nil {
			t.Fatalf("cannot build the token: %v", err)
		}

		encoded, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize the token: %v", err)
		}

		parsed, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot parse the token: %v", err)
		}

		return parsed
	}

	accept := func(*jwk.Key, *header.Header) error { return nil }

	t.Run("ItIsNotUsedUnlessTheRecipientAsksForIt", func(t *testing.T) {
		token := carrying(t, jwk.NewKey(signingKey.Public()))

		if err := token.Verify(t.Context(), nil, jwt.DefaultVerificationConfig); err == nil {
			t.Error("a token verified under the key it carried, with no policy asked for")
		}
	})

	t.Run("ItIsTheVerificationKey", func(t *testing.T) {
		token := carrying(t, jwk.NewKey(signingKey.Public()))

		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(accept))

		if err := token.Verify(t.Context(), nil, config); err != nil {
			t.Errorf("got error %v, want nil", err)
		}
	})

	t.Run("ItIsThePublicKey", func(t *testing.T) {
		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(accept))

		for name, testCase := range map[string]struct {
			key      *jwk.Key
			expected error
		}{
			"private material":   {jwk.NewKey(signingKey), jwt.ErrPrivateHeaderKey},
			"symmetric material": {jwk.NewKey(secret("header")), jwt.ErrSymmetricHeaderKey},
		} {
			t.Run(name, func(t *testing.T) {
				err := carrying(t, testCase.key).Verify(t.Context(), nil, config)

				if !errors.Is(err, testCase.expected) {
					t.Errorf("got error %v, want %v", err, testCase.expected)
				}
			})
		}
	})

	t.Run("ItMustAgreeWithAnyCertificateChainBesideIt", func(t *testing.T) {
		other := generateSigningKey(t)

		token, err := jwt.NewToken(
			jwt.WithIssuer("conformance"),
			jwt.WithSignature(
				jwa.ES256(), jwk.NewKey(signingKey),
				jws.WithProtectedHeader(
					header.WithJWK(jwk.NewKey(other.Public())),
					header.WithX509CertificateChain(certificateOf(t, signingKey)),
				),
			),
		)
		if err != nil {
			t.Fatalf("cannot build the token: %v", err)
		}

		encoded, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize the token: %v", err)
		}

		parsed, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot parse the token: %v", err)
		}

		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(accept))

		if err := parsed.Verify(t.Context(), nil, config); !errors.Is(err, jwk.ErrCertificateKeyMismatch) {
			t.Errorf("got error %v, want ErrCertificateKeyMismatch", err)
		}
	})
}

func generateSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return privateKey
}

func certificateOf(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rfc7515 conformance"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("cannot create a certificate: %v", err)
	}

	return base64.StdEncoding.EncodeToString(der)
}

// RFC 7515 section 4.1.4, OPTIONAL: "Use of this Header Parameter is OPTIONAL."
//
// The interop obligation, in the configuration that actually tests it. A
// producer that omits "kid" must still interoperate, and the case where that
// costs something is a key set holding more than one key the token could have
// been signed by -- which is what a JWK Set published for every consumer at once
// looks like.
//
// TestOptionalHeaderParametersMayBeOmitted also covers this id, and it verifies
// against a set holding exactly the signing key. That is the easy half: with one
// candidate, a verifier that considers only its best-ranked candidate looks
// identical to one that considers them all. This is the half that tells them
// apart, and it failed when it was first written.
//
// rfc-req: RFC7515-S4_1_4-R02
//
// capability: jws-kid-header -- absent from the header this test builds. Not
// skipped; see may_policy above.
func TestAKeyIDIsOptionalEvenAgainstASetOfSeveralKeys(t *testing.T) {
	keys := make([]*ecdsa.PrivateKey, 3)
	published := make([]*jwk.Key, 3)

	for i := range keys {
		keys[i] = generateSigningKey(t)
		published[i] = jwk.NewKey(keys[i].Public())
	}

	for i := range keys {
		t.Run(fmt.Sprintf("signed by key %d of %d", i+1, len(keys)), func(t *testing.T) {
			token, err := jwt.NewToken(
				jwt.WithIssuer("conformance"),
				jwt.WithSignature(jwa.ES256(), jwk.NewKey(keys[i])),
			)
			if err != nil {
				t.Fatalf("cannot build the token: %v", err)
			}

			compact, err := token.Marshal()
			if err != nil {
				t.Fatalf("cannot serialize: %v", err)
			}

			parsed, err := jwt.Unmarshal(compact)
			if err != nil {
				t.Fatalf("cannot parse: %v", err)
			}

			if err := parsed.Verify(t.Context(), jwk.NewKeySet(published...), jwt.DefaultVerificationConfig); err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}

	t.Run("a kid still binds", func(t *testing.T) {
		identified := jwk.NewKey(keys[0].Public(), jwk.WithID("first"))

		token, err := jwt.NewToken(
			jwt.WithIssuer("conformance"),
			jwt.WithSignature(
				jwa.ES256(),
				jwk.NewKey(keys[1]),
				jws.WithProtectedHeader(header.WithKeyID("first")),
			),
		)
		if err != nil {
			t.Fatalf("cannot build the token: %v", err)
		}

		compact, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize: %v", err)
		}

		parsed, err := jwt.Unmarshal(compact)
		if err != nil {
			t.Fatalf("cannot parse: %v", err)
		}

		err = parsed.Verify(t.Context(), jwk.NewKeySet(identified), jwt.DefaultVerificationConfig)
		if !errors.Is(err, jwt.ErrUnverified) {
			t.Errorf("got error %v, want ErrUnverified", err)
		}
	})
}
