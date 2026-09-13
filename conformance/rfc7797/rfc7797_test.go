package rfc7797_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

// RFC 7797 section 7 (MUST NOT): "For interoperability reasons, JSON Web Tokens
// [JWT] MUST NOT use "b64" with a "false" value."; and the Abstract (MUST NOT),
// restating it as this specification's update to RFC 7519.
//
// Checked in both directions: a header this module will not write is not one it
// should accept.
//
// rfc-req: RFC7797-S7-R03, RFC7797-SAbstract-R01
func TestFalseB64IsRefused(t *testing.T) {
	for name, document := range map[string]string{
		"WithCrit":    `{"alg":"HS256","b64":false,"crit":["b64"]}`,
		"WithoutCrit": `{"alg":"HS256","b64":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			var decoded header.Header
			if err := json.Unmarshal([]byte(document), &decoded); !errors.Is(err, header.ErrUnencodedPayload) {
				t.Errorf("got %v, want an error wrapping %v", err, header.ErrUnencodedPayload)
			}
		})
	}

	t.Run("Encoding", func(t *testing.T) {
		unencoded := false

		toEncode := &header.Header{
			Algorithm:              jwa.HS256(),
			Base64URLEncodePayload: &unencoded,
			Critical:               []string{"b64"},
		}

		if _, err := json.Marshal(toEncode); !errors.Is(err, header.ErrUnencodedPayload) {
			t.Errorf("got %v, want an error wrapping %v", err, header.ErrUnencodedPayload)
		}
	})
}

// RFC 7797 section 3 (MAY): "Use of this Header Parameter is OPTIONAL."
//
// This module declines the option, which is conformant. The interop half is
// what must hold either way and is never skipped: a JWS the module cannot
// process has to be refused rather than misread, and refused for that reason.
// RFC 7515 section 4.1.11 is what makes declining safe -- an implementation
// meeting a crit value it does not support must reject the JWS -- and RFC 7797
// section 6 is what guarantees b64 appears there.
//
// rfc-req: RFC7797-S3-R02
func TestConformantUnencodedPayloadJWSIsRefused(t *testing.T) {
	protectedHeader := `{"alg":"HS256","b64":false,"crit":["b64"]}`

	var decoded header.Header
	err := json.Unmarshal([]byte(protectedHeader), &decoded)

	if !errors.Is(err, header.ErrUnencodedPayload) {
		t.Fatalf("got %v, want an error wrapping %v", err, header.ErrUnencodedPayload)
	}

	compact := base64.RawURLEncoding.EncodeToString([]byte(protectedHeader)) + ".payload-with-no-period.c2ln"

	if _, err := jwt.Unmarshal(compact); !errors.Is(err, header.ErrUnencodedPayload) {
		t.Errorf("got %v, want an error wrapping %v", err, header.ErrUnencodedPayload)
	}
}

// RFC 7797 section 6 (MUST): "The "crit" Header Parameter MUST be included with
// "b64" in its set of values when using the "b64" Header Parameter to cause
// implementations not implementing "b64" to reject the JWS (instead of it being
// misinterpreted)."
//
// The converse is checked too, from RFC 7515 section 4.1.11: crit "MUST NOT be
// used with ... Header Parameter values that are not present". Testing both
// halves is what distinguishes a real consistency rule from a check that only
// ever inspects one member.
//
// rfc-req: RFC7797-S6-R01
func TestB64RequiresCritAndCritRequiresB64(t *testing.T) {
	for name, testCase := range map[string]struct {
		document string
		want     error
	}{
		"B64WithoutCrit":  {`{"alg":"HS256","b64":true}`, header.ErrCriticalParameterMismatch},
		"CritWithoutB64":  {`{"alg":"HS256","crit":["b64"]}`, header.ErrCriticalParameterMismatch},
		"BothConsistent":  {`{"alg":"HS256","b64":true,"crit":["b64"]}`, nil},
		"NeitherPresent":  {`{"alg":"HS256"}`, nil},
		"UnknownCritical": {`{"alg":"HS256","crit":["exp"]}`, header.ErrUnsupportedCriticalParameter},
	} {
		t.Run(name, func(t *testing.T) {
			var decoded header.Header
			err := json.Unmarshal([]byte(testCase.document), &decoded)

			if testCase.want == nil {
				if err != nil {
					t.Errorf("got %v, want no error", err)
				}

				return
			}

			if !errors.Is(err, testCase.want) {
				t.Errorf("got %v, want an error wrapping %v", err, testCase.want)
			}
		})
	}
}

// RFC 7797 section 3 (MUST): "When used, this Header Parameter MUST be
// integrity protected; therefore, it MUST occur only within the JWS Protected
// Header."
//
// The fixtures deliberately carry crit alongside b64 in the unprotected header.
// Without it the header-level rule of section 6 fires first and this rule is
// never reached, so a fixture omitting crit would pass while proving something
// else entirely.
//
// rfc-req: RFC7797-S3-R01
func TestB64OutsideTheProtectedHeaderIsRefused(t *testing.T) {
	encodePayload := true

	t.Run("Marshalling", func(t *testing.T) {
		signature := &jws.Signature{
			ProtectedHeader: &header.Header{Algorithm: jwa.HS256()},
			Header: &header.Header{
				Base64URLEncodePayload: &encodePayload,
				Critical:               []string{"b64"},
			},
		}

		if _, err := json.Marshal(signature); !errors.Is(err, jws.ErrUnprotectedUnencodedPayload) {
			t.Errorf("got %v, want an error wrapping %v", err, jws.ErrUnprotectedUnencodedPayload)
		}
	})

	t.Run("Unmarshalling", func(t *testing.T) {
		document := `{"protected":"` +
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) +
			`","header":{"crit":["b64"],"b64":true},"signature":""}`

		var signature jws.Signature
		if err := json.Unmarshal([]byte(document), &signature); !errors.Is(err, jws.ErrUnprotectedUnencodedPayload) {
			t.Errorf("got %v, want an error wrapping %v", err, jws.ErrUnprotectedUnencodedPayload)
		}
	})
}

// RFC 7797 section 7 (SHOULD): "While it is legal to use "b64" with a "true"
// value, it is RECOMMENDED that "b64" simply be omitted in this case, since it
// would be selecting the behavior already specified in [JWS]."
//
// Two halves: this module follows the recommendation by never writing b64 of
// its own accord, and it honours the "legal" in that sentence by letting a
// caller who writes one explicitly round-trip it.
//
// rfc-req: RFC7797-S7-R02
func TestB64IsOmittedRatherThanWrittenTrue(t *testing.T) {
	token, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), jwk.NewKey(hmacSecret())))
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	protectedHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(serialized, ".")[0])
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}

	var members map[string]any
	if err := json.Unmarshal(protectedHeader, &members); err != nil {
		t.Fatalf("cannot read the protected header: %v", err)
	}

	if _, present := members["b64"]; present {
		t.Errorf("got a b64 member in %s, want it omitted", protectedHeader)
	}

	encodePayload := true

	explicit := &header.Header{
		Algorithm:              jwa.HS256(),
		Base64URLEncodePayload: &encodePayload,
		Critical:               []string{"b64"},
	}

	encoded, err := json.Marshal(explicit)
	if err != nil {
		t.Fatalf("a true b64 is legal but failed to encode: %v", err)
	}

	var decoded header.Header
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot decode what was just encoded: %v", err)
	}

	if decoded.Base64URLEncodePayload == nil || !*decoded.Base64URLEncodePayload {
		t.Errorf("got b64 %v after a round trip, want it preserved as true", decoded.Base64URLEncodePayload)
	}
}

func hmacSecret() []byte {
	return []byte("a shared secret of thirty-two-plus octets")
}
