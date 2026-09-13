package rfc7520_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

// RFC 7520 section 4 (test vectors): the four worked JWS signing examples, each
// published with the key, the protected header and the resulting signature.
//
// Verification is the assertion that applies to all four. It is also the
// stronger direction: it proves this module accepts what another implementation
// produced, which regenerating a signature from our own key would not.
//
// rfc-req: RFC7520-S4-R01
func TestPublishedSignaturesVerify(t *testing.T) {
	for _, vector := range jwsVectors {
		t.Run(vector.name, func(t *testing.T) {
			key := parseKey(t, vector.key)

			algorithm, ok := jwa.ByName(vector.name)
			if !ok {
				t.Skipf("%s is not implemented", vector.name)
			}

			verifier, ok := algorithm.(jwa.Verifier)
			if !ok {
				t.Fatalf("%s cannot verify", vector.name)
			}

			signingInput, signature := split(t, vector.compact)

			material := key.Material()
			if public := key.Public(); public != nil {
				material = public.Material()
			}

			if err := verifier.Verify(signingInput, signature, material); err != nil {
				t.Errorf(
					"section %s (%s): the published signature did not verify: %v",
					vector.section, vector.note, err,
				)
			}
		})
	}
}

// RFC 7520 section 4 (test vectors): for the examples whose algorithms are
// deterministic, signing the published input with the published key must
// reproduce the published signature octet for octet.
//
// PS384 and ES512 are excluded here rather than skipped silently: RSASSA-PSS
// randomises its salt and ECDSA its per-signature nonce, so neither can be
// regenerated. Their coverage comes from TestPublishedSignaturesVerify.
//
// rfc-req: RFC7520-S4-R02
func TestDeterministicSignaturesAreReproduced(t *testing.T) {
	for _, vector := range jwsVectors {
		if !vector.deterministic {
			continue
		}

		t.Run(vector.name, func(t *testing.T) {
			key := parseKey(t, vector.key)

			algorithm, ok := jwa.ByName(vector.name)
			if !ok {
				t.Skipf("%s is not implemented", vector.name)
			}

			signingInput, want := split(t, vector.compact)

			got, err := algorithm.(jwa.Signer).Sign(signingInput, key.Material())
			if err != nil {
				t.Fatalf("section %s: cannot sign: %v", vector.section, err)
			}

			if base64.RawURLEncoding.EncodeToString(got) != base64.RawURLEncoding.EncodeToString(want) {
				t.Errorf(
					"section %s (%s):\ngot  %s\nwant %s",
					vector.section, vector.note,
					base64.RawURLEncoding.EncodeToString(got),
					base64.RawURLEncoding.EncodeToString(want),
				)
			}
		})
	}
}

// RFC 7520 section 3 (test vectors): the keys the examples are signed with,
// given as JWKs. Parsing them is a precondition of everything above, and worth
// asserting on its own so that a key-parsing failure is not reported as a
// signature failure.
//
// rfc-req: RFC7520-S3-R01
func TestPublishedKeysParse(t *testing.T) {
	for _, vector := range jwsVectors {
		t.Run(vector.name, func(t *testing.T) {
			key := parseKey(t, vector.key)

			if key.Material() == nil {
				t.Fatal("the key parsed but carries no material")
			}

			var members map[string]any
			if err := json.Unmarshal([]byte(vector.key), &members); err != nil {
				t.Fatalf("cannot read the published JWK: %v", err)
			}

			protectedHeader := decodeSegment(t, strings.Split(vector.compact, ".")[0])

			var headerMembers map[string]any
			if err := json.Unmarshal(protectedHeader, &headerMembers); err != nil {
				t.Fatalf("cannot read the protected header: %v", err)
			}

			if headerMembers["kid"] != members["kid"] {
				t.Errorf("header names kid %v, key carries %v", headerMembers["kid"], members["kid"])
			}

			if headerMembers["alg"] != vector.name {
				t.Errorf("header names alg %v, want %s", headerMembers["alg"], vector.name)
			}
		})
	}
}

// RFC 7520 section 4 (test vectors): every example signs the same payload, the
// base64url encoding of Figure 7's text given as Figure 8.
//
// Asserted separately because it is what makes the signing inputs comparable
// across the four examples, and because a payload that silently differed would
// make every signature above fail for a reason nothing else would explain.
//
// rfc-req: RFC7520-S4-R03
func TestAllExamplesShareTheFigure8Payload(t *testing.T) {
	const opening = "It’s a dangerous business, Frodo, going out your door."

	decoded := decodeSegment(t, payload)

	if !strings.HasPrefix(string(decoded), opening) {
		t.Errorf("got a payload beginning %q, want it to begin %q", string(decoded)[:min(len(decoded), 60)], opening)
	}

	for _, vector := range jwsVectors {
		if got := strings.Split(vector.compact, ".")[1]; got != payload {
			t.Errorf("section %s signs a different payload than Figure 8", vector.section)
		}
	}
}

func parseKey(t *testing.T, encoded string) *jwk.Key {
	t.Helper()

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(encoded), key); err != nil {
		t.Fatalf("cannot parse the published JWK: %v", err)
	}

	return key
}

func split(t *testing.T, compact string) ([]byte, []byte) {
	t.Helper()

	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}

	return []byte(parts[0] + "." + parts[1]), decodeSegment(t, parts[2])
}

func decodeSegment(t *testing.T, segment string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("cannot decode %q: %v", segment[:min(len(segment), 32)], err)
	}

	return decoded
}
