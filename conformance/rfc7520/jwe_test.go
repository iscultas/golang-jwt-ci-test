package rfc7520_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
)

func recipientKey(t *testing.T, vector jweVector) any {
	t.Helper()

	if vector.password != "" {
		return []byte(vector.password)
	}

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(vector.key), key); err != nil {
		t.Fatalf("cannot parse the key: %v", err)
	}

	return key.Material()
}

// RFC 7520 section 5 (test vectors): the worked JWE encryption examples, each
// published with the recipient's key and both serializations.
//
// Decryption is the assertion. It proves this module reads what another
// implementation wrote, which is the property the cookbook exists to establish
// and the only one available here -- see the note on jweVector for why these
// cannot be reproduced.
//
// rfc-req: RFC7520-S5-R01
func TestPublishedJWEsDecrypt(t *testing.T) {
	for _, vector := range jweVectors {
		t.Run(vector.name, func(t *testing.T) {
			if vector.compact == "" {
				t.Skipf("section %s publishes no compact serialization", vector.section)
			}

			message, err := jwe.Unmarshal(vector.compact)
			if err != nil {
				t.Fatalf("section %s: cannot parse: %v", vector.section, err)
			}

			plaintext, err := message.Decrypt(recipientKey(t, vector))
			if err != nil {
				t.Fatalf("section %s: cannot decrypt: %v", vector.section, err)
			}

			if string(plaintext) != vector.plaintext {
				t.Errorf("section %s: plaintext mismatch:\n got %q\nwant %q", vector.section, plaintext, vector.plaintext)
			}
		})
	}
}

// RFC 7520 section 5 (test vectors): the same examples in the general JWE JSON
// Serialization of RFC 7516 section 7.2.1.
//
// Asserted separately because it is a different parser reaching the same
// decryption, and because it is the only form in which section 5.10's "aad"
// example exists. A JSON serialization that dropped "aad" would still decrypt
// every other vector here, since the AAD is the protected header alone whenever
// the member is absent.
//
// rfc-req: RFC7520-S5-R02
func TestPublishedJWEJSONSerializationsDecrypt(t *testing.T) {
	for _, vector := range jweVectors {
		t.Run(vector.name, func(t *testing.T) {
			message := new(jwe.Message)
			if err := json.Unmarshal([]byte(vector.json), message); err != nil {
				t.Fatalf("section %s: cannot parse: %v", vector.section, err)
			}

			plaintext, err := message.Decrypt(recipientKey(t, vector))
			if err != nil {
				t.Fatalf("section %s: cannot decrypt: %v", vector.section, err)
			}

			if string(plaintext) != vector.plaintext {
				t.Errorf("section %s: plaintext mismatch:\n got %q\nwant %q", vector.section, plaintext, vector.plaintext)
			}
		})
	}
}

// RFC 7520 section 5 (test vectors): the published keys parse as JWKs.
//
// Cheap, and asserted on its own so that a key this module cannot read fails as
// what it is rather than surfacing as an unexplained decryption failure above.
// Section 5.4's P-384 key and section 5.5's P-256 key are the ones that matter
// here: ECDH-ES is the only family whose recipient key is asymmetric.
//
// rfc-req: RFC7520-S5-R03
func TestPublishedJWEKeysParse(t *testing.T) {
	for _, vector := range jweVectors {
		if vector.key == "" {
			continue
		}

		t.Run(vector.name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(vector.key), key); err != nil {
				t.Fatalf("section %s: cannot parse the key: %v", vector.section, err)
			}

			if key.Material() == nil {
				t.Errorf("section %s: the key parsed but holds no material", vector.section)
			}
		})
	}
}
