package rfc7517_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
)

var decoders = map[string]func([]byte, any) error{
	"encoding/json/v2": func(document []byte, into any) error { return json.Unmarshal(document, into) },
	"encoding/json":    jsonv1.Unmarshal,
}

// rfc-req: RFC7517-S2-R01
// rfc-req: RFC7517-S5-R01
//
// RFC 7517 section 2: "JWK Set A JSON object that represents a set of JWKs.
// The JSON object MUST have a "keys" member, which is an array of JWKs."
// Section 5 restates the identical rule in normative terms: "The JSON object
// MUST have a "keys" member, with its value being an array of JWKs." One test
// proves both: every KeySet this package marshals carries "keys" holding an
// array, and decoding a document that omits it does not error.
func TestJWKSetKeysMemberIsAlwaysPresent(t *testing.T) {
	t.Run("EmptySet", func(t *testing.T) {
		requireKeysArray(t, jwk.NewKeySet(), 0)
	})

	t.Run("OneKey", func(t *testing.T) {
		requireKeysArray(t, jwk.NewKeySet(jwk.NewKey([]byte("secret"))), 1)
	})

	t.Run("SeveralKeys", func(t *testing.T) {
		requireKeysArray(t, jwk.NewKeySet(jwk.NewKey([]byte("a")), jwk.NewKey([]byte("b"))), 2)
	})

	t.Run("DecodingWithoutKeysMemberYieldsAnEmptySet", func(t *testing.T) {
		var keySet jwk.KeySet
		if err := json.Unmarshal([]byte(`{}`), &keySet); err != nil {
			t.Fatalf("got error %v, want nil", err)
		}

		if len(keySet.Keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keySet.Keys))
		}
	})
}

// rfc-req: RFC7517-S4-R01
//
// RFC 7517 section 4: "This JSON object MAY contain whitespace and/or line
// breaks before or after any JSON values or structural characters, in
// accordance with Section 2 of RFC 7159."
//
// capability: whitespace-in-json-serialization -- this package never emits it,
// so only the consuming half is exercised, which is the interop obligation.
func TestJWKToleratesWhitespaceAroundValuesAndStructuralCharacters(t *testing.T) {
	compact := []byte(`{"kty":"oct","k":"c2VjcmV0"}`)
	padded := []byte("  {\n \"kty\"\t: \"oct\" ,\n\"k\" : \"c2VjcmV0\"\n} \n")

	var compactKey, paddedKey jwk.Key
	if err := json.Unmarshal(compact, &compactKey); err != nil {
		t.Fatalf("compact: got error %v, want nil", err)
	}
	if err := json.Unmarshal(padded, &paddedKey); err != nil {
		t.Fatalf("padded: got error %v, want nil", err)
	}

	if !bytes.Equal(compactKey.Material().([]byte), paddedKey.Material().([]byte)) {
		t.Errorf("got material %v and %v, want equal", compactKey.Material(), paddedKey.Material())
	}
}

// rfc-req: RFC7517-S4-R02
//
// RFC 7517 section 4: "The member names within a JWK MUST be unique; JWK
// parsers MUST either reject JWKs with duplicate member names or use a JSON
// parser that returns only the lexically last duplicate member name." This
// package takes the first of the two.
//
// The document goes through the two encoding/json packages. A caller selects
// the decoder, and the rejection is a property of the key and not of that
// selection.
func TestJWKDuplicateMemberNameIsRejected(t *testing.T) {
	document := []byte(`{"kty":"oct","k":"AAAA","k":"BBBB"}`)

	for name, unmarshal := range decoders {
		t.Run(name, func(t *testing.T) {
			err := unmarshal(document, new(jwk.Key))
			if !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Errorf("got %v, want an error wrapping jsontext.ErrDuplicateName", err)
			}
		})
	}
}

// rfc-req: RFC7517-S4-R03
//
// RFC 7517 section 4: "Additional members can be present in the JWK; if not
// understood by implementations encountering them, they MUST be ignored."
func TestJWKIgnoresAnUnrecognizedMember(t *testing.T) {
	document := []byte(`{"kty":"oct","k":"c2VjcmV0","x-custom-member":{"nested":true}}`)

	var key jwk.Key
	if err := json.Unmarshal(document, &key); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if string(key.Material().([]byte)) != "secret" {
		t.Errorf("got material %q, want %q", key.Material(), "secret")
	}
}

// rfc-req: RFC7517-S4_1-R01
//
// RFC 7517 section 4.1: "This member [kty] MUST be present in a JWK."
// Checked from both directions: every material type this package represents
// names itself, and material it cannot name is refused rather than written
// out as a JWK with no kty at all.
func TestKeyTypeIsAlwaysPresent(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]*jwk.Key{
		"EllipticCurve":       jwk.NewKey(ecdsaKey),
		"EllipticCurvePublic": jwk.NewKey(&ecdsaKey.PublicKey),
		"RSA":                 jwk.NewKey(rsaKey),
		"RSAPublic":           jwk.NewKey(&rsaKey.PublicKey),
		"OctetSequence":       jwk.NewKey([]byte("secret")),
		"OctetKeyPairPrivate": jwk.NewKey(ed25519Private),
		"OctetKeyPairPublic":  jwk.NewKey(ed25519Public),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			document, err := json.Marshal(key)
			if err != nil {
				t.Fatalf("got error %v, want nil", err)
			}

			var members map[string]jsontext.Value
			if err := json.Unmarshal(document, &members); err != nil {
				t.Fatal(err)
			}

			kty, ok := members["kty"]
			if !ok || len(kty) <= len(`""`) {
				t.Errorf("got document %s, want a non-empty \"kty\" member", document)
			}
		})
	}

	t.Run("UnnameableMaterialIsRefused", func(t *testing.T) {
		if _, err := json.Marshal(jwk.NewKey(struct{ Unsupported bool }{})); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
			t.Errorf("got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
		}
	})

	t.Run("KeyDecodedFromAnUnimplementedKeyTypeIsRefused", func(t *testing.T) {
		key := new(jwk.Key)
		if err := json.Unmarshal([]byte(`{"kty":"bogus"}`), key); err != nil {
			t.Fatalf("got error %v, want nil", err)
		}

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
			t.Errorf("got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
		}
	})
}

// rfc-req: RFC7517-S4_3-R02
//
// RFC 7517 section 4.3: "Duplicate key operation values MUST NOT be present in
// the array." Applied on both sides -- a serialization this package would
// refuse to parse must not be one it will produce.
func TestDuplicateKeyOperationsAreRejected(t *testing.T) {
	t.Run("Encoding", func(t *testing.T) {
		key := jwk.NewKey([]byte("secret"), jwk.WithOperations(jwk.Sign, jwk.Sign))

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrDuplicateKeyOperation) {
			t.Errorf("got error %v, want %v", err, jwk.ErrDuplicateKeyOperation)
		}
	})

	t.Run("Decoding", func(t *testing.T) {
		document := []byte(`{"kty":"oct","k":"AAAA","key_ops":["sign","verify","sign"]}`)

		if err := json.Unmarshal(document, new(jwk.Key)); !errors.Is(err, jwk.ErrDuplicateKeyOperation) {
			t.Errorf("got error %v, want %v", err, jwk.ErrDuplicateKeyOperation)
		}
	})

	t.Run("ExtensionOperation", func(t *testing.T) {
		document := []byte(`{"kty":"oct","k":"AAAA","key_ops":["custom-op","custom-op"]}`)

		if err := json.Unmarshal(document, new(jwk.Key)); !errors.Is(err, jwk.ErrDuplicateKeyOperation) {
			t.Errorf("got error %v, want %v", err, jwk.ErrDuplicateKeyOperation)
		}
	})
}

// rfc-req: RFC7517-S4_3-R06
//
// RFC 7517 section 4.3: "The "use" and "key_ops" JWK members SHOULD NOT be used
// together; however, if both are used, the information they convey MUST be
// consistent." The MUST half is asserted here. The SHOULD NOT half is not: the
// clause after it defines what to do when both are set, so refusing a key that
// sets both would reject documents the sentence contemplates.
//
// Which operations belong to which use is taken from section 4.2, not inferred:
// it defines sig as verifying signatures and enc as encrypting data, then puts
// key wrapping under enc ("key wrapping is a kind of encryption") and key
// agreement under it too.
func TestInconsistentPublicKeyUseIsRejected(t *testing.T) {
	for name, document := range map[string]string{
		"SigningOperationUnderEncryptionUse":   `{"kty":"oct","k":"AAAA","use":"enc","key_ops":["sign"]}`,
		"EncryptionOperationUnderSignatureUse": `{"kty":"oct","k":"AAAA","use":"sig","key_ops":["decrypt"]}`,
		"OneOfSeveralInconsistent":             `{"kty":"oct","k":"AAAA","use":"sig","key_ops":["sign","verify","wrapKey"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(document), new(jwk.Key)); !errors.Is(err, jwk.ErrInconsistentKeyUse) {
				t.Errorf("got error %v, want %v", err, jwk.ErrInconsistentKeyUse)
			}
		})
	}

	t.Run("Encoding", func(t *testing.T) {
		key := jwk.NewKey(
			[]byte("secret"), jwk.WithPublicKeyUse(jwk.Encryption), jwk.WithOperations(jwk.Sign),
		)

		if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrInconsistentKeyUse) {
			t.Errorf("got error %v, want %v", err, jwk.ErrInconsistentKeyUse)
		}
	})

	for name, document := range map[string]string{
		"SignAndVerifyUnderSignatureUse": `{"kty":"oct","k":"AAAA","use":"sig","key_ops":["sign","verify"]}`,
		"KeyWrappingUnderEncryptionUse":  `{"kty":"oct","k":"AAAA","use":"enc","key_ops":["wrapKey","unwrapKey"]}`,
		"KeyAgreementUnderEncryptionUse": `{"kty":"oct","k":"AAAA","use":"enc","key_ops":["deriveKey"]}`,
		"ExtensionUse":                   `{"kty":"oct","k":"AAAA","use":"custom-use","key_ops":["sign"]}`,
		"ExtensionOperation":             `{"kty":"oct","k":"AAAA","use":"enc","key_ops":["custom-op"]}`,
		"OperationsWithoutUse":           `{"kty":"oct","k":"AAAA","key_ops":["sign","decrypt"]}`,
		"UseWithoutOperations":           `{"kty":"oct","k":"AAAA","use":"sig"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(document), new(jwk.Key)); err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}

// rfc-req: RFC7517-S4_2-R01
//
// RFC 7517 section 4.2: "Values defined by this specification are: "sig"
// (signature), "enc" (encryption). Other values MAY be used."
//
// capability: unregistered-public-key-use -- present. The interop obligation
// is the consuming half: a decoder knowing only "sig" and "enc" must still
// accept a key carrying neither, and carry the value back out unchanged.
func TestPublicKeyUseAcceptsValuesBeyondSigAndEnc(t *testing.T) {
	key := jwk.NewKey([]byte("secret"), jwk.WithPublicKeyUse("custom-use"))

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	roundTripped, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(roundTripped), `"use":"custom-use"`) {
		t.Errorf("got %s, want a preserved \"use\":\"custom-use\" member", roundTripped)
	}
}

// rfc-req: RFC7517-S4_2-R02
//
// RFC 7517 section 4.2: "Use of the "use" member is OPTIONAL, unless the
// application requires its presence."
//
// capability: jwk-use-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestPublicKeyUseIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"use"`) {
		t.Errorf("got %s, want no \"use\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"use\" member", err)
	}
}

// rfc-req: RFC7517-S4_3-R01
//
// RFC 7517 section 4.3: "Values defined by this specification are: "sign",
// "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey",
// "deriveBits" ... Other values MAY be used."
//
// capability: unregistered-key-operations -- present. The interop obligation
// is the consuming half, asserted below the emit check.
func TestKeyOperationsAcceptsValuesBeyondTheEightRegistered(t *testing.T) {
	key := jwk.NewKey([]byte("secret"), jwk.WithOperations("custom-op"))

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if !strings.Contains(string(document), `"key_ops":["custom-op"]`) {
		t.Errorf("got %s, want a preserved \"key_ops\":[\"custom-op\"] member", document)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	roundTripped, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(roundTripped), `"key_ops":["custom-op"]`) {
		t.Errorf("got %s, want a preserved \"key_ops\":[\"custom-op\"] member", roundTripped)
	}
}

// rfc-req: RFC7517-S4_3-R03
//
// RFC 7517 section 4.3: "Use of the "key_ops" member is OPTIONAL, unless the
// application requires its presence."
//
// capability: jwk-key-ops-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestKeyOperationsIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"key_ops"`) {
		t.Errorf("got %s, want no \"key_ops\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"key_ops\" member", err)
	}
}

// rfc-req: RFC7517-S4_4-R01
//
// RFC 7517 section 4.4: "Use of this member [alg] is OPTIONAL."
//
// capability: jwk-alg-member -- absent from the key this test builds; the
// obligation is that decoding, and key selection, succeed anyway. See
// may_policy above.
func TestAlgorithmIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"alg"`) {
		t.Errorf("got %s, want no \"alg\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"alg\" member", err)
	}
}

// rfc-req: RFC7517-S4_5-R02
//
// RFC 7517 section 4.5: "Use of this member [kid] is OPTIONAL."
//
// capability: jwk-kid-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestKeyIDIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"kid"`) {
		t.Errorf("got %s, want no \"kid\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"kid\" member", err)
	}
}

// rfc-req: RFC7517-S4_6-R04
//
// RFC 7517 section 4.6: "Use of this member [x5u] is OPTIONAL."
//
// capability: jwk-x5u-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestX509URLIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"x5u"`) {
		t.Errorf("got %s, want no \"x5u\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"x5u\" member", err)
	}
}

// rfc-req: RFC7517-S4_7-R02
//
// RFC 7517 section 4.7: "The PKIX certificate containing the key value MUST
// be the first certificate. This MAY be followed by additional certificates,
// with each subsequent certificate being the one used to certify the
// previous one."
//
// capability: x509-chain-intermediates -- present. A producer sending a
// single-certificate chain is equally conformant; the obligation asserted
// here is that a longer chain from such a peer survives intact and in order.
func TestX509CertificateChainPreservesOrderAcrossMultipleCertificates(t *testing.T) {
	intermediate, intermediateKey := selfSignedCertificate(t, "intermediate")

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leaf := certificateFor(t, "leaf", leafKey, intermediateKey, intermediate, 0)

	key := jwk.NewKey(&leafKey.PublicKey, jwk.WithX509CertificateChain([]*x509.Certificate{leaf, intermediate}))

	first, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	second, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("round trip not byte-identical:\n first=%s\nsecond=%s", first, second)
	}
}

// rfc-req: RFC7517-S4_7-R04
//
// RFC 7517 section 4.7: "Use of this member [x5c] is OPTIONAL."
//
// capability: jwk-x5c-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestX509CertificateChainIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"x5c"`) {
		t.Errorf("got %s, want no \"x5c\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"x5c\" member", err)
	}
}

// rfc-req: RFC7517-S4_7-R05
//
// RFC 7517 section 4.7: "As with the "x5u" member, optional JWK members
// providing key usage, algorithm, or other information MAY also be present
// when the "x5c" member is used."
//
// capability: coexisting-optional-jwk-members -- present. Not skipped; see
// may_policy above.
func TestX509CertificateChainCoexistsWithOtherOptionalMembers(t *testing.T) {
	cert, certKey := selfSignedCertificate(t, "leaf")
	key := jwk.NewKey(&certKey.PublicKey,
		jwk.WithX509CertificateChain([]*x509.Certificate{cert}),
		jwk.WithID("kid-1"),
		jwk.WithPublicKeyUse(jwk.Signature),
	)

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	roundTripped, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(document, roundTripped) {
		t.Errorf("round trip not byte-identical:\n first=%s\nsecond=%s", document, roundTripped)
	}
}

// rfc-req: RFC7517-S4_7-R07
//
// RFC 7517 section 4.7: "Each string in the array is a base64-encoded
// (Section 4 of [RFC4648] -- not base64url-encoded) DER [ITU.X690.1994] PKIX
// certificate value." This sentence carries no BCP 14 keyword but is squarely
// normative: it fixes the alphabet, distinct from the base64url used
// elsewhere in a JWK.
//
// The citation of RFC 4648 section 4 carries more than the alphabet, and the
// rest is asserted here because no separate suite holds it: padding is required
// rather than omitted, and line breaks are refused. The second was a real
// defect -- a certificate copied out of a PEM file, wrapped at 64 columns,
// parsed -- and it is reached through this sentence, since it is section 4.7's
// citation and nothing else that puts "x5c" under those rules.
func TestX509CertificateChainUsesStandardBase64NotURLSafeAlphabet(t *testing.T) {
	var cert *x509.Certificate
	var certKey *ecdsa.PrivateKey
	var encoded string
	for range 50 {
		candidate, candidateKey := selfSignedCertificate(t, "leaf")
		candidateEncoded := base64.StdEncoding.EncodeToString(candidate.Raw)
		if strings.ContainsAny(candidateEncoded, "+/") && len(candidate.Raw)%3 != 0 {
			cert, certKey, encoded = candidate, candidateKey, candidateEncoded
			break
		}
	}
	if cert == nil {
		t.Fatal("failed to generate a certificate whose base64 encoding exercises '+' or '/' and needs padding")
	}

	key := jwk.NewKey(&certKey.PublicKey, jwk.WithX509CertificateChain([]*x509.Certificate{cert}))

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if !strings.Contains(string(document), `"x5c":["`+encoded+`"]`) {
		t.Errorf("got %s, want the x5c entry to equal the standard-alphabet encoding %q", document, encoded)
	}

	if _, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		t.Errorf("encoding %q unexpectedly also decodes as base64url; fixture does not distinguish the alphabets", encoded)
	}

	if !strings.HasSuffix(encoded, "=") {
		t.Fatalf("the fixture %q needs no padding, so this case would hold vacuously", encoded)
	}

	if _, err := base64.StdEncoding.Strict().DecodeString(encoded); err != nil {
		t.Errorf("the x5c entry this module wrote is not correctly padded: %v", err)
	}

	for name, mutated := range map[string]string{
		"unpadded":              strings.TrimRight(encoded, "="),
		"wrapped at 64 columns": wrapAt64(encoded),
	} {
		t.Run(name, func(t *testing.T) {
			document := strings.Replace(string(document), encoded, mutated, 1)

			if err := json.Unmarshal([]byte(document), new(jwk.Key)); err == nil {
				t.Errorf("accepted %s, want an error", document)
			}
		})
	}
}

func wrapAt64(encoded string) string {
	var wrapped strings.Builder

	for index := 0; index < len(encoded); index += 64 {
		if index != 0 {
			wrapped.WriteString(`\n`)
		}

		wrapped.WriteString(encoded[index:min(index+64, len(encoded))])
	}

	return wrapped.String()
}

// rfc-req: RFC7517-S4_8-R02
//
// RFC 7517 section 4.8: "Use of this member [x5t] is OPTIONAL."
//
// capability: jwk-x5t-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestX509SHA1ThumbprintIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"x5t"`) {
		t.Errorf("got %s, want no \"x5t\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"x5t\" member", err)
	}
}

// rfc-req: RFC7517-S4_8-R03
//
// RFC 7517 section 4.8: "As with the "x5u" member, optional JWK members
// providing key usage, algorithm, or other information MAY also be present
// when the "x5t" member is used."
//
// capability: coexisting-optional-jwk-members -- present. Not skipped; see
// may_policy above.
func TestX509SHA1ThumbprintCoexistsWithOtherOptionalMembers(t *testing.T) {
	certificate, certificateKey := selfSignedCertificate(t, "leaf")
	digest := sha1.Sum(certificate.Raw)

	key := jwk.NewKey(&certificateKey.PublicKey,
		jwk.WithX509CertificateChain([]*x509.Certificate{certificate}),
		jwk.WithX509CertificateSHA1Thumbprint(base64.RawURLEncoding.EncodeToString(digest[:])),
		jwk.WithID("kid-1"),
		jwk.WithAlgorithm(jwa.ES256()),
	)

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	roundTripped, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(document, roundTripped) {
		t.Errorf("round trip not byte-identical:\n first=%s\nsecond=%s", document, roundTripped)
	}
}

// rfc-req: RFC7517-S4_9-R02
//
// RFC 7517 section 4.9: "Use of this member [x5t#S256] is OPTIONAL."
//
// capability: jwk-x5t-s256-member -- absent from the key this test builds; the
// obligation is that decoding succeeds anyway. See may_policy above.
func TestX509SHA256ThumbprintIsOptional(t *testing.T) {
	document, err := json.Marshal(jwk.NewKey([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(document), `"x5t#S256"`) {
		t.Errorf("got %s, want no \"x5t#S256\" member when none was configured", document)
	}

	var key jwk.Key
	if err := json.Unmarshal([]byte(`{"kty":"oct","k":"c2VjcmV0"}`), &key); err != nil {
		t.Errorf("got error %v, want nil for a JWK with no \"x5t#S256\" member", err)
	}
}

// rfc-req: RFC7517-S4_9-R03
//
// RFC 7517 section 4.9: "As with the "x5u" member, optional JWK members
// providing key usage, algorithm, or other information MAY also be present
// when the "x5t#S256" member is used."
//
// capability: coexisting-optional-jwk-members -- present. Not skipped; see
// may_policy above.
func TestX509SHA256ThumbprintCoexistsWithOtherOptionalMembers(t *testing.T) {
	certificate, certificateKey := selfSignedCertificate(t, "leaf")
	digest := sha256.Sum256(certificate.Raw)

	key := jwk.NewKey(&certificateKey.PublicKey,
		jwk.WithX509CertificateChain([]*x509.Certificate{certificate}),
		jwk.WithX509CertificateSHA256Thumbprint(base64.RawURLEncoding.EncodeToString(digest[:])),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithID("kid-1"),
	)

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	roundTripped, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(document, roundTripped) {
		t.Errorf("round trip not byte-identical:\n first=%s\nsecond=%s", document, roundTripped)
	}
}

// rfc-req: RFC7517-S5-R02
//
// RFC 7517 section 5: "This JSON object MAY contain whitespace and/or line
// breaks."
//
// capability: whitespace-in-json-serialization, at the JWK Set level. Same
// asymmetry as the single-key case: emitted compact, accepted padded.
func TestJWKSetToleratesWhitespace(t *testing.T) {
	compact := []byte(`{"keys":[{"kty":"oct","k":"AAAA"},{"kty":"oct","k":"BBBB"}]}`)
	padded := []byte("  {\n \"keys\" : [\n {\"kty\":\"oct\", \"k\":\"AAAA\"} ,\n {\"kty\":\"oct\",\"k\":\"BBBB\"}\n ]\n} \n")

	var compactSet, paddedSet jwk.KeySet
	if err := json.Unmarshal(compact, &compactSet); err != nil {
		t.Fatalf("compact: got error %v, want nil", err)
	}
	if err := json.Unmarshal(padded, &paddedSet); err != nil {
		t.Fatalf("padded: got error %v, want nil", err)
	}

	if len(compactSet.Keys) != len(paddedSet.Keys) {
		t.Fatalf("got %d and %d keys, want equal counts", len(compactSet.Keys), len(paddedSet.Keys))
	}
	for i := range compactSet.Keys {
		if !bytes.Equal(compactSet.Keys[i].Material().([]byte), paddedSet.Keys[i].Material().([]byte)) {
			t.Errorf("key %d: got material %v and %v, want equal", i, compactSet.Keys[i].Material(), paddedSet.Keys[i].Material())
		}
	}
}

// rfc-req: RFC7517-S5-R03
//
// RFC 7517 section 5: "The member names within a JWK Set MUST be unique; JWK
// Set parsers MUST either reject JWK Sets with duplicate member names or use
// a JSON parser that returns only the lexically last duplicate member name."
// This package takes the first of the two. A set that names "keys" two times
// would otherwise publish one array and hide another.
func TestJWKSetDuplicateMemberNameIsRejected(t *testing.T) {
	document := []byte(`{"keys":[{"kty":"oct","k":"AAAA"}],"keys":[{"kty":"oct","k":"BBBB"}]}`)

	for name, unmarshal := range decoders {
		t.Run(name, func(t *testing.T) {
			err := unmarshal(document, new(jwk.KeySet))
			if !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Errorf("got %v, want an error wrapping jsontext.ErrDuplicateName", err)
			}
		})
	}
}

// rfc-req: RFC7517-S5-R04
//
// RFC 7517 section 5: "Additional members can be present in the JWK Set; if
// not understood by implementations encountering them, they MUST be
// ignored."
func TestJWKSetIgnoresAnUnrecognizedMember(t *testing.T) {
	document := []byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}],"x-custom-member":42}`)

	var keySet jwk.KeySet
	if err := json.Unmarshal(document, &keySet); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if len(keySet.Keys) != 1 || string(keySet.Keys[0].Material().([]byte)) != "secret" {
		t.Errorf("got %+v, want one key with material \"secret\"", keySet.Keys)
	}
}

// rfc-req: RFC7517-S5-R05
//
// RFC 7517 section 5: "Implementations SHOULD ignore JWKs within a JWK Set that
// use "kty" (key type) values that are not understood by them, that are missing
// required members, or for which values are out of the supported ranges."
//
// A JWKS is published once for every consumer, so it will routinely carry a key
// some particular consumer cannot use. Failing the document over one such key
// would leave the usable keys beside it unreachable.
func TestJWKSetIgnoresUnusableKeys(t *testing.T) {
	const usable = `{"kty":"oct","k":"c2VjcmV0"}`

	for name, testCase := range map[string]struct {
		unusable     string
		expectedKeys int
	}{
		"KeyTypeNotUnderstood":  {`{"kty":"bogus","whatever":1}`, 1},
		"MissingRequiredMember": {`{"kty":"RSA"}`, 1},
		"ValueOutOfRange":       {`{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}`, 1},
		"NullElement":           {`null`, 1},
	} {
		t.Run(name, func(t *testing.T) {
			document := []byte(`{"keys":[` + usable + `,` + testCase.unusable + `,` + usable + `]}`)

			var keySet jwk.KeySet
			if err := json.Unmarshal(document, &keySet); err != nil {
				t.Fatalf("got error %v, want nil", err)
			}

			if len(keySet.Keys) != testCase.expectedKeys*2 {
				t.Fatalf("got %d keys, want %d", len(keySet.Keys), testCase.expectedKeys*2)
			}

			for i, key := range keySet.Keys {
				if key.Material() == nil {
					t.Errorf("got key %d with no material, want it ignored rather than kept", i)
				}
			}
		})
	}

	t.Run("NothingUsable", func(t *testing.T) {
		var keySet jwk.KeySet
		if err := json.Unmarshal([]byte(`{"keys":[{"kty":"RSA"}]}`), &keySet); err != nil {
			t.Fatalf("got error %v, want nil", err)
		}

		if len(keySet.Keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keySet.Keys))
		}
	})

	t.Run("MalformedSetStillRejected", func(t *testing.T) {
		if err := json.Unmarshal([]byte(`{"keys":"not an array"}`), new(jwk.KeySet)); err == nil {
			t.Error("got nil error, want one")
		}
	})
}

// rfc-req: RFC7517-S6-R01
//
// RFC 7517 section 6: "The string comparison rules for this specification
// are the same as those defined in Section 5.3 of [JWS]" -- exact,
// case-sensitive, Unicode code-point equality. Exercised on the one string
// comparison this package performs on a JWK's own data: matching a requested
// kid against a candidate key's kid in KeySet.Key.
func TestKeySetSelectionComparesKeyIDCaseSensitively(t *testing.T) {
	keySet := jwk.NewKeySet(jwk.NewKey([]byte("secret"), jwk.WithID("ABC")))

	if _, err := keySet.Key("", nil, nil, "abc"); err == nil {
		t.Error("got nil error selecting by \"abc\" against a key whose kid is \"ABC\", want ErrNoSuitableKey")
	}

	if _, err := keySet.Key("", nil, nil, "ABC"); err != nil {
		t.Errorf("got error %v selecting by the exact kid \"ABC\", want nil", err)
	}
}

func requireKeysArray(t *testing.T, keySet *jwk.KeySet, expectedKeys int) {
	t.Helper()

	document, err := json.Marshal(keySet)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	var members map[string]jsontext.Value
	if err := json.Unmarshal(document, &members); err != nil {
		t.Fatal(err)
	}

	keys, ok := members["keys"]
	if !ok {
		t.Fatalf("got document %s, want a \"keys\" member", document)
	}

	var array []jsontext.Value
	if err := json.Unmarshal(keys, &array); err != nil {
		t.Fatalf("got \"keys\" value %s in %s, want a JSON array: %v", keys, document, err)
	}

	if keys[0] != '[' {
		t.Errorf("got \"keys\" value %s in %s, want a JSON array", keys, document)
	}

	if len(array) != expectedKeys {
		t.Errorf("got %d elements in %s, want %d", len(array), keys, expectedKeys)
	}
}

func selfSignedCertificate(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return certificateFor(t, commonName, privateKey, privateKey, nil, 0), privateKey
}

func certificateFor(
	t *testing.T,
	commonName string,
	subject, issuer *ecdsa.PrivateKey,
	issuerCertificate *x509.Certificate,
	usage x509.KeyUsage,
) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     usage,
	}

	parent := template
	if issuerCertificate != nil {
		parent = issuerCertificate
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &subject.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// TestEncryptedJWKUsesTheContentType checks §7's "cty" guidance for a JWK
// carried as a JWE plaintext.
//
// MUST — "A 'cty' (content type) Header Parameter value of 'jwk+json' MUST be
// used to indicate that the content of the JWE is a JWK, unless the application
// knows that the encrypted content is a JWK by another means or convention."
//
// Not-testable until this module gained a JWE type. The value is the
// application's to choose — the sentence itself provides for one that knows the
// content type by other means — so what this module owes is that the parameter is
// carried faithfully and integrity protected, which is what is asserted.
//
// rfc-req: RFC7517-S7-R02
func TestEncryptedJWKUsesTheContentType(t *testing.T) {
	subject := jwk.NewKey(
		bytes.Repeat([]byte{3}, 32),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign),
	)

	plaintext, err := json.Marshal(subject)
	if err != nil {
		t.Fatalf("cannot encode the JWK: %v", err)
	}

	key := bytes.Repeat([]byte{7}, 16)

	message := &jwe.Message{ProtectedHeader: &header.Header{
		ContentType:         "jwk+json",
		Algorithm:           jwa.A128KW(),
		EncryptionAlgorithm: jwa.A128GCM(),
	}}

	if err := message.Encrypt(plaintext, key); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	encoded, err := message.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	read, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	if got := read.ProtectedHeader.ContentType; got != "jwk+json" {
		t.Errorf("cty is %q, want %q", got, "jwk+json")
	}

	recovered, err := read.Decrypt(key)
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	recoveredKey := new(jwk.Key)
	if err := json.Unmarshal(recovered, recoveredKey); err != nil {
		t.Fatalf("the plaintext is not a JWK: %v", err)
	}

	if recoveredKey.Type() != subject.Type() {
		t.Errorf("kty is %q, want %q", recoveredKey.Type(), subject.Type())
	}

	read.ProtectedHeader = &header.Header{
		ContentType:         "text/plain",
		Algorithm:           jwa.A128KW(),
		EncryptionAlgorithm: jwa.A128GCM(),
	}

	if _, err := read.Decrypt(key); err == nil {
		t.Error("a rewritten cty was accepted")
	}
}

// TestEncryptedJWKSetUsesTheContentType is the same rule for a JWK Set, which §7
// states in a sentence of its own.
//
// MUST — "A 'cty' (content type) Header Parameter value of 'jwk-set+json' MUST
// be used to indicate that the content of the JWE is a JWK Set, unless the
// application knows that the encrypted content is a JWK Set by another means or
// convention."
//
// This was excluded as not-testable on the ground that this module had no JWE
// type — a reason that stopped being true when the jwe package was written, and
// that nothing was watching to notice. Its sibling above was re-enriched at the
// time and this one was not.
//
// The interop evidence is stronger here than for the single-key case: RFC 7520
// §5.3 encrypts a JWK Set with exactly this cty under PBES2, and
// conformance/rfc7520 already decrypts that vector and reads a JWK Set out of
// it. What is asserted here is the module's own production of the pair, and that
// the cty is integrity protected.
//
// rfc-req: RFC7517-S7-R03
func TestEncryptedJWKSetUsesTheContentType(t *testing.T) {
	subject := jwk.NewKeySet(
		jwk.NewKey(
			bytes.Repeat([]byte{3}, 32),
			jwk.WithID("first"),
			jwk.WithPublicKeyUse(jwk.Signature),
			jwk.WithOperations(jwk.Sign),
		),
		jwk.NewKey(
			bytes.Repeat([]byte{5}, 32),
			jwk.WithID("second"),
			jwk.WithPublicKeyUse(jwk.Signature),
			jwk.WithOperations(jwk.Verify),
		),
	)

	plaintext, err := json.Marshal(subject)
	if err != nil {
		t.Fatalf("cannot encode the JWK Set: %v", err)
	}

	key := bytes.Repeat([]byte{7}, 16)

	message := &jwe.Message{ProtectedHeader: &header.Header{
		ContentType:         "jwk-set+json",
		Algorithm:           jwa.A128KW(),
		EncryptionAlgorithm: jwa.A128GCM(),
	}}

	if err := message.Encrypt(plaintext, key); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	encoded, err := message.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	read, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	if got := read.ProtectedHeader.ContentType; got != "jwk-set+json" {
		t.Errorf("cty is %q, want %q", got, "jwk-set+json")
	}

	if read.ProtectedHeader.ContentType == "jwk+json" {
		t.Error("a JWK Set was labelled as a single JWK")
	}

	recovered, err := read.Decrypt(key)
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	recoveredSet := new(jwk.KeySet)
	if err := json.Unmarshal(recovered, recoveredSet); err != nil {
		t.Fatalf("the plaintext is not a JWK Set: %v", err)
	}

	for _, id := range []string{"first", "second"} {
		if _, err := recoveredSet.Key(jwk.Signature, nil, nil, id); err != nil {
			t.Errorf("the recovered set has no key %q: %v", id, err)
		}
	}

	read.ProtectedHeader = &header.Header{
		ContentType:         "jwk+json",
		Algorithm:           jwa.A128KW(),
		EncryptionAlgorithm: jwa.A128GCM(),
	}

	if _, err := read.Decrypt(key); err == nil {
		t.Error("a rewritten cty was accepted")
	}
}
