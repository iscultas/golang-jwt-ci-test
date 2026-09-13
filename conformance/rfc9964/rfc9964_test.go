package rfc9964_test

import (
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

var parameterSets = map[string]struct {
	parameters    mldsa.Parameters
	publicKeySize int
	signatureSize int
}{
	"ML-DSA-44": {mldsa.MLDSA44(), 1312, 2420},
	"ML-DSA-65": {mldsa.MLDSA65(), 1952, 3309},
	"ML-DSA-87": {mldsa.MLDSA87(), 2592, 4627},
}

func privateJWK(example joseExample) string {
	return fmt.Sprintf(
		`{"kid":%q,"kty":"AKP","alg":%q,"pub":%q,"priv":%q}`,
		example.keyID, example.algorithm, example.publicKey, example.seed,
	)
}

func publicJWK(example joseExample) string {
	return fmt.Sprintf(
		`{"kid":%q,"kty":"AKP","alg":%q,"pub":%q}`, example.keyID, example.algorithm, example.publicKey,
	)
}

func decodeJWK(t *testing.T, document string) *jwk.Key {
	t.Helper()

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(document), key); err != nil {
		t.Fatalf("cannot decode the JWK of appendix A.1: %v", err)
	}

	if key.Material() == nil {
		t.Fatalf("got no key material from %s", document)
	}

	return key
}

func decodeBase64url(t *testing.T, name, value string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("cannot decode %s: %v", name, err)
	}

	return decoded
}

func splitCompactJWS(t *testing.T, serialization string) (signingInput string, signature []byte) {
	t.Helper()

	parts := strings.Split(serialization, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts in the JWS, want 3", len(parts))
	}

	return parts[0] + "." + parts[1], decodeBase64url(t, "the signature", parts[2])
}

func members(t *testing.T, key *jwk.Key) map[string]string {
	t.Helper()

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot encode the key: %v", err)
	}

	decoded := map[string]string{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot read back the key this package produced: %v", err)
	}

	return decoded
}

func expectedMembers(example joseExample, private bool) map[string]string {
	expected := map[string]string{
		"kid": example.keyID,
		"kty": "AKP",
		"alg": example.algorithm,
		"pub": example.publicKey,
	}

	if private {
		expected["priv"] = example.seed
	}

	return expected
}

func publicKeyMaterial(t *testing.T, key *jwk.Key) *mldsa.PublicKey {
	t.Helper()

	publicKey, ok := key.Public().Material().(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("got material %T, want *mldsa.PublicKey", key.Public().Material())
	}

	return publicKey
}

func TestAKPKeyTypeIsSupported(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S8_1_5-R01
			key := new(jwk.Key)
			err := json.Unmarshal([]byte(privateJWK(example)), key)

			if err != nil || key.Material() == nil {
				if _, marshalErr := json.Marshal(key); !errors.Is(marshalErr, jwk.ErrUnsupportedKeyType) {
					t.Errorf(
						"the AKP key type is not implemented, but a key of it encodes with error %v; "+
							"want %v so that an unread key cannot be republished",
						marshalErr, jwk.ErrUnsupportedKeyType,
					)
				}

				return
			}

			if keyType := key.Type(); keyType != jwk.AlgorithmKeyPair {
				t.Errorf("got kty %q, want %q", keyType, jwk.AlgorithmKeyPair)
			}

			if _, ok := key.Material().(*mldsa.PrivateKey); !ok {
				t.Errorf("got material %T, want *mldsa.PrivateKey", key.Material())
			}

			if got, want := members(t, key), expectedMembers(example, true); !maps.Equal(got, want) {
				t.Errorf("got the members %v, want %v", got, want)
			}
		})
	}
}

func TestMLDSAAlgorithmIdentifiers(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S8_1_4-R01a, RFC9964-S8_1_4-R01b, RFC9964-S8_1_4-R01c
			algorithm, ok := jwa.ByName(example.algorithm)
			if !ok {
				encodedHeader := base64.RawURLEncoding.EncodeToString(
					fmt.Appendf(nil, `{"alg":%q}`, example.algorithm),
				)

				err := new(header.Header).Unmarshal(encodedHeader)
				if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
					t.Errorf(
						"%s is not registered, but a header naming it gives error %v; want %v",
						example.algorithm, err, jwa.ErrUnsupportedAlgorithm,
					)
				}

				return
			}

			if algorithm.String() != example.algorithm {
				t.Errorf("got %s, want %s", algorithm, example.algorithm)
			}

			signer, isSigner := algorithm.(jwa.Signer)
			verifier, isVerifier := algorithm.(jwa.Verifier)

			if !isSigner || !isVerifier {
				t.Fatalf("%s is registered but does not sign and verify", example.algorithm)
			}

			key := decodeJWK(t, privateJWK(example))
			token := []byte("a token signed under " + example.algorithm)

			signature, err := signer.Sign(token, key.Material())
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			if err := verifier.Verify(token, signature, publicKeyMaterial(t, key)); err != nil {
				t.Errorf("cannot verify a signature this package made: %v", err)
			}

			for _, other := range joseExamples {
				if other.algorithm == example.algorithm {
					continue
				}

				otherAlgorithm, ok := jwa.ByName(other.algorithm)
				if !ok {
					continue
				}

				if _, err := otherAlgorithm.(jwa.Signer).Sign(token, key.Material()); !errors.Is(err, jwa.ErrInvalidKeyType) {
					t.Errorf(
						"signing a %s key under %s: got error %v, want %v",
						example.algorithm, other.algorithm, err, jwa.ErrInvalidKeyType,
					)
				}
			}
		})
	}
}

func TestMLDSAIdentifierIsUsableEndToEnd(t *testing.T) {
	// rfc-req: RFC9964-S8_1_4-R01a
	algorithm, ok := jwa.ByName("ML-DSA-44")
	if !ok {
		t.Skip(`"ML-DSA-44" is not registered by this package (Optional per RFC 9964 Section 8.1.4.1)`)
	}

	signer, isSigner := algorithm.(jwa.Signer)
	if !isSigner {
		t.Fatal(`"ML-DSA-44" is registered but does not implement jwa.Signer`)
	}

	key := decodeJWK(t, privateJWK(joseExamples[0]))

	token, err := jwt.NewToken(jwt.WithIssuer("rfc9964-conformance"), jwt.WithSignature(signer, key))
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	encodedProtectedHeader, _, _ := strings.Cut(serialized, ".")

	protectedHeader := new(header.Header)
	if err := protectedHeader.Unmarshal(encodedProtectedHeader); err != nil {
		t.Fatalf("cannot parse the protected header this package produced: %v", err)
	}

	if got := protectedHeader.Algorithm; got != algorithm {
		t.Errorf("got alg %v in the protected header, want ML-DSA-44", got)
	}

	parsed, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot parse the token this package produced: %v", err)
	}

	if err := parsed.Verify(t.Context(), jwk.NewKeySet(key.Public()), jwt.DefaultVerificationConfig); err != nil {
		t.Errorf(
			"verifying an ML-DSA-44 token under the default config: %v; a registered identifier that "+
				"the default allowlist rejects cannot be negotiated with",
			err,
		)
	}
}

func TestAKPKeyRequiresAlgorithm(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S3-R01
			key := decodeJWK(t, privateJWK(example))

			if algorithm := key.Algorithm(); algorithm == nil || algorithm.String() != example.algorithm {
				t.Errorf("got alg %v, want %s", algorithm, example.algorithm)
			}

			if algorithm := members(t, jwk.NewKey(key.Material()))["alg"]; algorithm != example.algorithm {
				t.Errorf("got alg %q from a key built from material alone, want %s", algorithm, example.algorithm)
			}

			withoutAlgorithm := fmt.Sprintf(`{"kty":"AKP","pub":%q}`, example.publicKey)

			parsed := new(jwk.Key)
			if err := json.Unmarshal([]byte(withoutAlgorithm), parsed); err == nil {
				t.Error("got no error for an AKP key with no alg member, want a missing parameter error")
			} else if _, ok := errors.AsType[*jwk.MissingRequiredParameterError](err); !ok {
				t.Errorf("got error %v, want a missing parameter error", err)
			}

			if parsed.Material() != nil {
				t.Errorf("got material %v from a key with no alg member, want none", parsed.Material())
			}
		})
	}
}

func TestAKPKeyRequiresPublicKey(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S3-R02
			for _, testCase := range []struct {
				name     string
				document string
			}{
				{"Private", privateJWK(example)},
				{"Public", publicJWK(example)},
			} {
				if publicKey := members(t, decodeJWK(t, testCase.document))["pub"]; publicKey != example.publicKey {
					t.Errorf("%s: got pub %q, want the value of the figure", testCase.name, publicKey)
				}
			}

			withoutPublicKey := fmt.Sprintf(`{"kty":"AKP","alg":%q,"priv":%q}`, example.algorithm, example.seed)

			parsed := new(jwk.Key)
			if err := json.Unmarshal([]byte(withoutPublicKey), parsed); err == nil {
				t.Error("got no error for an AKP key with no pub member, want a missing parameter error")
			} else if _, ok := errors.AsType[*jwk.MissingRequiredParameterError](err); !ok {
				t.Errorf("got error %v, want a missing parameter error", err)
			}

			if parsed.Material() != nil {
				t.Errorf("got material %v from a key with no pub member, want none", parsed.Material())
			}
		})
	}
}

func TestPrivateParameterIsAbsentFromPublicKeys(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S3-R03
			key := decodeJWK(t, privateJWK(example))

			if !key.IsPrivate() {
				t.Error("got a public key from a JWK with a priv member, want a private one")
			}

			for _, testCase := range []struct {
				name string
				key  *jwk.Key
			}{
				{"Public", key.Public()},
				{"KeySetPublic", jwk.NewKeySet(key).Public().Keys[0]},
			} {
				got := members(t, testCase.key)

				if value, ok := got["priv"]; ok {
					t.Errorf("%s: got a priv member %q in a public key, want none", testCase.name, value)
				}

				if want := expectedMembers(example, false); !maps.Equal(got, want) {
					t.Errorf("%s: got the members %v, want %v", testCase.name, got, want)
				}
			}
		})
	}
}

func TestAKPParametersAreBase64url(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S3-R04
			key := decodeJWK(t, privateJWK(example))

			privateKey, ok := key.Material().(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("got material %T, want *mldsa.PrivateKey", key.Material())
			}

			if got := decodeBase64url(t, "pub", example.publicKey); string(got) != string(privateKey.PublicKey().Bytes()) {
				t.Error("got pub octets that are not the public key of the parsed key")
			}

			if got := decodeBase64url(t, "priv", example.seed); string(got) != string(privateKey.Bytes()) {
				t.Error("got priv octets that are not the seed of the parsed key")
			}

			for name, value := range map[string]string{"pub": example.publicKey, "priv": example.seed} {
				if strings.ContainsAny(value, "+/=") {
					t.Errorf("got %s with a character outside the base64url alphabet: %q", name, value)
				}
			}

			malformed := fmt.Sprintf(`{"kty":"AKP","alg":%q,"pub":"+"}`, example.algorithm)

			parsed := new(jwk.Key)
			if err := json.Unmarshal([]byte(malformed), parsed); err == nil {
				t.Error("got no error for a pub member that is not base64url, want one")
			}

			if parsed.Material() != nil {
				t.Errorf("got material %v from a malformed pub member, want none", parsed.Material())
			}
		})
	}
}

func TestPrivateParameterIsTheSeed(t *testing.T) {
	expandedPrivateKeySizes := map[string]int{"ML-DSA-44": 2560, "ML-DSA-65": 4032, "ML-DSA-87": 4896}

	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S4-R01
			seed := decodeBase64url(t, "priv", example.seed)

			if len(seed) != mldsa.PrivateKeySize {
				t.Errorf("got a seed of %d octets, want %d", len(seed), mldsa.PrivateKeySize)
			}

			key := decodeJWK(t, privateJWK(example))

			privateKey, ok := key.Material().(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("got material %T, want *mldsa.PrivateKey", key.Material())
			}

			if string(privateKey.Bytes()) != string(seed) {
				t.Error("got a priv value that is not the seed the JWK carried")
			}

			expanded := base64.RawURLEncoding.EncodeToString(make([]byte, expandedPrivateKeySizes[example.algorithm]))

			document := fmt.Sprintf(
				`{"kty":"AKP","alg":%q,"pub":%q,"priv":%q}`, example.algorithm, example.publicKey, expanded,
			)

			parsed := new(jwk.Key)
			if err := json.Unmarshal([]byte(document), parsed); !errors.Is(err, jwk.ErrMalformedKey) {
				t.Errorf(
					"a priv member of %d octets, the expanded private key width: got error %v, want %v",
					expandedPrivateKeySizes[example.algorithm], err, jwk.ErrMalformedKey,
				)
			}
		})
	}
}

func TestSignatureUsesTheEmptyContext(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S5-R01
			algorithm, ok := jwa.ByName(example.algorithm)
			if !ok {
				t.Skipf("%s is not registered by this package (Optional per RFC 9964 Section 8.1.4)", example.algorithm)
			}

			key := decodeJWK(t, publicJWK(example))
			publicKey := publicKeyMaterial(t, key)
			signingInput, signature := splitCompactJWS(t, example.signature)

			if err := algorithm.(jwa.Verifier).Verify([]byte(signingInput), signature, publicKey); err != nil {
				t.Errorf("cannot verify the JWS of appendix A.1: %v", err)
			}

			if err := mldsa.Verify(
				publicKey, []byte(signingInput), signature, &mldsa.Options{Context: "jose"},
			); err == nil {
				t.Error("the appendix signature verifies under a non-empty ctx as well; the vector cannot show the empty ctx")
			}

			ourSignature, err := algorithm.(jwa.Signer).Sign(
				[]byte(signingInput), decodeJWK(t, privateJWK(example)).Material(),
			)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			if err := mldsa.Verify(publicKey, []byte(signingInput), ourSignature, nil); err != nil {
				t.Errorf("a signature this package made does not verify under the empty ctx: %v", err)
			}

			if err := mldsa.Verify(
				publicKey, []byte(signingInput), ourSignature, &mldsa.Options{Context: "jose"},
			); err == nil {
				t.Error("a signature this package made verifies under a non-empty ctx; it was not made with the empty one")
			}
		})
	}
}

func TestPublicKeyParameterWidths(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S5-R02
			size := parameterSets[example.algorithm].publicKeySize

			publicKey := decodeBase64url(t, "pub", example.publicKey)
			if len(publicKey) != size {
				t.Errorf("got a pub of %d octets, want %d", len(publicKey), size)
			}

			if _, err := mldsa.NewPublicKey(parameterSets[example.algorithm].parameters, publicKey); err != nil {
				t.Errorf("the pub of the figure is not a public key of its own parameter set: %v", err)
			}

			for _, other := range joseExamples {
				if other.algorithm == example.algorithm {
					continue
				}

				document := fmt.Sprintf(`{"kty":"AKP","alg":%q,"pub":%q}`, other.algorithm, example.publicKey)

				parsed := new(jwk.Key)
				if err := json.Unmarshal([]byte(document), parsed); !errors.Is(err, jwk.ErrMalformedKey) {
					t.Errorf(
						"a %s pub under alg %s: got error %v, want %v",
						example.algorithm, other.algorithm, err, jwk.ErrMalformedKey,
					)
				}
			}
		})
	}
}

func TestSignatureEncoding(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S5-R03
			algorithm, ok := jwa.ByName(example.algorithm)
			if !ok {
				t.Skipf("%s is not registered by this package (Optional per RFC 9964 Section 8.1.4)", example.algorithm)
			}

			size := parameterSets[example.algorithm].signatureSize

			signingInput, signature := splitCompactJWS(t, example.signature)
			if len(signature) != size {
				t.Errorf("got a signature of %d octets in the JWS of appendix A.1, want %d", len(signature), size)
			}

			key := decodeJWK(t, privateJWK(example))

			ourSignature, err := algorithm.(jwa.Signer).Sign([]byte(signingInput), key.Material())
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			if len(ourSignature) != size {
				t.Errorf("got a signature of %d octets, want %d", len(ourSignature), size)
			}

			encoded := base64.RawURLEncoding.EncodeToString(ourSignature)
			if len(encoded) <= size {
				t.Errorf("got an encoded signature of %d characters, want more than the %d octets", len(encoded), size)
			}

			err = algorithm.(jwa.Verifier).Verify([]byte(signingInput), ourSignature[:size-1], publicKeyMaterial(t, key))
			if !errors.Is(err, jwa.ErrMalformedSignature) {
				t.Errorf("got error %v for a short signature, want %v", err, jwa.ErrMalformedSignature)
			}
		})
	}
}

func TestAKPThumbprint(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S6-R01
			key := decodeJWK(t, privateJWK(example))

			id, err := key.ThumbprintID(crypto.SHA256)
			if err != nil {
				t.Fatalf("cannot compute the thumbprint: %v", err)
			}

			if id != example.keyID {
				t.Errorf("got the thumbprint %s, want the kid %s of the figure", id, example.keyID)
			}

			publicID, err := key.Public().ThumbprintID(crypto.SHA256)
			if err != nil {
				t.Fatalf("cannot compute the thumbprint of the public half: %v", err)
			}

			if publicID != example.keyID {
				t.Errorf("got the thumbprint %s for the public half, want %s", publicID, example.keyID)
			}
		})
	}
}

func TestEveryAlgorithmRelatedParameterIsValidated(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S7_3-R01
			size := parameterSets[example.algorithm].publicKeySize

			mismatchedSeed := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))

			for name, document := range map[string]string{
				"ShortPub": fmt.Sprintf(
					`{"kty":"AKP","alg":%q,"pub":%q}`,
					example.algorithm, base64.RawURLEncoding.EncodeToString(make([]byte, size-1)),
				),
				"LongPub": fmt.Sprintf(
					`{"kty":"AKP","alg":%q,"pub":%q}`,
					example.algorithm, base64.RawURLEncoding.EncodeToString(make([]byte, size+1)),
				),
				"ShortPriv": fmt.Sprintf(
					`{"kty":"AKP","alg":%q,"pub":%q,"priv":"AAAA"}`, example.algorithm, example.publicKey,
				),
				"MismatchedPriv": fmt.Sprintf(
					`{"kty":"AKP","alg":%q,"pub":%q,"priv":%q}`, example.algorithm, example.publicKey, mismatchedSeed,
				),
			} {
				parsed := new(jwk.Key)

				if err := json.Unmarshal([]byte(document), parsed); !errors.Is(err, jwk.ErrMalformedKey) {
					t.Errorf("%s: got error %v, want %v", name, err, jwk.ErrMalformedKey)
				}

				if parsed.Material() != nil {
					t.Errorf("%s: got material %v, want none: an unvalidated key must not reach jwa", name, parsed.Material())
				}
			}
		})
	}
}

func TestSeedLengthCheck(t *testing.T) {
	for _, example := range joseExamples {
		t.Run(example.algorithm, func(t *testing.T) {
			// rfc-req: RFC9964-S7_3-R02
			// 31 and 33 are the two neighbours of the width, 64 is the length that
			// an implementation carrying an Ed25519-shaped private key would write.
			// A "priv" member that is the empty string is not here: this package
			// reads an empty member as an absent one for each key type, thus such a
			// document is a public key and not a malformed private one.
			for _, length := range []int{31, 33, 64} {
				seed := base64.RawURLEncoding.EncodeToString(make([]byte, length))

				document := fmt.Sprintf(
					`{"kty":"AKP","alg":%q,"pub":%q,"priv":%q}`, example.algorithm, example.publicKey, seed,
				)

				parsed := new(jwk.Key)

				if err := json.Unmarshal([]byte(document), parsed); !errors.Is(err, jwk.ErrMalformedKey) {
					t.Errorf("a seed of %d octets: got error %v, want %v", length, err, jwk.ErrMalformedKey)
				}

				if parsed.Material() != nil {
					t.Errorf("a seed of %d octets: got material %v, want none", length, parsed.Material())
				}
			}

			if key := decodeJWK(t, privateJWK(example)); !key.IsPrivate() {
				t.Error("got a public key from a JWK with a 32-octet seed, want a private one")
			}
		})
	}
}
