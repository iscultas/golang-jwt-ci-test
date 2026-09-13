package rfc7519_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
)

func encryptionKey(t *testing.T, size int) *jwk.Key {
	t.Helper()

	return jwk.NewKey(
		bytes.Repeat([]byte{7}, size),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)
}

func signingKeyForNesting(t *testing.T) *jwk.Key {
	t.Helper()

	return jwk.NewKey(
		bytes.Repeat([]byte{1}, 32),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
	)
}

func nestedToken(t *testing.T) (*jwt.Token, *jwk.Key, *jwk.Key) {
	t.Helper()

	signing, encryption := signingKeyForNesting(t), encryptionKey(t, 16)

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithSignature(jwa.HS256(), signing),
		jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), encryption),
	)
	if err != nil {
		t.Fatalf("cannot build a nested token: %v", err)
	}

	return token, signing, encryption
}

// TestNestedJWTSetsContentTypeJWT checks the outer "cty" of a Nested JWT.
//
// MUST — "In the case that nested signing or encryption is employed, this Header
// Parameter MUST be present; in this case, the value MUST be 'JWT', to indicate
// that a Nested JWT is carried in this JWT."
//
// Both directions. Writing it is half the requirement; the other half is that a
// recipient reads it, so a decrypted payload whose cty says "JWT" is parsed as a
// token rather than as a claims set. A token with no cty decrypts to claims,
// which is the negative case showing the parameter is read rather than assumed.
//
// rfc-req: RFC7519-S5_2-R02
func TestNestedJWTSetsContentTypeJWT(t *testing.T) {
	token, signing, encryption := nestedToken(t)

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	protectedHeader := decodeProtectedHeader(t, encoded)

	var contentType string
	if err := json.Unmarshal(protectedHeader["cty"], &contentType); err != nil {
		t.Fatalf("no cty on the outer header: %v", err)
	}

	if contentType != "JWT" {
		t.Errorf("cty is %q, want %q", contentType, "JWT")
	}

	read, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	config := jwt.NewDecryptionConfig(jwt.WithRequiredNestedToken())
	if err := read.Decrypt(t.Context(), jwk.NewKeySet(signing, encryption), config); err != nil {
		t.Fatalf("cannot decrypt a nested token: %v", err)
	}

	if read.Issuer() != "joe" {
		t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
	}

	bare, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), encryption),
	)
	if err != nil {
		t.Fatalf("cannot build a bare encrypted token: %v", err)
	}

	encodedBare, err := bare.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	readBare, err := jwt.Unmarshal(encodedBare)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	if err := readBare.Decrypt(t.Context(), jwk.NewKeySet(encryption), config); err == nil {
		t.Error("a token with no cty was accepted where a Nested JWT was required")
	}
}

// TestNestedContentTypeIsUppercase checks the spelling.
//
// SHOULD — "While media type names are not case sensitive, it is RECOMMENDED
// that 'JWT' always be spelled using uppercase characters for compatibility with
// legacy implementations."
//
// should_policy: strict. Compared byte for byte rather than case-insensitively —
// a case-insensitive comparison would pass on exactly the value the
// recommendation exists to prevent.
//
// rfc-req: RFC7519-S5_2-R03
func TestNestedContentTypeIsUppercase(t *testing.T) {
	if jwt.NestedContentType != "JWT" {
		t.Errorf("NestedContentType is %q, want %q", jwt.NestedContentType, "JWT")
	}

	token, _, _ := nestedToken(t)

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	if raw := decodeProtectedHeader(t, encoded)["cty"]; string(raw) != `"JWT"` {
		t.Errorf("cty is %s, want \"JWT\" exactly", raw)
	}
}

// TestEncryptedJWTFollowsTheJWESteps checks that the JWE creation procedure is
// deferred to rather than reimplemented.
//
// MUST — "Else, if the JWT is a JWE, create a JWE using the Message as the
// plaintext for the JWE; all steps specified in [JWE] for creating a JWE MUST be
// followed."
//
// The assertion that matters is the deferral: jwt.Token.encrypt builds a
// jwe.Message and calls its Encrypt, so a second implementation of RFC 7516's
// steps does not exist to drift. Asserted by checking that the token this module
// emits is one jwe.Unmarshal accepts and jwe.Message.Decrypt reads. The steps
// themselves are conformance/rfc7516's to assert.
//
// rfc-req: RFC7519-S7_1-R03
func TestEncryptedJWTFollowsTheJWESteps(t *testing.T) {
	key := encryptionKey(t, 16)

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), key),
	)
	if err != nil {
		t.Fatalf("cannot build: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	message, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("the token is not a well-formed JWE: %v", err)
	}

	plaintext, err := message.Decrypt(key.Material())
	if err != nil {
		t.Fatalf("cannot decrypt through the jwe package: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		t.Fatalf("the plaintext is not a claims set: %v", err)
	}

	if claims["iss"] != "joe" {
		t.Errorf("iss is %v, want joe", claims["iss"])
	}

	read, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	if err := read.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig); err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if read.Issuer() != "joe" {
		t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
	}
}

// TestEncryptedJWTsAreSupported records that this module exercises the option.
//
// MAY — "Support for encrypted JWTs is OPTIONAL."
//
// capability: encrypted-jwt — present. An implementation providing none would be
// equally conformant; the interop obligation is that one lacking the capability
// must refuse an encrypted JWT rather than mis-parse it, which the segment-count
// dispatch provides (RFC7516-S9-R01).
//
// rfc-req: RFC7519-S8-R04
func TestEncryptedJWTsAreSupported(t *testing.T) {
	key := encryptionKey(t, 16)

	token, err := jwt.NewToken(jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), key))
	if err != nil {
		t.Fatalf("cannot build: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	if got := strings.Count(encoded, "."); got != 4 {
		t.Errorf("an encrypted JWT has %d full stops, want 4", got)
	}
}

func rsa15Token(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()

	encryption := jwa.A128CBCHS256()

	cek, err := jwa.GenerateContentEncryptionKey(encryption)
	if err != nil {
		t.Fatalf("cannot make a CEK: %v", err)
	}

	initializationVector := make([]byte, encryption.IVSize())
	if _, err := rand.Read(initializationVector); err != nil {
		t.Fatalf("cannot make an IV: %v", err)
	}

	protectedHeader := &header.Header{Algorithm: jwa.RSA15(), EncryptionAlgorithm: encryption}

	encodedProtectedHeader, err := protectedHeader.Marshal()
	if err != nil {
		t.Fatalf("cannot encode the protected header: %v", err)
	}

	ciphertext, tag, err := encryption.Encrypt(
		[]byte(`{"iss":"joe"}`), cek, initializationVector, []byte(encodedProtectedHeader),
	)
	if err != nil {
		t.Fatalf("cannot encrypt the content: %v", err)
	}

	//nolint:staticcheck // The deprecation is the point: this is the half jwa declines to offer, and a consumer-side conformance test needs a producer from somewhere.
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, key, cek)
	if err != nil {
		t.Fatalf("cannot wrap the CEK: %v", err)
	}

	message := &jwe.Message{
		ProtectedHeader:      protectedHeader,
		Recipients:           []*jwe.Recipient{{EncryptedKey: encryptedKey}},
		InitializationVector: initializationVector,
		Ciphertext:           ciphertext,
		AuthenticationTag:    tag,
	}

	compact, err := message.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	return compact
}

// TestRequiredEncryptionAlgorithms checks §8's mandatory set.
//
// MUST — "If an implementation provides encryption capabilities, of the
// encryption algorithms specified in [JWA], only RSAES-PKCS1-v1_5 with 2048-bit
// keys ('RSA1_5'), AES Key Wrap with 128- and 256-bit keys ('A128KW' and
// 'A256KW'), and the composite authenticated encryption algorithm using AES-CBC
// and HMAC SHA-2 ('A128CBC-HS256' and 'A256CBC-HS512') MUST be implemented by
// conforming implementations."
//
// All five are implemented and all five are asserted. Four round-trip; RSA1_5 is
// decrypted from a vector assembled here, since this module implements the
// consuming half of it alone.
//
// This requirement was vacuous while the module was signature-only — its
// condition was never met — and the JWE work made it live. It was then recorded
// as covered with its scope narrowed to four, on the reading that RFC 8725 §3.2,
// a BCP formally updating this document, governs over §8's unqualified MUST.
// That reading was an interpretation rather than a quotation, and the IR
// recorded a reader who weighed the Standards Track MUST higher as having a
// case. Implementing the decryption half settles it: §8 is met on its own terms.
//
// What survives of RFC 8725 §3.2's advice is the shape of the implementation,
// not a gap in it. The algorithm decrypts and never encrypts, so no token this
// module writes carries that padding, and jwt.DefaultDecryptionConfig does not
// accept it, so no caller consumes one without asking. Both are asserted below.
//
// rfc-req: RFC7519-S8-R05
func TestRequiredEncryptionAlgorithms(t *testing.T) {
	for _, pairing := range []struct {
		algorithm  jwa.KeyEncrypter
		encryption jwa.ContentEncrypter
		size       int
	}{
		{jwa.A128KW(), jwa.A128CBCHS256(), 16},
		{jwa.A256KW(), jwa.A128CBCHS256(), 32},
		{jwa.A128KW(), jwa.A256CBCHS512(), 16},
		{jwa.A256KW(), jwa.A256CBCHS512(), 32},
	} {
		t.Run(pairing.algorithm.String()+"+"+pairing.encryption.String(), func(t *testing.T) {
			roundTripEncrypted(t, pairing.algorithm, pairing.encryption, encryptionKey(t, pairing.size))
		})
	}

	t.Run("RSA1_5", func(t *testing.T) {
		material, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("cannot generate a key: %v", err)
		}

		key := jwk.NewKey(
			material,
			jwk.WithPublicKeyUse(jwk.Encryption),
			jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
		)

		encoded := rsa15Token(t, &material.PublicKey)

		read, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.NewDecryptionConfig(
			jwt.WithKeyManagementAlgorithms(jwa.RSA15()),
		)); err != nil {
			t.Fatalf("cannot decrypt: %v", err)
		}

		if read.Issuer() != "joe" {
			t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
		}

		refused, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := refused.Decrypt(
			t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig,
		); !errors.Is(err, jwt.ErrForbiddenKeyManagement) {
			t.Errorf("got %v, want ErrForbiddenKeyManagement", err)
		}

		if _, ok := any(jwa.RSA15()).(jwa.KeyEncrypter); ok {
			t.Error("RSA1_5 can encrypt a key; this module must not produce that padding")
		}
	})
}

// TestRecommendedEncryptionAlgorithms checks §8's recommended set.
//
// SHOULD — "It is RECOMMENDED that implementations also support using Elliptic
// Curve Diffie-Hellman Ephemeral Static (ECDH-ES) to agree upon a key used to
// wrap the Content Encryption Key ('ECDH-ES+A128KW' and 'ECDH-ES+A256KW') and AES
// in Galois/Counter Mode (GCM) with 128- and 256-bit keys ('A128GCM' and
// 'A256GCM')."
//
// should_policy: strict — asserted, not logged. All four are implemented, along
// with the A192 variants the sentence does not name.
//
// rfc-req: RFC7519-S8-R06
func TestRecommendedEncryptionAlgorithms(t *testing.T) {
	agreement, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	key := jwk.NewKey(
		agreement,
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.DeriveKey),
	)

	for _, algorithm := range []jwa.KeyEncrypter{jwa.ECDHESA128KW(), jwa.ECDHESA256KW()} {
		for _, encryption := range []jwa.ContentEncrypter{jwa.A128GCM(), jwa.A256GCM()} {
			t.Run(algorithm.String()+"+"+encryption.String(), func(t *testing.T) {
				roundTripEncrypted(t, algorithm, encryption, key)
			})
		}
	}
}

// TestOptionalEncryptionAlgorithms checks the option, and the obligation behind
// it.
//
// MAY — "Support for other algorithms and key sizes is OPTIONAL."
//
// capability: optional-jwe-algorithms. Each optional identifier either resolves
// to a working algorithm or is reported unsupported, and both are conformant.
// What must hold either way is that an unresolved name produces
// jwa.ErrUnsupportedAlgorithm rather than a silent fallback: a recipient quietly
// substituting an algorithm it did understand for one it did not would be reading
// a token that says something else. That is the interop obligation and it is
// asserted rather than skipped.
//
// rfc-req: RFC7519-S8-R07
func TestOptionalEncryptionAlgorithms(t *testing.T) {
	for _, name := range []string{
		"A192KW", "A128GCMKW", "A192GCMKW", "A256GCMKW",
		"PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
		"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A192KW", "dir",
		"A192CBC-HS384", "A192GCM",
	} {
		if _, ok := jwa.ByName(name); !ok {
			t.Logf("%s is not implemented, which is conformant", name)
		}
	}

	for _, unregistered := range []string{"A512KW", "NOTAREALALG", ""} {
		if _, ok := jwa.ByName(unregistered); ok {
			t.Errorf("%q resolved", unregistered)
		}
	}
}

// TestNestedJWTsAreSupported records that this module exercises the option.
//
// MAY — "Support for Nested JWTs is OPTIONAL."
//
// capability: nested-jwt — present. The interop half: an implementation without
// the capability must not treat the decrypted JWS as a claims set, and the outer
// cty is what prevents that (RFC7519-S5_2-R02).
//
// rfc-req: RFC7519-S8-R08
func TestNestedJWTsAreSupported(t *testing.T) {
	token, signing, encryption := nestedToken(t)

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	read, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	config := jwt.NewDecryptionConfig(jwt.WithRequiredNestedToken())
	if err := read.Decrypt(t.Context(), jwk.NewKeySet(signing, encryption), config); err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if read.Issuer() != "joe" {
		t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
	}
}

func roundTripEncrypted(t *testing.T, algorithm jwa.KeyEncrypter, encryption jwa.ContentEncrypter, key *jwk.Key) {
	t.Helper()

	encrypting := key
	if public := key.Public(); public != nil {
		encrypting = public
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithEncryption(algorithm, encryption, encrypting),
	)
	if err != nil {
		t.Fatalf("cannot build: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	read, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read: %v", err)
	}

	if err := read.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig); err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if read.Issuer() != "joe" {
		t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
	}
}

func decodeProtectedHeader(t *testing.T, encoded string) map[string]jsontext.Value {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(strings.Split(encoded, ".")[0])
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}

	var members map[string]jsontext.Value
	if err := json.Unmarshal(decoded, &members); err != nil {
		t.Fatalf("the protected header is not an object: %v", err)
	}

	return members
}

func nestedJWSOf(t *testing.T, encoded string, key *jwk.Key) []byte {
	t.Helper()

	message, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse the JWE: %v", err)
	}

	innerJWS, err := message.Decrypt(key.Material())
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	return innerJWS
}

// TestNestedContentTypeIsReadCaseInsensitively covers the reading side of §5.2's
// spelling recommendation, which §7.3 governs.
//
// SHOULD — "While media type names are not case sensitive, it is RECOMMENDED
// that 'JWT' always be spelled using uppercase characters for compatibility with
// legacy implementations."
//
// The sentence states the fact and the preference in that order, and they cut in
// opposite directions: a producer writes "JWT", a recipient must accept whatever
// spelling names the same media type. §7.3 says so directly — "only the 'typ'
// and 'cty' member values do not use these comparison rules" — the rules in
// question being the case-sensitive ones that govern every other string.
//
// Asserted with WithRequiredNestedToken, so a spelling not recognised fails
// loudly: an unrecognised cty takes the claims-set branch, which that option
// refuses outright.
//
// rfc-req: RFC7519-S5_2-R03, RFC7519-S7_3-R01
func TestNestedContentTypeIsReadCaseInsensitively(t *testing.T) {
	token, signing, encryption := nestedToken(t)

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	innerJWS := nestedJWSOf(t, encoded, encryption)
	keySet := jwk.NewKeySet(signing, encryption)
	config := jwt.NewDecryptionConfig(jwt.WithRequiredNestedToken())

	for _, contentType := range []string{"JWT", "jwt", "Jwt", "jWt"} {
		t.Run(contentType, func(t *testing.T) {
			message := &jwe.Message{ProtectedHeader: &header.Header{
				Type:                "JWT",
				ContentType:         contentType,
				Algorithm:           jwa.A128KW(),
				EncryptionAlgorithm: jwa.A128GCM(),
			}}

			if err := message.Encrypt(innerJWS, encryption.Material()); err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			serialized, err := message.Marshal()
			if err != nil {
				t.Fatalf("cannot serialize: %v", err)
			}

			read, err := jwt.Unmarshal(serialized)
			if err != nil {
				t.Fatalf("cannot parse: %v", err)
			}

			if err := read.Decrypt(t.Context(), keySet, config); err != nil {
				t.Fatalf("a Nested JWT whose cty is %q was refused: %v", contentType, err)
			}

			if read.Issuer() != "joe" {
				t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
			}
		})
	}

	if got := protectedHeaderOf(t, encoded).ContentType; got != "JWT" {
		t.Errorf(`this module wrote cty %q, want "JWT"`, got)
	}
}
