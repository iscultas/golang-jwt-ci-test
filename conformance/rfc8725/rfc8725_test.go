package rfc8725_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"math/big"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

func generateES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate ES256 key: %v", err)
	}

	return privateKey
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

func TestVerificationHonorsCallerConfiguredAlgorithmAllowlist(t *testing.T) {
	// rfc-req: RFC8725-S3_1-R01a, RFC8725-S3_1-R01b
	es256Key := generateES256Key(t)
	jwkKey := jwk.NewKey(es256Key)
	keySet := jwk.NewKeySet(jwk.NewKey(&es256Key.PublicKey))

	es256Token, err := jwt.NewToken(jwt.WithSignature(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatalf("cannot build ES256 token: %v", err)
	}
	es256Serialized, err := es256Token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize ES256 token: %v", err)
	}

	hs256Token, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("shared secret"))))
	if err != nil {
		t.Fatalf("cannot build HS256 token: %v", err)
	}
	hs256Serialized, err := hs256Token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize HS256 token: %v", err)
	}

	config := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.ES256()))

	t.Run("AllowedAlgorithmVerifies", func(t *testing.T) {
		parsed, err := jwt.Unmarshal(es256Serialized)
		if err != nil {
			t.Fatalf("cannot parse token: %v", err)
		}

		if err := parsed.Verify(t.Context(), keySet, config); err != nil {
			t.Errorf(
				"a caller-configured allowlist naming ES256 must accept an ES256-signed token: %v", err,
			)
		}
	})

	t.Run("ExcludedAlgorithmIsForbidden", func(t *testing.T) {
		parsed, err := jwt.Unmarshal(hs256Serialized)
		if err != nil {
			t.Fatalf("cannot parse token: %v", err)
		}

		err = parsed.Verify(t.Context(), keySet, config)
		if !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
			t.Errorf("verifying an HS256 token against an ES256-only allowlist: got %v, want %v", err, jwt.ErrForbiddenAlgorithm)
		}
	})
}

func TestKeyConfusionAttackFailsClosed(t *testing.T) {
	// rfc-req: RFC8725-S3_1-R02
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key: %v", err)
	}

	rsaPublicJWK := jwk.NewKey(&rsaPrivateKey.PublicKey)
	keySet := jwk.NewKeySet(rsaPublicJWK)

	attackerChosenSecret := jwk.NewKey(secret("whatever an attacker chooses"))

	attackToken, err := jwt.NewToken(
		jwt.WithIssuer("attacker-controlled"),
		jwt.WithSignature(jwa.HS256(), attackerChosenSecret),
	)
	if err != nil {
		t.Fatalf("cannot build attack token: %v", err)
	}

	serialized, err := attackToken.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize attack token: %v", err)
	}

	parsed, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot parse attack token: %v", err)
	}

	verifyErr := parsed.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig)
	if !errors.Is(verifyErr, jwt.ErrUnverified) {
		t.Fatalf(
			"RS256-to-HS256 key confusion attack (RFC 8725 Section 2.1): got %v, want an error wrapping %v",
			verifyErr, jwt.ErrUnverified,
		)
	}
	if !errors.Is(verifyErr, jwa.ErrInvalidKeyType) {
		t.Errorf(
			"got %v; expected the failure to specifically be a key-type mismatch (jwa.ErrInvalidKeyType), "+
				"confirming the RSA key material was never coerced into an HMAC secret",
			verifyErr,
		)
	}
}

func TestKeySelectionEnforcesSingleAlgorithmBinding(t *testing.T) {
	// rfc-req: RFC8725-S3_1-R03
	key := jwk.NewKey(secret("shared secret"), jwk.WithAlgorithm(jwa.HS256()))
	keySet := jwk.NewKeySet(key)

	if selected, err := keySet.Key("", nil, jwa.RS256(), ""); !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Fatalf(
			"selecting an HS256-bound key for RS256: got key %v, error %v, want %v",
			selected, err, jwk.ErrNoSuitableKey,
		)
	}

	selected, err := keySet.Key("", nil, jwa.HS256(), "")
	if err != nil {
		t.Fatalf("selecting the key for its own bound algorithm: %v", err)
	}
	if selected != key {
		t.Errorf("got key %v, want %v", selected, key)
	}
}

func TestNoneAlgorithmRequiresExplicitOptIn(t *testing.T) {
	// rfc-req: RFC8725-S3_2-R04, RFC8725-S3_2-R05
	t.Run("NotGeneratedImplicitly", func(t *testing.T) {
		token, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("secret"))))
		if err != nil {
			t.Fatalf("cannot build token: %v", err)
		}
		serialized, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize token: %v", err)
		}
		if got := protectedHeaderOf(t, serialized).Algorithm; got != jwa.HS256() {
			t.Errorf("signing with HS256 produced alg %v, want HS256 (never an implicit none)", got)
		}

		noneToken, err := jwt.NewToken(jwt.WithSignature(jwa.None(), nil))
		if err != nil {
			t.Fatalf("cannot build explicit none token: %v", err)
		}
		noneSerialized, err := noneToken.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize explicit none token: %v", err)
		}
		if got := protectedHeaderOf(t, noneSerialized).Algorithm; got != jwa.None() {
			t.Errorf("explicitly requesting jwa.None() produced alg %v, want none", got)
		}
	})

	t.Run("NotConsumedByDefault", func(t *testing.T) {
		noneToken, err := jwt.NewToken(jwt.WithSignature(jwa.None(), nil))
		if err != nil {
			t.Fatalf("cannot build none token: %v", err)
		}
		serialized, err := noneToken.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize none token: %v", err)
		}

		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("cannot parse token: %v", err)
		}

		if err := parsed.Verify(t.Context(), jwk.NewKeySet(), jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
			t.Errorf(
				"verifying alg=none under DefaultVerificationConfig (no explicit request): got %v, want %v",
				err, jwt.ErrForbiddenAlgorithm,
			)
		}

		explicitConfig := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))
		keySet := jwk.NewKeySet(jwk.NewKey(secret("unused")))
		if err := parsed.Verify(t.Context(), keySet, explicitConfig); err != nil {
			t.Errorf("verifying alg=none with an explicit opt-in allowlist: %v, want nil", err)
		}
	})
}

// TestRSAPKCS1V15IsAvoided covers RFC8725-S3_2-R06.
//
// RFC 8725 Section 3.2: "Applications SHOULD follow these algorithm-specific
// recommendations: * Avoid all RSA-PKCS1 v1.5 encryption algorithms ([RFC8017],
// Section 7.2), preferring RSAES-OAEP ([RFC8017], Section 7.1)."
//
// The stem carries the keyword and the bullet carries the substance. "Avoid" is
// read here as two obligations, and both are asserted, in the same shape this
// document gives "none" in R04 and R05: a library may consume what it must not
// produce, provided the caller asks.
//
// Producing is refused by the type. jwa.RSAESPKCS1v15 has DecryptKey and neither
// EncryptKey nor WrapKey, so it is not a jwa.KeyEncrypter, and there is no
// option, configuration or caller that can turn the producing half on. Consuming
// is refused by default: RSA1_5 is absent from the key management algorithms
// jwt.DefaultDecryptionConfig accepts, so a token naming it is rejected before
// any key is touched unless the caller names the algorithm.
//
// RFC 7519 §8 states an unqualified MUST for RSA1_5 once an implementation
// provides encryption, and this shape satisfies both documents: the algorithm is
// implemented, and it is neither written nor read by accident. See
// RFC7519-S8-R05.
//
// rfc-req: RFC8725-S3_2-R06
func TestRSAPKCS1V15IsAvoided(t *testing.T) {
	material, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	t.Run("NeverProduced", func(t *testing.T) {
		algorithm, ok := jwa.ByName("RSA1_5")
		if !ok {
			t.Fatal("RSA1_5 does not resolve")
		}

		if _, ok := algorithm.(jwa.KeyEncrypter); ok {
			t.Error("RSA1_5 can encrypt a key; this module must not produce that padding")
		}

		message := &jwe.Message{ProtectedHeader: &header.Header{
			Algorithm: algorithm, EncryptionAlgorithm: jwa.A128GCM(),
		}}

		if err := message.Encrypt([]byte("plaintext"), &material.PublicKey); !errors.Is(
			err, jwa.ErrUnsupportedAlgorithm,
		) {
			t.Errorf("encrypting with RSA1_5: got %v, want ErrUnsupportedAlgorithm", err)
		}
	})

	t.Run("NotConsumedByDefault", func(t *testing.T) {
		key := jwk.NewKey(
			material,
			jwk.WithPublicKeyUse(jwk.Encryption),
			jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
		)

		encoded := "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.AAAA.AAAA.AAAA.AAAA"

		parsed, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot parse token: %v", err)
		}

		if err := parsed.Decrypt(
			t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig,
		); !errors.Is(err, jwt.ErrForbiddenKeyManagement) {
			t.Errorf(
				"decrypting alg=RSA1_5 under DefaultDecryptionConfig (no explicit request): got %v, want %v",
				err, jwt.ErrForbiddenKeyManagement,
			)
		}

		explicit := jwt.NewDecryptionConfig(jwt.WithKeyManagementAlgorithms(jwa.RSA15()))

		if err := parsed.Decrypt(
			t.Context(), jwk.NewKeySet(key), explicit,
		); errors.Is(err, jwt.ErrForbiddenKeyManagement) {
			t.Error("an explicit opt-in was still refused by the allowlist")
		}
	})
}

func TestECDSASigningIsDeterministic(t *testing.T) {
	// rfc-req: RFC8725-S3_2-R07
	key := generateES256Key(t)

	const signingInput = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UifQ"

	first, err := jwa.ES256().Sign([]byte(signingInput), key)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	second, err := jwa.ES256().Sign([]byte(signingInput), key)
	if err != nil {
		t.Fatalf("cannot sign a second time: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf(
			"signing one input twice with one key gave two signatures, so the nonce is not "+
				"deterministic:\n%x\n%x",
			first, second,
		)
	}
}

func TestSignatureTamperCausesRejection(t *testing.T) {
	// rfc-req: RFC8725-S3_3-R01
	key := jwk.NewKey(secret("shared secret"))

	token, err := jwt.NewToken(jwt.WithIssuer("rfc8725-conformance"), jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d compact segments, want 3", len(parts))
	}

	rawSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("cannot decode signature: %v", err)
	}
	if len(rawSignature) == 0 {
		t.Fatal("signature is empty; nothing to tamper with")
	}
	rawSignature[len(rawSignature)-1] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(rawSignature)

	tampered := strings.Join(parts, ".")

	parsed, err := jwt.Unmarshal(tampered)
	if err != nil {
		t.Fatalf("cannot parse tampered token: %v", err)
	}

	if err := parsed.Verify(t.Context(), jwk.NewKeySet(key), jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrUnverified) {
		t.Errorf("verifying a token with a tampered signature: got %v, want an error wrapping %v", err, jwt.ErrUnverified)
	}
}

func TestUTF8OnlyEncoding(t *testing.T) {
	// rfc-req: RFC8725-S3_7-R01
	t.Run("ValidUnicodeRoundTrips", func(t *testing.T) {
		const claimValue = "日本語 🎉"

		token, err := jwt.NewToken(
			jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("secret"))),
			jwt.WithPrivateClaim("note", claimValue),
		)
		if err != nil {
			t.Fatalf("cannot build token: %v", err)
		}

		serialized, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize token: %v", err)
		}

		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("cannot parse token: %v", err)
		}

		if got := parsed.PrivateClaim("note"); got != claimValue {
			t.Errorf("got claim %q, want %q", got, claimValue)
		}
	})

	t.Run("InvalidUTF8IsNeverEmitted", func(t *testing.T) {
		invalid := string([]byte{0xff, 0xfe, 0x41})

		token, err := jwt.NewToken(
			jwt.WithSignature(jwa.HS256(), jwk.NewKey(secret("secret"))),
			jwt.WithPrivateClaim("x", invalid),
		)
		if err != nil {
			t.Fatalf("cannot build token: %v", err)
		}

		serialized, err := token.Marshal()
		if err == nil {
			t.Fatalf("serializing a claim that is not UTF-8: got %q, want an error", serialized)
		}

		if utf8.ValidString(invalid) {
			t.Fatal("the test input is valid UTF-8; it proves nothing")
		}
	})
}

func TestAudienceValidation(t *testing.T) {
	// rfc-req: RFC8725-S3_9-R02
	const expectedAudience = "api.example.com"

	cases := []struct {
		name      string
		audience  []string
		wantError bool
	}{
		{name: "MatchingAudienceVerifies", audience: []string{expectedAudience}, wantError: false},
		{name: "MismatchedAudienceIsRejected", audience: []string{"other.example.com"}, wantError: true},
		{name: "AbsentAudienceIsRejected", audience: nil, wantError: true},
	}

	key := jwk.NewKey(secret("shared secret"))

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			options := []func(*jwt.Token) error{jwt.WithSignature(jwa.HS256(), key)}
			if testCase.audience != nil {
				options = append(options, jwt.WithAudience(testCase.audience...))
			}

			token, err := jwt.NewToken(options...)
			if err != nil {
				t.Fatalf("cannot build token: %v", err)
			}

			serialized, err := token.Marshal()
			if err != nil {
				t.Fatalf("cannot serialize token: %v", err)
			}

			parsed, err := jwt.Unmarshal(serialized)
			if err != nil {
				t.Fatalf("cannot parse token: %v", err)
			}

			config := jwt.NewVerificationConfig(jwt.WithExpectedAudience(expectedAudience))
			err = parsed.Verify(t.Context(), jwk.NewKeySet(key), config)

			if testCase.wantError && !errors.Is(err, jwt.ErrUnexpectedAudience) {
				t.Errorf("got %v, want an error wrapping %v", err, jwt.ErrUnexpectedAudience)
			}
			if !testCase.wantError && err != nil {
				t.Errorf("got %v, want nil", err)
			}
		})
	}
}

var forbiddenImportPrefixes = []string{"net/http", "net/rpc", "net/smtp", "net/mail"}

const networkingPackage = "jwk/remote"

var tokenBearingPackages = []string{
	"github.com/iscultas/jwt-go",
	"github.com/iscultas/jwt-go/header",
	"github.com/iscultas/jwt-go/jws",
	"github.com/iscultas/jwt-go/jwe",
}

func moduleImports(t *testing.T, root, directory string) map[string][]string {
	t.Helper()

	fileSet := token.NewFileSet()
	imports := make(map[string][]string)

	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		relative = filepath.ToSlash(relative)

		for _, imported := range file.Imports {
			imports[relative] = append(imports[relative], strings.Trim(imported.Path.Value, `"`))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("cannot walk module source: %v", err)
	}

	return imports
}

func moduleRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine this file's path via runtime.Caller")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func TestTheNetworkingPackageCannotSeeAToken(t *testing.T) {
	// rfc-req: RFC8725-S3_10-R01
	root := moduleRoot(t)

	imports := moduleImports(t, root, filepath.Join(root, filepath.FromSlash(networkingPackage)))

	if len(imports) == 0 {
		t.Fatalf("no source found in %s", networkingPackage)
	}

	for file, paths := range imports {
		for _, path := range paths {
			if slices.Contains(tokenBearingPackages, path) {
				t.Errorf(
					"%s imports %q, a package that decodes a token, thus a jku or an x5u could reach the code that makes a request",
					file, path,
				)
			}
		}
	}
}

type countingRefresher struct {
	gets      atomic.Int64
	refreshes atomic.Int64
}

func (source *countingRefresher) Get(context.Context) (*jwk.KeySet, error) {
	source.gets.Add(1)

	return jwk.NewKeySet(), nil
}

func (source *countingRefresher) Refresh(context.Context) (*jwk.KeySet, error) {
	source.refreshes.Add(1)

	return jwk.NewKeySet(), nil
}

func TestAnUnknownKeyCausesOneKeyRefreshAtMost(t *testing.T) {
	// rfc-req: RFC8725-S3_10-R01
	key := jwk.NewKey(secret("shared secret"))

	token, err := jwt.NewToken(
		jwt.WithSignature(jwa.HS256(), key, jws.WithProtectedHeader(header.WithKeyID("unknown-a"))),
		jwt.WithSignature(jwa.HS256(), key, jws.WithProtectedHeader(header.WithKeyID("unknown-b"))),
	)
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	source := new(countingRefresher)

	const tokens = 8

	for range tokens {
		if err := token.Verify(t.Context(), source, jwt.NewVerificationConfig(
			jwt.WithAlgorithms(jwa.HS256()),
		)); !errors.Is(err, jwk.ErrNoSuitableKey) {
			t.Fatalf("got error %v, want ErrNoSuitableKey", err)
		}
	}

	if got := source.gets.Load(); got != tokens {
		t.Errorf("got %d calls to Get, want %d: one for each verification", got, tokens)
	}

	if got := source.refreshes.Load(); got != tokens {
		t.Errorf(
			"got %d calls to Refresh, want %d: a token with two signatures asked for the keys more than one time",
			got, tokens,
		)
	}
}

func TestJKUAndX5UAreNeverDereferenced(t *testing.T) {
	// rfc-req: RFC8725-S3_10-R01
	t.Run("NoNetworkingImportInModuleSource", func(t *testing.T) {
		repoRoot := moduleRoot(t)

		for file, paths := range moduleImports(t, repoRoot, repoRoot) {
			if strings.HasPrefix(file, networkingPackage+"/") {
				continue
			}

			for _, importPath := range paths {
				for _, forbidden := range forbiddenImportPrefixes {
					if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
						t.Errorf("%s imports %q, a networking package this SHOULD requires the library to avoid", file, importPath)
					}
				}
			}
		}
	})

	t.Run("BogusJKUDoesNotPreventVerification", func(t *testing.T) {
		key := jwk.NewKey(secret("shared secret"))
		bogusJKU, err := url.Parse("https://attacker.invalid.example/exfiltrate")
		if err != nil {
			t.Fatalf("cannot parse bogus jku URL: %v", err)
		}

		token, err := jwt.NewToken(
			jwt.WithSignature(jwa.HS256(), key, jws.WithProtectedHeader(header.WithJWKSetURL(bogusJKU))),
		)
		if err != nil {
			t.Fatalf("cannot build token: %v", err)
		}

		serialized, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot serialize token: %v", err)
		}

		parsed, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("cannot parse token: %v", err)
		}

		if err := parsed.Verify(t.Context(), jwk.NewKeySet(key), jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("verifying a token whose header names an unreachable jku: %v, want nil", err)
		}
	})
}

func TestExplicitTypingRoundTrips(t *testing.T) {
	// rfc-req: RFC8725-S3_11-R01, RFC8725-S3_11-R05
	const typ = "secevent+jwt"

	key := jwk.NewKey(secret("shared secret"))

	token, err := jwt.NewToken(
		jwt.WithSignature(
			jwa.HS256(), key,
			jws.WithProtectedHeader(func(h *header.Header) { h.Type = typ }),
		),
	)
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	encodedProtectedHeader, _, _ := strings.Cut(serialized, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(encodedProtectedHeader)
	if err != nil {
		t.Fatalf("cannot decode protected header: %v", err)
	}

	var members map[string]any
	if err := json.Unmarshal(headerJSON, &members); err != nil {
		t.Fatalf("cannot decode protected header JSON: %v", err)
	}
	if members["typ"] != typ {
		t.Errorf("got typ %v on the wire, want %q (unmangled, no application/ prefix)", members["typ"], typ)
	}

	parsedHeader := protectedHeaderOf(t, serialized)
	if parsedHeader.Type != typ {
		t.Errorf("got parsed typ %q, want %q", parsedHeader.Type, typ)
	}
}

// TestExplicitTypingIsEnforcedOnTheReadPath is the second half of
// RFC8725-S3_11-R05.
//
// TestExplicitTypingRoundTrips proves that a recipient can recover the exact
// value. That is what section 3.11 needs at a minimum, and it was all this
// library offered while the discrimination check belonged to application code.
// The library now performs that check itself, through jwt.WithExpectedType, so
// the read path is held to the outcome the recommendation exists for: a token
// of one type must not pass where a different type was asked for.
//
// This adds no requirement to the IR. RFC8725-S3_11-R05 is one requirement, and
// this test asserts the same one more strictly than the round-trip test alone.
//
// rfc-req: RFC8725-S3_11-R05
func TestExplicitTypingIsEnforcedOnTheReadPath(t *testing.T) {
	const secEvent = "secevent+jwt"

	key := jwk.NewKey(secret("shared secret"))
	keySet := jwk.NewKeySet(key)

	for _, testCase := range []struct {
		name string
		typ  string
		want error
	}{
		{"TheTypeAskedFor", secEvent, nil},
		{"ADifferentType", "at+jwt", jwt.ErrUnexpectedType},
		{"AnUntypedJWT", "JWT", jwt.ErrUnexpectedType},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token, err := jwt.NewToken(
				jwt.WithType(testCase.typ),
				jwt.WithSignature(jwa.HS256(), key),
			)
			if err != nil {
				t.Fatalf("cannot build token: %v", err)
			}

			serialized, err := token.Marshal()
			if err != nil {
				t.Fatalf("cannot serialize token: %v", err)
			}

			parsed, err := jwt.Unmarshal(serialized)
			if err != nil {
				t.Fatalf("cannot parse token: %v", err)
			}

			err = parsed.Verify(t.Context(), keySet, jwt.NewVerificationConfig(
				jwt.WithAlgorithms(jwa.HS256()), jwt.WithExpectedType(secEvent),
			))
			if !errors.Is(err, testCase.want) {
				t.Errorf("got %v, want %v", err, testCase.want)
			}
		})
	}
}

func secret(seed string) []byte {
	key := sha512.Sum512([]byte(seed))

	return key[:]
}

// TestNestedJWTValidatesBothOperations checks §3.3's Nested JWT half.
//
// MUST — "This is true not only of JWTs with a single set of Header Parameters
// but also for Nested JWTs in which both outer and inner operations MUST be
// validated using the keys and algorithms supplied by the application."
//
// Not-testable until this module gained Nested JWT support. Both orders are
// asserted, since an implementation that stopped after the outer operation would
// pass the ciphertext case alone: a tampered inner signature must fail even
// though the outer AEAD verified, and a tampered outer ciphertext must fail
// before the inner signature is reached.
//
// The keys and algorithms are the application's to supply, as the sentence
// requires — the outer through jwt.DecryptionConfig's allow lists, the inner
// through the VerificationConfig that WithVerification carries.
//
// rfc-req: RFC8725-S3_3-R02
func TestNestedJWTValidatesBothOperations(t *testing.T) {
	signing := jwk.NewKey(
		bytes.Repeat([]byte{1}, 32),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
	)
	wrapping := jwk.NewKey(
		bytes.Repeat([]byte{7}, 16),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)

	keySet := jwk.NewKeySet(signing, wrapping)
	config := jwt.NewDecryptionConfig(
		jwt.WithRequiredNestedToken(),
		jwt.WithVerification(jwt.WithAlgorithms(jwa.HS256())),
	)

	build := func() string {
		t.Helper()

		token, err := jwt.NewToken(
			jwt.WithIssuer("joe"),
			jwt.WithSignature(jwa.HS256(), signing),
			jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), wrapping),
		)
		if err != nil {
			t.Fatalf("cannot build: %v", err)
		}

		encoded, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot marshal: %v", err)
		}

		return encoded
	}

	t.Run("both valid", func(t *testing.T) {
		read, err := jwt.Unmarshal(build())
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(t.Context(), keySet, config); err != nil {
			t.Fatalf("a well-formed nested token was refused: %v", err)
		}

		if read.Issuer() != "joe" {
			t.Errorf("issuer is %q, want %q", read.Issuer(), "joe")
		}
	})

	t.Run("the outer operation fails", func(t *testing.T) {
		encoded := build()
		parts := strings.Split(encoded, ".")

		ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
		if err != nil {
			t.Fatalf("cannot decode the ciphertext: %v", err)
		}

		ciphertext[0] ^= 1
		parts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)

		read, err := jwt.Unmarshal(strings.Join(parts, "."))
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(t.Context(), keySet, config); err == nil {
			t.Error("a tampered ciphertext was accepted")
		}
	})

	t.Run("the inner operation fails", func(t *testing.T) {
		inner, err := jwt.NewToken(jwt.WithIssuer("joe"), jwt.WithSignature(jwa.HS256(), signing))
		if err != nil {
			t.Fatalf("cannot build the inner token: %v", err)
		}

		signed, err := inner.Marshal()
		if err != nil {
			t.Fatalf("cannot sign: %v", err)
		}

		parts := strings.Split(signed, ".")

		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("cannot decode the signature: %v", err)
		}

		signature[0] ^= 1
		parts[2] = base64.RawURLEncoding.EncodeToString(signature)

		message := &jwe.Message{ProtectedHeader: &header.Header{
			Type:                "JWT",
			ContentType:         jwt.NestedContentType,
			Algorithm:           jwa.A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
		}}

		if err := message.Encrypt([]byte(strings.Join(parts, ".")), wrapping.Material()); err != nil {
			t.Fatalf("cannot encrypt: %v", err)
		}

		encoded, err := message.Marshal()
		if err != nil {
			t.Fatalf("cannot marshal: %v", err)
		}

		read, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(t.Context(), keySet, config); err == nil {
			t.Error("a nested token with an invalid inner signature was accepted")
		}
	})

	t.Run("the application forbids the inner algorithm", func(t *testing.T) {
		forbidding := jwt.NewDecryptionConfig(
			jwt.WithRequiredNestedToken(),
			jwt.WithVerification(jwt.WithAlgorithms(jwa.HS384())),
		)

		read, err := jwt.Unmarshal(build())
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(t.Context(), keySet, forbidding); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
			t.Errorf("got error %v, want %v", err, jwt.ErrForbiddenAlgorithm)
		}
	})
}

// TestECDHInputsAreValidated checks §3.4.
//
// MUST — "For the NIST prime-order curves P-256, P-384, and P-521, validation
// MUST be performed according to Section 5.6.2.3.4 (ECC Partial Public-Key
// Validation Routine) of [SP 800-56A]."
//
// Excluded while this module had no key agreement.
//
// Assumption, labelled, and it is the whole scope of what is claimed: the
// validation is **delegated** to crypto/ecdh. jwa routes both keys through
// (*ecdsa.PublicKey).ECDH, whose ecdh.Curve.NewPublicKey performs exactly this
// routine — rejecting the point at infinity, compressed encodings and points off
// the curve. This test asserts that the path reaches it and that the named cases
// are refused. It does not independently verify the standard library's
// arithmetic, and a defect there would not be caught here. Saying so is the
// point: a suite claiming to have verified SP 800-56A when it has verified a
// delegation would be claiming more than it did.
//
// rfc-req: RFC8725-S3_4-R01
func TestECDHInputsAreValidated(t *testing.T) {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	t.Run("a point on another curve", func(t *testing.T) {
		ephemeral, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate an ephemeral key: %v", err)
		}

		_, err = jwa.ECDHES().DecryptKey(
			nil, recipient, jwa.A128GCM(), &jwa.KeyParameters{EphemeralPublicKey: &ephemeral.PublicKey},
		)
		if !errors.Is(err, jwa.ErrInvalidKeyType) {
			t.Errorf("got %v, want ErrInvalidKeyType", err)
		}
	})

	t.Run("a point not on the curve", func(t *testing.T) {
		offCurve := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
			X: big.NewInt(1),
			//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
			Y: big.NewInt(1),
		}

		_, err = jwa.ECDHES().DecryptKey(
			nil, recipient, jwa.A128GCM(), &jwa.KeyParameters{EphemeralPublicKey: offCurve},
		)
		if err == nil {
			t.Error("a point off the curve was accepted")
		}
	})

	t.Run("the point at infinity", func(t *testing.T) {
		infinity := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
			X: big.NewInt(0),
			//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
			Y: big.NewInt(0),
		}

		_, err = jwa.ECDHES().DecryptKey(
			nil, recipient, jwa.A128GCM(), &jwa.KeyParameters{EphemeralPublicKey: infinity},
		)
		if err == nil {
			t.Error("the point at infinity was accepted")
		}
	})

	t.Run("a well-formed point", func(t *testing.T) {
		ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate an ephemeral key: %v", err)
		}

		if _, err := jwa.ECDHES().DecryptKey(
			nil, recipient, jwa.A128GCM(), &jwa.KeyParameters{EphemeralPublicKey: &ephemeral.PublicKey},
		); err != nil {
			t.Errorf("a valid ephemeral key was refused: %v", err)
		}
	})
}

// TestCompressionIsNotDoneBeforeEncryption checks §3.6.
//
// SHOULD NOT — "Compression of data SHOULD NOT be done before encryption,
// because such compressed data often reveals information about the plaintext."
//
// Excluded while this module had no encryption. should_policy is strict, so it is
// a hard assertion — but it is a SHOULD NOT rather than a MUST NOT, so declining
// is this module's choice and is recorded as one. The ciphertext length tracks
// the compressed length, so an attacker who can influence part of the plaintext
// learns how well the rest compresses against it: the CRIME and BREACH family.
//
// The resolution is asymmetric and both halves are asserted, because the
// asymmetry is the behaviour rather than an omission: none is ever produced,
// and a compressed JWE from another implementation is still read. Declining to
// produce something costs a sender nothing; declining to read it would cost a
// recipient a message they were entitled to.
//
// rfc-req: RFC8725-S3_6-R01
func TestCompressionIsNotDoneBeforeEncryption(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)

	t.Run("never produced", func(t *testing.T) {
		message := &jwe.Message{ProtectedHeader: &header.Header{
			Algorithm:            jwa.A128KW(),
			EncryptionAlgorithm:  jwa.A128GCM(),
			CompressionAlgorithm: header.Deflate,
		}}

		if err := message.Encrypt([]byte("plaintext"), key); !errors.Is(err, jwe.ErrCompressedPlaintext) {
			t.Errorf("got %v, want ErrCompressedPlaintext", err)
		}
	})

	t.Run("still read", func(t *testing.T) {
		var compressed bytes.Buffer

		writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
		if err != nil {
			t.Fatalf("cannot build a writer: %v", err)
		}

		if _, err := writer.Write([]byte("plaintext")); err != nil {
			t.Fatalf("cannot compress: %v", err)
		}

		if err := writer.Close(); err != nil {
			t.Fatalf("cannot flush: %v", err)
		}

		protectedHeader := &header.Header{
			Algorithm:            jwa.A128KW(),
			EncryptionAlgorithm:  jwa.A128GCM(),
			CompressionAlgorithm: header.Deflate,
		}

		encoded, err := protectedHeader.Marshal()
		if err != nil {
			t.Fatalf("cannot encode the header: %v", err)
		}

		cek, encryptedKey, err := jwa.A128KW().EncryptKey(key, jwa.A128GCM(), new(jwa.KeyParameters))
		if err != nil {
			t.Fatalf("cannot wrap: %v", err)
		}

		iv := bytes.Repeat([]byte{5}, jwa.A128GCM().IVSize())

		ciphertext, tag, err := jwa.A128GCM().Encrypt(compressed.Bytes(), cek, iv, []byte(encoded))
		if err != nil {
			t.Fatalf("cannot encrypt: %v", err)
		}

		message := &jwe.Message{
			ProtectedHeader:      protectedHeader,
			Recipients:           []*jwe.Recipient{{EncryptedKey: encryptedKey}},
			InitializationVector: iv,
			Ciphertext:           ciphertext,
			AuthenticationTag:    tag,
		}

		recovered, err := message.Decrypt(key)
		if err != nil {
			t.Fatalf("cannot decrypt a compressed JWE: %v", err)
		}

		if string(recovered) != "plaintext" {
			t.Errorf("got %q, want %q", recovered, "plaintext")
		}
	})
}

// TestNestedJWTCarriesTheExplicitTypeInside covers the placement rule §3.11
// states for Nested JWTs.
//
// MUST — "When applying explicit typing to a Nested JWT, the 'typ' Header
// Parameter containing the explicit type value MUST be present in the inner JWT
// of the Nested JWT (the JWT whose payload is the JWT Claims Set)."
//
// Not-testable until this module gained Nested JWT support, and the exclusion
// outlived that: the reason recorded — "this package has no Nested JWT concept
// at all — there is no inner JWT for a typ Header Parameter to be present on" —
// stopped being true when WithSignature and WithEncryption could be given
// together.
//
// Where the value lands is the whole requirement. An outer "typ" says only that
// the JWE carries a JWT; the inner one is what tells a recipient what kind of
// claims set it is about to trust, and a recipient that read the outer would
// learn nothing an attacker could not have written. The assertion is therefore
// on the decrypted inner JWS rather than on what jwt.Token reports.
//
// rfc-req: RFC8725-S3_11-R04
func TestNestedJWTCarriesTheExplicitTypeInside(t *testing.T) {
	const explicitType = "secevent+jwt"

	signing := jwk.NewKey(
		bytes.Repeat([]byte{1}, 32),
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
		jwt.WithSignature(
			jwa.HS256(), signing,
			jws.WithProtectedHeader(func(h *header.Header) { h.Type = explicitType }),
		),
		jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), wrapping),
	)
	if err != nil {
		t.Fatalf("cannot build: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	outer := headerMembers(t, encoded)

	if outer["typ"] != "JWT" {
		t.Errorf(`outer typ is %v, want "JWT"`, outer["typ"])
	}

	if outer["cty"] != "JWT" {
		t.Errorf(`outer cty is %v, want "JWT"`, outer["cty"])
	}

	if outer["typ"] == explicitType {
		t.Error("the explicit type was written to the outer JWT, where §3.11 says it does not belong")
	}

	message, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot read the JWE: %v", err)
	}

	innerCompact, err := message.Decrypt(wrapping.Material())
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	inner := headerMembers(t, string(innerCompact))

	if inner["typ"] != explicitType {
		t.Errorf("inner typ is %v, want %q", inner["typ"], explicitType)
	}
}

func headerMembers(t *testing.T, compact string) map[string]any {
	t.Helper()

	encodedHeader, _, _ := strings.Cut(compact, ".")

	decoded, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}

	members := make(map[string]any)
	if err := json.Unmarshal(decoded, &members); err != nil {
		t.Fatalf("cannot decode the protected header JSON: %v", err)
	}

	return members
}
