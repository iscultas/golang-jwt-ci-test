package rfc7516_test

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
	"slices"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

const plaintext = "The true sign of intelligence is not knowledge but imagination."

func wrappingKey() []byte { return bytes.Repeat([]byte{7}, 16) }

func message(t *testing.T, options ...func(*header.Header)) *jwe.Message {
	t.Helper()

	protectedHeader := &header.Header{Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM()}
	for _, option := range options {
		option(protectedHeader)
	}

	encrypted := &jwe.Message{ProtectedHeader: protectedHeader}
	if err := encrypted.Encrypt([]byte(plaintext), wrappingKey()); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	return encrypted
}

func members(t *testing.T, encrypted *jwe.Message) map[string]jsontext.Value {
	t.Helper()

	encoded, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	decoded := map[string]jsontext.Value{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}

	return decoded
}

// TestJSONSerializationToleratesWhitespace checks that a JWE JSON document
// formatted for readability still decodes and decrypts.
//
// rfc-req: RFC7516-S3-R01
// MAY — "These JSON data structures MAY contain whitespace and/or line breaks
// before or after any JSON values or structural characters, in accordance with
// Section 2 of RFC 7159."
//
// The permission is exercised by producers; the obligation a consumer carries is
// the receiving half, and that half is asserted rather than skipped. The
// tolerance stops at the base64url parts — §5.2 step 2 forbids whitespace inside
// those — which is a separate requirement.
func TestJSONSerializationToleratesWhitespace(t *testing.T) {
	encoded, err := json.Marshal(message(t))
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	indented := jsontext.Value(encoded)
	if err := indented.Indent(jsontext.WithIndentPrefix("  "), jsontext.WithIndent("\t")); err != nil {
		t.Fatalf("cannot indent: %v", err)
	}

	decoded := new(jwe.Message)
	if err := json.Unmarshal(indented, decoded); err != nil {
		t.Fatalf("cannot decode an indented document: %v", err)
	}

	recovered, err := decoded.Decrypt(wrappingKey())
	if err != nil {
		t.Fatalf("cannot decrypt an indented document: %v", err)
	}

	if string(recovered) != plaintext {
		t.Errorf("got %q, want %q", recovered, plaintext)
	}
}

// TestAMessageWithNoHeaderIsRefused checks that a JWE naming its parameters
// nowhere is refused.
//
// rfc-req: RFC7516-S3_2-R01
// MUST — "In the JWE JSON Serialization, one or more of the JWE Protected
// Header, JWE Shared Unprotected Header, and JWE Per-Recipient Unprotected
// Header MUST be present."
//
// Assumption, labelled: this module is stricter than the sentence. RFC 7516
// would allow the sole header to be an unprotected one; jwe requires a protected
// header, because "enc" is read from it alone. The requirement as stated is
// satisfied a fortiori — everything the RFC refuses is refused here, and some of
// what it permits. The narrowing is argued at TestEncOutsideTheProtectedHeaderIsRefused.
func TestAMessageWithNoHeaderIsRefused(t *testing.T) {
	for name, act := range map[string]func(*jwe.Message) error{
		"encrypt": func(m *jwe.Message) error { return m.Encrypt([]byte(plaintext), wrappingKey()) },
		"decrypt": func(m *jwe.Message) error { _, err := m.Decrypt(wrappingKey()); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := act(new(jwe.Message)); !errors.Is(err, jwe.ErrMalformedMessage) {
				t.Errorf("got %v, want ErrMalformedMessage", err)
			}
		})
	}
}

// TestOptionalMembersAreAbsentWhenUnused checks that a minimal message carries
// only the members it needs.
//
// rfc-req: RFC7516-S3_2-R02
// MAY — "The inclusion of some of these values is OPTIONAL."
func TestOptionalMembersAreAbsentWhenUnused(t *testing.T) {
	present := slices.Sorted(maps(members(t, message(t))))

	want := []string{"ciphertext", "encrypted_key", "iv", "protected", "tag"}
	if !slices.Equal(present, want) {
		t.Errorf("got members %v, want %v", present, want)
	}
}

func maps(m map[string]jsontext.Value) func(func(string) bool) {
	return func(yield func(string) bool) {
		for name := range m {
			if !yield(name) {
				return
			}
		}
	}
}

// TestDuplicateHeaderParameterNameIsRejected checks how a JOSE Header repeating
// a member name is parsed.
//
// rfc-req: RFC7516-S4-R01
// MUST — "The Header Parameter names within the JOSE Header MUST be unique, just
// as described in Section 4 of [JWS]."
//
// RFC 7515 section 4 offers two conforming behaviours: reject the object, or use
// a JSON parser returning only the lexically last duplicate member. This package
// rejects — the same resolution recorded at RFC7515-S4-R01. What this test adds
// is that the JWE path behaves identically to the JWS one: one parser, one
// answer.
func TestDuplicateHeaderParameterNameIsRejected(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"A128KW","enc":"A128GCM","kid":"one","kid":"two"}`),
	)

	err := new(header.Header).Unmarshal(encoded)
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("got %v, want an error wrapping jsontext.ErrDuplicateName", err)
	}
}

// TestEncIsAlwaysAEADWithAFixedKeyLength checks that every algorithm this module
// accepts as an "enc" is authenticated encryption with one valid key length.
//
// rfc-req: RFC7516-S4_1_2-R01
// MUST — "This algorithm MUST be an AEAD algorithm with a specified key length."
func TestEncIsAlwaysAEADWithAFixedKeyLength(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{
		jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
		jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
	} {
		t.Run(encryption.String(), func(t *testing.T) {
			cek := bytes.Repeat([]byte{3}, encryption.KeySize())
			iv := bytes.Repeat([]byte{5}, encryption.IVSize())

			ciphertext, tag, err := encryption.Encrypt([]byte(plaintext), cek, iv, []byte("aad"))
			if err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			if len(tag) == 0 {
				t.Error("no authentication tag, so the algorithm is not AEAD")
			}

			tampered := slices.Clone(tag)
			tampered[0] ^= 1

			if _, err := encryption.Decrypt(ciphertext, cek, iv, []byte("aad"), tampered); !errors.Is(
				err, jwa.ErrDecryptionFailed,
			) {
				t.Errorf("a tampered tag gave %v, want ErrDecryptionFailed", err)
			}

			if _, err := encryption.Decrypt(ciphertext, cek, iv, []byte("aaD"), tag); !errors.Is(
				err, jwa.ErrDecryptionFailed,
			) {
				t.Errorf("a tampered AAD gave %v, want ErrDecryptionFailed", err)
			}

			for _, size := range []int{encryption.KeySize() - 1, encryption.KeySize() + 1} {
				_, _, err := encryption.Encrypt([]byte(plaintext), make([]byte, size), iv, nil)
				if !errors.Is(err, jwa.ErrInvalidKeySize) {
					t.Errorf("a %d-octet CEK gave %v, want ErrInvalidKeySize", size, err)
				}
			}
		})
	}
}

// TestASignatureAlgorithmIsNotAnEnc checks that a name outside the content
// encryption registry cannot be used as one.
//
// rfc-req: RFC7516-S4_1_2-R01
// MUST — the same sentence, from the other side: an algorithm that is not AEAD
// must not resolve as an "enc" at all.
//
// jwa keeps one name registry, since the IANA JWS and JWE names are disjoint;
// what separates their uses is the interface each caller asserts. header.Header's
// EncryptionAlgorithm field is typed jwa.ContentEncrypter, so the refusal happens
// where the value is read rather than somewhere less informative later.
func TestASignatureAlgorithmIsNotAnEnc(t *testing.T) {
	err := json.Unmarshal([]byte(`{"alg":"A128KW","enc":"HS256"}`), new(header.Header))
	if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestEncMustBePresent checks that a JWE naming no content encryption algorithm
// is refused rather than defaulted.
//
// rfc-req: RFC7516-S4_1_2-R02
// MUST — "This Header Parameter MUST be present and MUST be understood and
// processed by implementations."
func TestEncMustBePresent(t *testing.T) {
	for name, act := range map[string]func() error{
		"encrypt": func() error {
			return (&jwe.Message{ProtectedHeader: &header.Header{Algorithm: jwa.A128KW()}}).
				Encrypt([]byte(plaintext), wrappingKey())
		},
		"decrypt": func() error {
			encrypted := message(t)
			encrypted.ProtectedHeader = &header.Header{Algorithm: jwa.A128KW()}
			_, err := encrypted.Decrypt(wrappingKey())

			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := act(); !errors.Is(err, jwe.ErrMalformedMessage) {
				t.Errorf("got %v, want ErrMalformedMessage", err)
			}
		})
	}
}

// TestAnUnknownCompressionAlgorithmIsRefused checks that a "zip" this module
// does not implement is refused rather than treated as no compression.
//
// rfc-req: RFC7516-S4_1_3-R01
// MAY — "Other values MAY be used."
//
// capability: alternative-compression-algorithms — absent here. This is the
// interop half of a MAY and is not skipped: the obligation on an implementation
// lacking the capability is to refuse, because passing the octets through
// unchanged would emit something that is not the plaintext.
func TestAnUnknownCompressionAlgorithmIsRefused(t *testing.T) {
	encrypted := message(t)
	encoded := encrypted.ProtectedHeader.Encoded()

	encrypted.ProtectedHeader = &header.Header{
		Algorithm:            jwa.A128KW(),
		EncryptionAlgorithm:  jwa.A128GCM(),
		CompressionAlgorithm: "XYZ",
	}
	encrypted.ProtectedHeader.SetEncoded(encoded)

	recovered, err := encrypted.Decrypt(wrappingKey())
	if err == nil {
		t.Errorf("an unknown zip was ignored, recovering %q", recovered)
	}
}

// TestZipIsReadFromTheProtectedHeaderOnly checks that a compression algorithm
// named outside the integrity-protected header has no effect.
//
// rfc-req: RFC7516-S4_1_3-R02
// MUST — "When used, this Header Parameter MUST be integrity protected;
// therefore, it MUST occur only within the JWE Protected Header."
//
// The rule has teeth: "zip" in an unprotected header sits outside the Additional
// Authenticated Data, so an attacker who could add one would make the recipient
// inflate octets of their choosing.
func TestZipIsReadFromTheProtectedHeaderOnly(t *testing.T) {
	for name, place := range map[string]func(*jwe.Message, *header.Header){
		"shared":        func(m *jwe.Message, h *header.Header) { m.SharedHeader = h },
		"per-recipient": func(m *jwe.Message, h *header.Header) { m.Recipients[0].Header = h },
	} {
		t.Run(name, func(t *testing.T) {
			encrypted := message(t)
			place(encrypted, &header.Header{CompressionAlgorithm: header.Deflate})

			recovered, err := encrypted.Decrypt(wrappingKey())
			if err != nil {
				t.Fatalf("cannot decrypt: %v", err)
			}

			if string(recovered) != plaintext {
				t.Errorf("an unprotected zip changed the result: got %q, want %q", recovered, plaintext)
			}
		})
	}
}

// TestCompressionIsAsymmetric checks both halves of this module's position on
// "zip": it reads what it will not write.
//
// rfc-req: RFC7516-S4_1_3-R03
// MAY — "Use of this Header Parameter is OPTIONAL."
//
// rfc-req: RFC7516-S4_1_3-R04
// MUST — "This Header Parameter MUST be understood and processed by
// implementations."
//
// capability: compression-before-encryption — deliberately absent. RFC 8725 §3.6
// says compression "SHOULD NOT be done before encryption, because such compressed
// data often reveals information about the plaintext". It is a SHOULD NOT, so
// declining is this module's choice and is recorded as one; the MUST above is
// still met, because the parameter is understood on the way in.
func TestCompressionIsAsymmetric(t *testing.T) {
	t.Run("never produced", func(t *testing.T) {
		encrypted := &jwe.Message{ProtectedHeader: &header.Header{
			Algorithm:            jwa.A128KW(),
			EncryptionAlgorithm:  jwa.A128GCM(),
			CompressionAlgorithm: header.Deflate,
		}}

		if err := encrypted.Encrypt([]byte(plaintext), wrappingKey()); !errors.Is(
			err, jwe.ErrCompressedPlaintext,
		) {
			t.Errorf("got %v, want ErrCompressedPlaintext", err)
		}
	})

	t.Run("always understood", func(t *testing.T) {
		compressed := deflate(t, []byte(plaintext))

		protectedHeader := &header.Header{
			Algorithm:            jwa.A128KW(),
			EncryptionAlgorithm:  jwa.A128GCM(),
			CompressionAlgorithm: header.Deflate,
		}

		encoded, err := protectedHeader.Marshal()
		if err != nil {
			t.Fatalf("cannot encode the header: %v", err)
		}

		cek, encryptedKey, err := jwa.A128KW().EncryptKey(wrappingKey(), jwa.A128GCM(), new(jwa.KeyParameters))
		if err != nil {
			t.Fatalf("cannot wrap: %v", err)
		}

		iv := bytes.Repeat([]byte{5}, jwa.A128GCM().IVSize())

		ciphertext, tag, err := jwa.A128GCM().Encrypt(compressed, cek, iv, []byte(encoded))
		if err != nil {
			t.Fatalf("cannot encrypt: %v", err)
		}

		encrypted := &jwe.Message{
			ProtectedHeader:      protectedHeader,
			Recipients:           []*jwe.Recipient{{EncryptedKey: encryptedKey}},
			InitializationVector: iv,
			Ciphertext:           ciphertext,
			AuthenticationTag:    tag,
		}

		recovered, err := encrypted.Decrypt(wrappingKey())
		if err != nil {
			t.Fatalf("cannot decrypt a compressed JWE: %v", err)
		}

		if string(recovered) != plaintext {
			t.Errorf("got %q, want %q", recovered, plaintext)
		}
	})
}

// TestTheCEKIsAlwaysTheLengthEncRequires checks the CEK length across the whole
// algorithm matrix.
//
// rfc-req: RFC7516-S5_1-R01
// MUST — "The CEK MUST have a length equal to that required for the content
// encryption algorithm."
//
// The cross product is the point rather than thoroughness for its own sake: "alg"
// and "enc" are chosen independently in a JOSE header and the CEK length is the
// only thing coupling them, so a key management algorithm that assumed one length
// would pass any single-pairing test.
func TestTheCEKIsAlwaysTheLengthEncRequires(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{
		jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
		jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
	} {
		t.Run(encryption.String(), func(t *testing.T) {
			for _, pairing := range keyManagement(t, encryption) {
				t.Run(pairing.algorithm.String(), func(t *testing.T) {
					cek, _, err := pairing.algorithm.EncryptKey(
						pairing.encryptionKey, encryption, new(jwa.KeyParameters),
					)
					if err != nil {
						t.Fatalf("cannot settle a CEK: %v", err)
					}

					if len(cek) != encryption.KeySize() {
						t.Errorf("got a %d-octet CEK, want %d", len(cek), encryption.KeySize())
					}
				})
			}
		})
	}
}

// TestAtLeastOneRecipientMustValidate checks that a JWE no recipient can read is
// invalid.
//
// rfc-req: RFC7516-S5_2-R01
// MUST — "in all cases, the encrypted content for at least one recipient MUST
// successfully validate or the JWE MUST be considered invalid."
//
// rfc-req: RFC7516-S5_2-R04
// MUST — "If there was no recipient for which all of the decryption steps
// succeeded, then the JWE MUST be considered invalid."
//
// How many recipients must validate is an application decision, as the RFC says.
// This module reports the first that does, which meets the floor the RFC sets.
func TestAtLeastOneRecipientMustValidate(t *testing.T) {
	first, second := wrappingKey(), bytes.Repeat([]byte{9}, 16)
	stranger := bytes.Repeat([]byte{11}, 16)

	encrypted := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
	}}

	err := encrypted.EncryptTo(
		[]byte(plaintext), jwe.RecipientKey{Key: first}, jwe.RecipientKey{Key: second},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	t.Run("a party addressed", func(t *testing.T) {
		for i, key := range [][]byte{first, second} {
			recovered, err := encrypted.Decrypt(key)
			if err != nil {
				t.Errorf("recipient %d: %v", i, err)

				continue
			}

			if string(recovered) != plaintext {
				t.Errorf("recipient %d: got %q, want %q", i, recovered, plaintext)
			}
		}
	})

	t.Run("a party not addressed", func(t *testing.T) {
		recovered, err := encrypted.Decrypt(stranger)
		if err == nil {
			t.Fatalf("a stranger decrypted the message, recovering %q", recovered)
		}

		if recovered != nil {
			t.Errorf("a failed decryption emitted %q", recovered)
		}
	})
}

// TestNoPlaintextEscapesAFailedDecryption checks that every way of breaking a
// JWE yields an error and nothing else.
//
// rfc-req: RFC7516-S5_2-R04
// MUST — "If there was no recipient for which all of the decryption steps
// succeeded, then the JWE MUST be considered invalid."
//
// Step 16 states the same rule for the tag specifically — "rejecting the input
// without emitting any decrypted output if the JWE Authentication Tag is
// incorrect" — and the assertion here is that no path emits partial output,
// not merely that an error is returned alongside it.
func TestNoPlaintextEscapesAFailedDecryption(t *testing.T) {
	for name, tamper := range map[string]func(*jwe.Message){
		"encrypted key": func(m *jwe.Message) { m.Recipients[0].EncryptedKey[0] ^= 1 },
		"iv":            func(m *jwe.Message) { m.InitializationVector[0] ^= 1 },
		"ciphertext":    func(m *jwe.Message) { m.Ciphertext[0] ^= 1 },
		"tag":           func(m *jwe.Message) { m.AuthenticationTag[0] ^= 1 },
		"protected header": func(m *jwe.Message) {
			m.ProtectedHeader.SetEncoded(m.ProtectedHeader.Encoded() + "x")
		},
	} {
		t.Run(name, func(t *testing.T) {
			encrypted := message(t)
			tamper(encrypted)

			recovered, err := encrypted.Decrypt(wrappingKey())
			if err == nil {
				t.Fatalf("a tampered %s decrypted, recovering %q", name, recovered)
			}

			if recovered != nil {
				t.Errorf("a tampered %s emitted %q alongside %v", name, recovered, err)
			}
		})
	}
}

// TestHeaderParameterNamesAreDisjointAcrossAllThreeHeaders checks the union rule
// of §5.2 step 4 and §7.2.1.
//
// rfc-req: RFC7516-S5_2-R02
// MUST — "When using the JWE JSON Serialization, this restriction includes that
// the same Header Parameter name also MUST NOT occur in distinct JSON object
// values that together comprise the JOSE Header."
//
// rfc-req: RFC7516-S7_2_1-R13
// MUST — "The Header Parameter names in the three locations MUST be disjoint."
//
// All three pairings, not only protected-against-the-rest: a name appearing in
// both unprotected headers and neither protected one is just as undefined, and is
// what a two-way check would miss. Both directions too — a producer that emitted
// what this consumer rejects is a defect the consumer's test alone would not find.
func TestHeaderParameterNamesAreDisjointAcrossAllThreeHeaders(t *testing.T) {
	for _, pairing := range []struct {
		name                 string
		protected            string
		shared, perRecipient *header.Header
	}{
		{"protected and shared", "a", &header.Header{KeyID: "a"}, nil},
		{"protected and per-recipient", "a", nil, &header.Header{KeyID: "a"}},
		{"shared and per-recipient", "", &header.Header{Type: "b"}, &header.Header{Type: "b"}},
	} {
		t.Run(pairing.name, func(t *testing.T) {
			t.Run("encrypting", func(t *testing.T) {
				encrypted := &jwe.Message{
					ProtectedHeader: &header.Header{
						Algorithm:           jwa.A128KW(),
						EncryptionAlgorithm: jwa.A128GCM(),
						KeyID:               pairing.protected,
					},
					SharedHeader: pairing.shared,
				}

				err := encrypted.EncryptTo(
					[]byte(plaintext),
					jwe.RecipientKey{Header: pairing.perRecipient, Key: wrappingKey()},
				)

				if !errors.Is(err, jwe.ErrDuplicateHeaderParameter) {
					t.Errorf("got %v, want ErrDuplicateHeaderParameter", err)
				}
			})

			t.Run("decrypting", func(t *testing.T) {
				encrypted := message(t, func(h *header.Header) { h.KeyID = pairing.protected })
				encrypted.SharedHeader = pairing.shared

				if pairing.perRecipient != nil {
					encrypted.Recipients[0].Header = pairing.perRecipient
				}

				if _, err := encrypted.Decrypt(wrappingKey()); !errors.Is(
					err, jwe.ErrDuplicateHeaderParameter,
				) {
					t.Errorf("got %v, want ErrDuplicateHeaderParameter", err)
				}
			})
		})
	}
}

// TestARecoveredCEKOfTheWrongLengthIsRejected checks the decryption-side length
// rule, and the error it uses.
//
// rfc-req: RFC7516-S5_2-R03
// MUST — "The CEK MUST have a length equal to that required for the content
// encryption algorithm."
//
// The choice of error is the assertion. jwa.ErrDecryptionFailed, not
// ErrInvalidKeySize: on this path the length is a fact about the token, so an
// attacker able to tell "the unwrap succeeded but gave the wrong length" from
// "the unwrap failed" would have the beginnings of the oracle §11.5 denies them.
func TestARecoveredCEKOfTheWrongLengthIsRejected(t *testing.T) {
	wrong := bytes.Repeat([]byte{3}, jwa.A256GCM().KeySize())

	encryptedKey, err := jwa.A128KW().WrapKey(wrong, wrappingKey(), jwa.A256GCM(), new(jwa.KeyParameters))
	if err != nil {
		t.Fatalf("cannot wrap: %v", err)
	}

	_, err = jwa.A128KW().DecryptKey(encryptedKey, wrappingKey(), jwa.A128GCM(), new(jwa.KeyParameters))
	if !errors.Is(err, jwa.ErrDecryptionFailed) {
		t.Errorf("got %v, want ErrDecryptionFailed", err)
	}

	if errors.Is(err, jwa.ErrInvalidKeySize) {
		t.Error("the error distinguishes a length failure from any other, which is the RFC 7516 section 11.5 leak")
	}
}

// TestUnacceptableAlgorithmsMakeAJWEInvalid checks the allowlist at the token
// layer.
//
// rfc-req: RFC7516-S5_2-R05
// SHOULD — "Even if a JWE can be successfully decrypted, unless the algorithms
// used in the JWE are acceptable to the application, it SHOULD consider the JWE
// to be invalid."
//
// should_policy: strict — asserted, not logged. Which algorithms are acceptable
// is the application's decision, as the sentence says, so what is tested is that
// the mechanism exists and bites: a token whose key would unwrap it is still
// refused when its "alg" is outside the configured set.
func TestUnacceptableAlgorithmsMakeAJWEInvalid(t *testing.T) {
	key := jwk.NewKey(
		wrappingKey(),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)

	keySet := jwk.NewKeySet(key)

	token, err := jwt.NewToken(jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), key))
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	t.Run("permitted", func(t *testing.T) {
		read, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(t.Context(), keySet, jwt.DefaultDecryptionConfig); err != nil {
			t.Errorf("the default configuration refused a token it implements: %v", err)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		read, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		config := jwt.NewDecryptionConfig(jwt.WithKeyManagementAlgorithms(jwa.A256KW()))

		if err := read.Decrypt(t.Context(), keySet, config); !errors.Is(err, jwt.ErrForbiddenKeyManagement) {
			t.Errorf("got %v, want ErrForbiddenKeyManagement", err)
		}
	})
}

// TestCompactSerializationGrammar checks the five-part concatenation of §7.1.
//
// rfc-req: RFC7516-S7_1-R01
// MUST (no BCP 14 keyword; see the IR) — "BASE64URL(UTF8(JWE Protected Header))
// || '.' || BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization
// Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE
// Authentication Tag)."
//
// The sentence carries no keyword. It is asserted anyway because it is the wire
// format: an implementation ordering the parts differently would be unreadable by
// every other, and RFC 8174 §2 notes plainly that normative text need not use the
// keywords.
func TestCompactSerializationGrammar(t *testing.T) {
	encrypted := message(t)

	compact, err := encrypted.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("got %d parts, want 5", len(parts))
	}

	for i, want := range [][]byte{
		nil,
		encrypted.Recipients[0].EncryptedKey,
		encrypted.InitializationVector,
		encrypted.Ciphertext,
		encrypted.AuthenticationTag,
	} {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Errorf("part %d is not unpadded base64url: %v", i, err)

			continue
		}

		if want != nil && !bytes.Equal(decoded, want) {
			t.Errorf("part %d holds %x, want %x", i, decoded, want)
		}
	}

	if encoded, _ := encrypted.ProtectedHeader.Marshal(); parts[0] != encoded {
		t.Errorf("part 0 is %q, want the encoded protected header %q", parts[0], encoded)
	}

	for _, count := range []int{2, 3, 4, 6} {
		malformed := strings.Join(slices.Repeat([]string{"AAAA"}, count), ".")

		if _, err := jwe.Unmarshal(malformed); !errors.Is(err, jwe.ErrMalformedMessage) {
			t.Errorf("%d parts gave %v, want ErrMalformedMessage", count, err)
		}
	}
}

// TestCompactSerializationRefusesWhatItCannotCarry checks that values the compact
// form has no room for are refused rather than dropped.
//
// rfc-req: RFC7516-S7_1-R02
// MUST (no BCP 14 keyword; see the IR) — "Only one recipient is supported by the
// JWE Compact Serialization and it provides no syntax to represent JWE Shared
// Unprotected Header, JWE Per-Recipient Unprotected Header, or JWE AAD values."
//
// Refusing rather than dropping is the point: a compact serialization written
// without the aad would produce a different Additional Authenticated Data on the
// way back and fail the tag check, reporting a cryptographic failure for what was
// a serialization mistake.
func TestCompactSerializationRefusesWhatItCannotCarry(t *testing.T) {
	for name, spoil := range map[string]func(*testing.T, *jwe.Message){
		"a second recipient": func(t *testing.T, m *jwe.Message) {
			t.Helper()

			second := &jwe.Message{ProtectedHeader: &header.Header{
				Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
			}}
			if err := second.EncryptTo(
				[]byte(plaintext),
				jwe.RecipientKey{Key: wrappingKey()},
				jwe.RecipientKey{Key: bytes.Repeat([]byte{9}, 16)},
			); err != nil {
				t.Fatalf("cannot encrypt to two: %v", err)
			}

			m.Recipients = second.Recipients
		},
		"a shared unprotected header": func(_ *testing.T, m *jwe.Message) {
			m.SharedHeader = &header.Header{KeyID: "shared"}
		},
		"a per-recipient header": func(_ *testing.T, m *jwe.Message) {
			m.Recipients[0].Header = &header.Header{KeyID: "mine"}
		},
		"an aad": func(_ *testing.T, m *jwe.Message) {
			m.AdditionalAuthenticatedData = []byte("extra")
		},
	} {
		t.Run(name, func(t *testing.T) {
			encrypted := message(t)
			spoil(t, encrypted)

			if _, err := encrypted.Marshal(); !errors.Is(err, jwe.ErrMalformedMessage) {
				t.Errorf("got %v, want ErrMalformedMessage", err)
			}
		})
	}
}

// TestJSONMembersCarryTheEncodedValues checks each member's encoding.
//
// rfc-req: RFC7516-S7_2_1-R01a
// rfc-req: RFC7516-S7_2_1-R03a
// rfc-req: RFC7516-S7_2_1-R04a
// rfc-req: RFC7516-S7_2_1-R06a
// rfc-req: RFC7516-S7_2_1-R10a
// MUST — each of "protected", "iv", "aad", "tag" and "encrypted_key" "MUST be
// present and contain the value BASE64URL(...) when the ... value is non-empty".
//
// Decoding the document back and decrypting is what makes this more than a string
// comparison: the value has to be the right one, not merely present.
func TestJSONMembersCarryTheEncodedValues(t *testing.T) {
	encrypted := message(t)
	encrypted.AdditionalAuthenticatedData = []byte("authenticated but not encrypted")

	encrypted.ProtectedHeader = &header.Header{Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM()}
	if err := encrypted.Encrypt([]byte(plaintext), wrappingKey()); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	present := members(t, encrypted)

	encodedProtectedHeader, err := encrypted.ProtectedHeader.Marshal()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	for _, member := range []struct {
		name string
		want string
	}{
		{"protected", encodedProtectedHeader},
		{"encrypted_key", base64.RawURLEncoding.EncodeToString(encrypted.Recipients[0].EncryptedKey)},
		{"iv", base64.RawURLEncoding.EncodeToString(encrypted.InitializationVector)},
		{"aad", base64.RawURLEncoding.EncodeToString(encrypted.AdditionalAuthenticatedData)},
		{"tag", base64.RawURLEncoding.EncodeToString(encrypted.AuthenticationTag)},
	} {
		raw, ok := present[member.name]
		if !ok {
			t.Errorf("%q is absent", member.name)

			continue
		}

		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("%q is not a string: %v", member.name, err)

			continue
		}

		if got != member.want {
			t.Errorf("%q is %q, want %q", member.name, got, member.want)
		}
	}

	decoded := new(jwe.Message)
	if err := json.Unmarshal([]byte(`{}`), decoded); err != nil {
		t.Fatalf("cannot decode an empty object: %v", err)
	}

	encoded, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("cannot round trip: %v", err)
	}

	recovered, err := decoded.Decrypt(wrappingKey())
	if err != nil {
		t.Fatalf("cannot decrypt after a round trip: %v", err)
	}

	if string(recovered) != plaintext {
		t.Errorf("got %q, want %q", recovered, plaintext)
	}
}

// TestUnprotectedHeadersAreUnencodedJSONObjects checks that the two unprotected
// headers are carried as objects rather than as base64url strings.
//
// rfc-req: RFC7516-S7_2_1-R02a
// rfc-req: RFC7516-S7_2_1-R09a
// MUST — "This value is represented as an unencoded JSON object, rather than as
// a string."
//
// The asymmetry with "protected" is the whole distinction between the two kinds
// of header: the protected one is a string because its exact octets are the
// Additional Authenticated Data, and the unprotected ones are objects because
// nothing depends on how they were spelled.
func TestUnprotectedHeadersAreUnencodedJSONObjects(t *testing.T) {
	encrypted := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
	}}

	err := encrypted.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Header: &header.Header{KeyID: "first"}, Key: wrappingKey()},
		jwe.RecipientKey{Header: &header.Header{KeyID: "second"}, Key: bytes.Repeat([]byte{9}, 16)},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	encrypted.SharedHeader = &header.Header{Type: "JWT"}

	present := members(t, encrypted)

	var shared map[string]jsontext.Value
	if err := json.Unmarshal(present["unprotected"], &shared); err != nil {
		t.Errorf(`"unprotected" is not a JSON object: %v`, err)
	}

	var recipients []map[string]jsontext.Value
	if err := json.Unmarshal(present["recipients"], &recipients); err != nil {
		t.Fatalf(`"recipients" is not an array of objects: %v`, err)
	}

	for i, recipient := range recipients {
		var perRecipient map[string]jsontext.Value
		if err := json.Unmarshal(recipient["header"], &perRecipient); err != nil {
			t.Errorf(`recipient %d: "header" is not a JSON object: %v`, i, err)
		}
	}

	var protectedHeader string
	if err := json.Unmarshal(present["protected"], &protectedHeader); err != nil {
		t.Errorf(`"protected" is not a string: %v`, err)
	}
}

// TestOptionalMembersAreAbsentRatherThanEmpty checks the second half of each
// member's rule.
//
// MUST — "otherwise, it MUST be absent."
//
// Absent-versus-empty is not a nicety. For "aad" the two differ in the Additional
// Authenticated Data computation — absent leaves it as the protected header
// alone, present appends a full stop even when empty — so a producer writing an
// empty member would change the tag.
//
// rfc-req: RFC7516-S7_2_1-R01b
// rfc-req: RFC7516-S7_2_1-R02b
// rfc-req: RFC7516-S7_2_1-R03b
// rfc-req: RFC7516-S7_2_1-R04b
// rfc-req: RFC7516-S7_2_1-R06b
// rfc-req: RFC7516-S7_2_1-R09b
// rfc-req: RFC7516-S7_2_1-R10b
func TestOptionalMembersAreAbsentRatherThanEmpty(t *testing.T) {
	present := members(t, message(t))

	for _, name := range []string{"unprotected", "header", "aad"} {
		if raw, ok := present[name]; ok {
			t.Errorf("%q is present as %s when its value is empty", name, raw)
		}
	}

	encrypted := message(t)
	encrypted.Recipients[0].Header = new(header.Header)

	if raw, ok := members(t, encrypted)["header"]; ok {
		t.Errorf("an empty per-recipient header was written as %s", raw)
	}
}

// TestCiphertextIsAlwaysPresent checks the one member with no absent-when-empty
// rule.
//
// rfc-req: RFC7516-S7_2_1-R05
// MUST — "The 'ciphertext' member MUST be present and contain the value
// BASE64URL(JWE Ciphertext)."
//
// Unconditionally, which is what distinguishes it from "iv", "aad" and "tag".
// Asserted by encrypting the empty plaintext under A128GCM, where the ciphertext
// genuinely is zero octets and an omitempty tag would have dropped it.
func TestCiphertextIsAlwaysPresent(t *testing.T) {
	encrypted := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
	}}
	if err := encrypted.Encrypt(nil, wrappingKey()); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	if len(encrypted.Ciphertext) != 0 {
		t.Fatalf("the empty plaintext gave a %d-octet ciphertext; the test proves nothing", len(encrypted.Ciphertext))
	}

	raw, ok := members(t, encrypted)["ciphertext"]
	if !ok {
		t.Fatal(`"ciphertext" is absent for an empty plaintext`)
	}

	if string(raw) != `""` {
		t.Errorf(`"ciphertext" is %s, want ""`, raw)
	}
}

// TestRecipientsIsAnArrayOfObjects checks the shape of the recipients member.
//
// rfc-req: RFC7516-S7_2_1-R07
// MUST — "The 'recipients' member value MUST be an array of JSON objects."
//
// rfc-req: RFC7516-S7_2_1-R08
// MUST — "This member MUST be present with exactly one array element per
// recipient, even if some or all of the array element values are the empty JSON
// object '{}'."
//
// The count is asserted rather than mere non-emptiness: a write path that
// overwrote its accumulator instead of appending yields a length of one and a
// message the second party cannot read.
func TestRecipientsIsAnArrayOfObjects(t *testing.T) {
	encrypted := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
	}}

	err := encrypted.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Key: wrappingKey()},
		jwe.RecipientKey{Key: bytes.Repeat([]byte{9}, 16)},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	var recipients []map[string]jsontext.Value
	if err := json.Unmarshal(members(t, encrypted)["recipients"], &recipients); err != nil {
		t.Fatalf("not an array of objects: %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("got %d elements, want one per recipient (2)", len(recipients))
	}

	for _, malformed := range []string{
		`{"protected":"e30","recipients":"a string","ciphertext":""}`,
		`{"protected":"e30","recipients":["a string"],"ciphertext":""}`,
		`{"protected":"e30","recipients":42,"ciphertext":""}`,
	} {
		if err := json.Unmarshal([]byte(malformed), new(jwe.Message)); err == nil {
			t.Errorf("accepted a malformed recipients member: %s", malformed)
		}
	}
}

// TestARecipientNeedsBothAlgorithms checks that a recipient computation whose
// algorithms cannot be resolved is refused.
//
// rfc-req: RFC7516-S7_2_1-R11
// MUST — "At least one of the 'header', 'protected', and 'unprotected' members
// MUST be present so that 'alg' and 'enc' Header Parameter values are conveyed
// for each recipient computation."
//
// A per-recipient "alg" is honoured when the protected header names none, which
// is the case this sentence exists for. "enc" is read from the protected header
// alone — see TestEncOutsideTheProtectedHeaderIsRefused — so this module is
// stricter than the sentence permits, which is recorded rather than hidden.
func TestARecipientNeedsBothAlgorithms(t *testing.T) {
	t.Run("a per-recipient alg is honoured", func(t *testing.T) {
		first, second := wrappingKey(), bytes.Repeat([]byte{9}, 32)

		encrypted := &jwe.Message{ProtectedHeader: &header.Header{EncryptionAlgorithm: jwa.A128GCM()}}

		err := encrypted.EncryptTo(
			[]byte(plaintext),
			jwe.RecipientKey{Header: &header.Header{Algorithm: jwa.A128KW()}, Key: first},
			jwe.RecipientKey{Header: &header.Header{Algorithm: jwa.A256KW()}, Key: second},
		)
		if err != nil {
			t.Fatalf("cannot encrypt: %v", err)
		}

		for i, key := range [][]byte{first, second} {
			recovered, err := encrypted.Decrypt(key)
			if err != nil {
				t.Errorf("recipient %d: %v", i, err)

				continue
			}

			if string(recovered) != plaintext {
				t.Errorf("recipient %d: got %q, want %q", i, recovered, plaintext)
			}
		}
	})

	t.Run("no alg anywhere is refused", func(t *testing.T) {
		encrypted := &jwe.Message{ProtectedHeader: &header.Header{EncryptionAlgorithm: jwa.A128GCM()}}

		err := encrypted.EncryptTo([]byte(plaintext), jwe.RecipientKey{Key: wrappingKey()})
		if !errors.Is(err, jwe.ErrMalformedMessage) {
			t.Errorf("got %v, want ErrMalformedMessage", err)
		}
	})
}

// TestUnknownMembersAreIgnored checks the extensibility rule.
//
// rfc-req: RFC7516-S7_2_1-R12
// MUST — "Additional members can be present in both the JSON objects defined
// above; if not understood by implementations encountering them, they MUST be
// ignored."
//
// This is what lets a newer implementation talk to an older one. Note it applies
// to the serialization's members, not to the JOSE Header, where "crit" governs
// instead.
func TestUnknownMembersAreIgnored(t *testing.T) {
	encrypted := message(t)

	document := members(t, encrypted)
	document["extension"] = jsontext.Value(`"a value from the future"`)

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("cannot re-encode: %v", err)
	}

	decoded := new(jwe.Message)
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("an unknown top-level member was not ignored: %v", err)
	}

	recovered, err := decoded.Decrypt(wrappingKey())
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if string(recovered) != plaintext {
		t.Errorf("got %q, want %q", recovered, plaintext)
	}
}

// TestOneCiphertextServesEveryRecipient checks that the parameters governing the
// plaintext are shared.
//
// rfc-req: RFC7516-S7_2_1-R14
// MUST — "all Header Parameters that specify the treatment of the plaintext
// value MUST be the same for all recipients."
//
// jwe.Message holds exactly one IV, ciphertext and tag, so the structure cannot
// express per-recipient values; what is asserted is that the write path does not
// defeat that. Verified by mutation: drawing a fresh CEK inside the per-recipient
// loop leaves the first recipient working and is caught by the second's
// decryption.
func TestOneCiphertextServesEveryRecipient(t *testing.T) {
	one := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
	}}
	if err := one.Encrypt([]byte(plaintext), wrappingKey()); err != nil {
		t.Fatalf("cannot encrypt to one: %v", err)
	}

	two := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
	}}
	if err := two.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Key: wrappingKey()},
		jwe.RecipientKey{Key: bytes.Repeat([]byte{9}, 16)},
	); err != nil {
		t.Fatalf("cannot encrypt to two: %v", err)
	}

	if len(one.Ciphertext) != len(two.Ciphertext) {
		t.Errorf(
			"a second recipient changed the ciphertext length: %d to %d",
			len(one.Ciphertext), len(two.Ciphertext),
		)
	}

	for i, key := range [][]byte{wrappingKey(), bytes.Repeat([]byte{9}, 16)} {
		recovered, err := two.Decrypt(key)
		if err != nil {
			t.Errorf("recipient %d: %v", i, err)

			continue
		}

		if string(recovered) != plaintext {
			t.Errorf("recipient %d: got %q, want %q", i, recovered, plaintext)
		}
	}
}

// TestEncOutsideTheProtectedHeaderIsRefused checks that the content encryption
// algorithm cannot differ between recipients, nor be rewritten in transit.
//
// rfc-req: RFC7516-S7_2_1-R15
// MUST — "This primarily means that the 'enc' (encryption algorithm) Header
// Parameter value in the JOSE Header for each recipient and any parameters of
// that algorithm MUST be the same."
//
// Assumption, labelled: this module is stricter than the RFC, which would allow
// "enc" in any of the three headers. Outside the protected header it is outside
// the Additional Authenticated Data, so a man in the middle could rewrite it to a
// weaker algorithm — the algorithm confusion of RFC 8725 §3.1. Reading it from
// the shared, integrity-protected header makes sameness hold by construction
// rather than by a check that could be skipped. It is why RFC 7520 §5.11–§5.13
// are excluded from conformance/rfc7520.
func TestEncOutsideTheProtectedHeaderIsRefused(t *testing.T) {
	for name, place := range map[string]func(*jwe.Message, *header.Header){
		"shared":        func(m *jwe.Message, h *header.Header) { m.SharedHeader = h },
		"per-recipient": func(m *jwe.Message, h *header.Header) { m.Recipients[0].Header = h },
	} {
		t.Run(name, func(t *testing.T) {
			encrypted := message(t)
			place(encrypted, &header.Header{EncryptionAlgorithm: jwa.A256GCM()})

			if _, err := encrypted.Decrypt(wrappingKey()); !errors.Is(err, jwe.ErrMalformedMessage) {
				t.Errorf("got %v, want ErrMalformedMessage", err)
			}
		})
	}
}

// TestFlattenedSyntaxHasNoRecipientsMember checks that the two JSON syntaxes are
// not mixed.
//
// rfc-req: RFC7516-S7_2_2-R01
// MUST — "The 'recipients' member MUST NOT be present when using this syntax."
//
// Both directions: this module writes the flattened form for a single recipient
// and refuses to read a document claiming both shapes, which has no defined
// meaning.
func TestFlattenedSyntaxHasNoRecipientsMember(t *testing.T) {
	present := members(t, message(t))

	if _, ok := present["recipients"]; ok {
		t.Error(`the flattened form carried a "recipients" member`)
	}

	if _, ok := present["encrypted_key"]; !ok {
		t.Error(`the flattened form did not hoist "encrypted_key"`)
	}

	both := `{"protected":"e30","recipients":[{"encrypted_key":"AAAA"}],"encrypted_key":"AAAA","ciphertext":""}`
	if err := json.Unmarshal([]byte(both), new(jwe.Message)); !errors.Is(err, jwe.ErrMalformedMessage) {
		t.Errorf("got %v, want ErrMalformedMessage", err)
	}
}

// TestSegmentCountDistinguishesJWSFromJWE checks the first of §9's three rules.
//
// rfc-req: RFC7516-S9-R01
// MUST (no BCP 14 keyword; see the IR) — "JWSs have three segments separated by
// two period ('.') characters.  JWEs have five segments separated by four period
// ('.') characters."
//
// This is the first decision made about untrusted input and everything downstream
// depends on it, so the near misses are asserted too.
func TestSegmentCountDistinguishesJWSFromJWE(t *testing.T) {
	signed, err := signedToken(t).Marshal()
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if got := strings.Count(signed, "."); got != 2 {
		t.Errorf("a JWS has %d full stops, want 2", got)
	}

	encrypted, err := encryptedToken(t).Marshal()
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	if got := strings.Count(encrypted, "."); got != 4 {
		t.Errorf("a JWE has %d full stops, want 4", got)
	}

	for _, encoded := range []string{signed, encrypted} {
		if _, err := jwt.Unmarshal(encoded); err != nil {
			t.Errorf("cannot read %q: %v", encoded[:16], err)
		}
	}

	for _, count := range []int{2, 4, 6} {
		malformed := strings.Join(slices.Repeat([]string{"e30"}, count), ".")

		if _, err := jwt.Unmarshal(malformed); err == nil {
			t.Errorf("%d segments was accepted", count)
		}
	}
}

// TestJSONMembersDistinguishJWSFromJWE checks the second of §9's three rules.
//
// rfc-req: RFC7516-S9-R02
// MUST (no BCP 14 keyword; see the IR) — "JWSs have a 'payload' member and JWEs
// do not.  JWEs have a 'ciphertext' member and JWSs do not."
//
// Asserted as a property of the two encoders rather than against a fixture, so it
// stays true as members are added.
func TestJSONMembersDistinguishJWSFromJWE(t *testing.T) {
	for _, shape := range []struct {
		name           string
		token          *jwt.Token
		present, empty string
	}{
		{"JWS", signedToken(t), "payload", "ciphertext"},
		{"JWE", encryptedToken(t), "ciphertext", "payload"},
	} {
		t.Run(shape.name, func(t *testing.T) {
			encoded, err := json.Marshal(shape.token)
			if err != nil {
				t.Fatalf("cannot marshal: %v", err)
			}

			var document map[string]jsontext.Value
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatalf("cannot decode: %v", err)
			}

			if _, ok := document[shape.present]; !ok {
				t.Errorf("no %q member", shape.present)
			}

			if _, ok := document[shape.empty]; ok {
				t.Errorf("carries a %q member, which belongs to the other kind", shape.empty)
			}
		})
	}
}

// TestTheAlgValueDistinguishesJWSFromJWE checks the third of §9's rules, on the
// header itself.
//
// rfc-req: RFC7516-S9-R03a
// MUST (no BCP 14 keyword; see the IR) — "If the value represents a digital
// signature or MAC algorithm, or is the value 'none', it is for a JWS; if it
// represents a Key Encryption, Key Wrapping, Direct Key Agreement, Key Agreement
// with Key Wrapping, or Direct Encryption algorithm, it is for a JWE."
//
// jwa keeps one name registry, since the IANA JWS and JWE alg names are disjoint;
// what separates their uses is the interface each caller asserts. Both directions
// are checked, since a registry shared between two uses is exactly the arrangement
// in which one of them silently accepting the other's names would go unnoticed.
func TestTheAlgValueDistinguishesJWSFromJWE(t *testing.T) {
	t.Run("a key management algorithm is not a JWS alg", func(t *testing.T) {
		signingKey := jwk.NewKey(
			bytes.Repeat([]byte{1}, 32),
			jwk.WithPublicKeyUse(jwk.Signature),
			jwk.WithOperations(jwk.Sign, jwk.Verify),
		)

		encoded, err := signedToken(t).Marshal()
		if err != nil {
			t.Fatalf("cannot build a token: %v", err)
		}

		forged := strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP"}`)),
			strings.Split(encoded, ".")[1],
			"AAAA",
		}, ".")

		read, err := jwt.Unmarshal(forged)
		if err != nil {
			t.Fatalf("cannot read the forged token: %v", err)
		}

		err = read.Verify(t.Context(), jwk.NewKeySet(signingKey), jwt.DefaultVerificationConfig)
		if !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
			t.Errorf("got %v, want ErrForbiddenAlgorithm", err)
		}
	})

	t.Run("a signature algorithm is not a JWE alg", func(t *testing.T) {
		encrypted := &jwe.Message{ProtectedHeader: &header.Header{
			Algorithm: jwa.ES256(), EncryptionAlgorithm: jwa.A128GCM(),
		}}

		if err := encrypted.Encrypt([]byte(plaintext), wrappingKey()); !errors.Is(
			err, jwa.ErrUnsupportedAlgorithm,
		) {
			t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

// TestTheEncMemberDistinguishesJWSFromJWE checks §9's fourth rule and, more
// importantly, what happens when the rules disagree.
//
// MUST (no BCP 14 keyword; see the IR) — "If the 'enc' member exists, it is a
// JWE; otherwise, it is a JWS."
//
// The two disagreement cases are asserted where they actually fail rather than
// where it would be tidier:
//
//   - A three-part token whose protected header carries "enc" fails at
//     jwt.Unmarshal with jws.ErrEncryptionAlgorithm. This was a real gap found
//     while writing this suite. Before the check was added, such a token parsed
//     as a JWS and its signature verified normally, so a relying party using the
//     segment-count rule would have trusted content a relying party using the
//     enc-member rule would have tried to decrypt.
//   - A five-part token naming no "enc" parses — the claims are unavailable until
//     a key arrives, so nothing is decided yet — and fails at Decrypt. Later, but
//     not weaker: no claim is readable and no plaintext emitted in between.
//
// Refusing rather than resolving is the point. The section's own caveat
// anticipates the case, and picking a winner would let a producer choose which
// rule a given consumer applied.
//
// rfc-req: RFC7516-S9-R03b
func TestTheEncMemberDistinguishesJWSFromJWE(t *testing.T) {
	t.Run("three parts carrying enc", func(t *testing.T) {
		forged := strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","enc":"A128GCM"}`)),
			base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
			"AAAA",
		}, ".")

		if _, err := jwt.Unmarshal(forged); !errors.Is(err, jws.ErrEncryptionAlgorithm) {
			t.Errorf("got %v, want ErrEncryptionAlgorithm", err)
		}
	})

	t.Run("five parts carrying no enc", func(t *testing.T) {
		forged := strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"A128KW"}`)),
			"AAAA", "AAAA", "AAAA", "AAAA",
		}, ".")

		read, err := jwt.Unmarshal(forged)
		if err != nil {
			t.Fatalf("cannot read the forged token: %v", err)
		}

		key := jwk.NewKey(
			wrappingKey(),
			jwk.WithPublicKeyUse(jwk.Encryption),
			jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
		)

		if err := read.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig); err == nil {
			t.Error("a five-part token naming no enc decrypted")
		}

		if issuer := read.Issuer(); issuer != "" {
			t.Errorf("a claim was readable before decryption: iss=%q", issuer)
		}
	})
}

// TestRSA1_5IsNoDecryptionOracle checks the countermeasure RFC 7516 §11.4 asks
// for, in place of the position this test used to record.
//
// MUST (no BCP 14 keyword; the sentence says "particularly important") — "It is
// therefore particularly important to report all formatting errors to the CEK,
// Additional Authenticated Data, or ciphertext as a single error when the
// encrypted content is rejected."
//
// The single-error rule is asserted by TestFailuresAreIndistinguishable. What
// this test covers is the attack the paragraph names: rewriting "alg" from
// "RSA-OAEP" to "RSA1_5" to turn the recipient into an oracle that recovers the
// CEK of a message RSAES-OAEP protected.
//
// RSA1_5 was unimplemented when this suite was written, so the rewrite failed
// before any key was touched and the attack was unreachable by construction.
// RSA1_5 decrypts here now, and three separate things close the attack instead.
// They are asserted in the order an attacker meets them.
//
// First, jwa.RSAESPKCS1v15.DecryptKey reports no formatting error at all. It
// draws a random CEK of the length the "enc" algorithm needs and lets the unwrap
// overwrite it only when the padding is correct — which is §11.5's own strongly
// recommended countermeasure, the one TestFailuresAreIndistinguishable records
// this module as not taking elsewhere. The rewritten token therefore fails as
// jwa.ErrDecryptionFailed at the tag check, exactly as a tampered ciphertext
// does, and the attacker learns nothing about the padding.
//
// Second, "alg" here is in the JWE Protected Header, which is the Additional
// Authenticated Data. Rewriting it is tampering with the AAD, so the tag would
// not verify even if the unwrap had succeeded.
//
// Third, the paragraph's own further countermeasure — restricting a key to a
// limited set of algorithms, usually one — is what jwk.Key's alg and key_ops
// members do and what DecryptionConfig's allowlists do at the token layer; see
// TestUnacceptableAlgorithmsMakeAJWEInvalid. RSA1_5 is not among the algorithms
// jwt.DefaultDecryptionConfig accepts, so a token naming it is refused before any
// key is touched unless a caller asks for it by name.
//
// rfc-req: RFC7516-S11_4-R01
func TestRSA1_5IsNoDecryptionOracle(t *testing.T) {
	encrypted := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: jwa.RSAOAEP256(), EncryptionAlgorithm: jwa.A128GCM()},
	}

	if err := encrypted.Encrypt([]byte(plaintext), &rsaKey.PublicKey); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	compact, err := encrypted.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	parts := strings.Split(compact, ".")

	rewrittenHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}

	rewrittenHeader = bytes.Replace(rewrittenHeader, []byte(`"RSA-OAEP-256"`), []byte(`"RSA1_5"`), 1)
	if !bytes.Contains(rewrittenHeader, []byte(`"RSA1_5"`)) {
		t.Fatalf("the alg was not where it was expected: %s", rewrittenHeader)
	}

	parts[0] = base64.RawURLEncoding.EncodeToString(rewrittenHeader)

	rewritten, err := jwe.Unmarshal(strings.Join(parts, "."))
	if err != nil {
		t.Fatalf("cannot parse the rewritten token: %v", err)
	}

	_, rewrittenErr := rewritten.Decrypt(rsaKey)
	if !errors.Is(rewrittenErr, jwa.ErrDecryptionFailed) {
		t.Errorf("got %v, want ErrDecryptionFailed", rewrittenErr)
	}

	tampered, err := jwe.Unmarshal(compact)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	tampered.Ciphertext[0] ^= 1

	_, tamperedErr := tampered.Decrypt(rsaKey)
	if tamperedErr == nil || rewrittenErr == nil || tamperedErr.Error() != rewrittenErr.Error() {
		t.Errorf("a rewritten alg gives %v and a tampered ciphertext gives %v", rewrittenErr, tamperedErr)
	}

	t.Run("DefaultConfiguration", func(t *testing.T) {
		key := jwk.NewKey(
			rsaKey,
			jwk.WithPublicKeyUse(jwk.Encryption),
			jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
		)

		read, err := jwt.Unmarshal(strings.Join(parts, "."))
		if err != nil {
			t.Fatalf("cannot read: %v", err)
		}

		if err := read.Decrypt(
			t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig,
		); !errors.Is(err, jwt.ErrForbiddenKeyManagement) {
			t.Errorf("got %v, want ErrForbiddenKeyManagement", err)
		}
	})
}

// TestFailuresAreIndistinguishable checks the single-error rule.
//
// MUST — "To mitigate the attacks described in RFC 3218, the recipient MUST NOT
// distinguish between format, padding, and length errors of encrypted keys."
//
// Every failure that depends on the token returns exactly jwa.ErrDecryptionFailed
// and nothing more specific. The boundary is deliberate and is stated rather than
// left implicit: failures that depend on the recipient's own key instead of on
// the token — ErrInvalidKeyType, ErrInvalidKeySize, ErrWeakKey — stay distinct,
// and only when a single recipient makes attribution unambiguous. An attacker
// chooses none of those, and answering a caller's own mistake with "decryption
// failed" would trade a real diagnostic for no security.
//
// Assumption, labelled: §11.5's second sentence — substitute a randomly generated
// CEK and proceed — is implemented for RSA1_5 alone, where the Bleichenbacher
// attack it exists for applies; see TestRSA1_5SubstitutesARandomKey. Every other
// key management algorithm returns early instead, which leaves a timing
// difference between a key that unwraps and one that does not. The sentence calls
// the substitution strongly recommended rather than required, and a timing
// assertion in a Go test would be measuring the scheduler, so the remaining gap is
// recorded rather than closed.
//
// rfc-req: RFC7516-S11_5-R01
func TestFailuresAreIndistinguishable(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{
		jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
		jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
	} {
		t.Run(encryption.String(), func(t *testing.T) {
			for name, tamper := range map[string]func(*jwe.Message){
				"format: the encrypted key": func(m *jwe.Message) { m.Recipients[0].EncryptedKey[0] ^= 1 },
				"length: the encrypted key": func(m *jwe.Message) { m.Recipients[0].EncryptedKey = []byte{1, 2, 3} },
				"padding: the ciphertext":   func(m *jwe.Message) { m.Ciphertext[len(m.Ciphertext)-1] ^= 1 },
				"the initialization vector": func(m *jwe.Message) { m.InitializationVector[0] ^= 1 },
				"the authentication tag":    func(m *jwe.Message) { m.AuthenticationTag[0] ^= 1 },
				"length: the ciphertext":    func(m *jwe.Message) { m.Ciphertext = m.Ciphertext[:len(m.Ciphertext)/2] },
			} {
				t.Run(name, func(t *testing.T) {
					encrypted := &jwe.Message{ProtectedHeader: &header.Header{
						Algorithm: jwa.A128KW(), EncryptionAlgorithm: encryption,
					}}
					if err := encrypted.Encrypt([]byte(plaintext), wrappingKey()); err != nil {
						t.Fatalf("cannot encrypt: %v", err)
					}

					tamper(encrypted)

					_, err := encrypted.Decrypt(wrappingKey())
					if !errors.Is(err, jwa.ErrDecryptionFailed) {
						t.Errorf("got %v, want exactly ErrDecryptionFailed", err)
					}
				})
			}
		})
	}
}

// TestRSA1_5SubstitutesARandomKey checks §11.5's second sentence where it
// matters most.
//
// rfc-req: RFC7516-S11_5-R01
// SHOULD — "It is strongly recommended, in the event of receiving an improperly
// formatted key, that the recipient substitute a randomly generated CEK and
// proceed to the next step, to mitigate timing attacks."
//
// should_policy: strict — asserted, not logged, for the one algorithm the
// sentence is written about. RFC 3218, which §11.5 cites, is a document about
// PKCS #1 v1.5 alone.
//
// jwa.RSAESPKCS1v15.DecryptKey draws a CEK of the length the "enc" algorithm
// needs and lets crypto/rsa overwrite it only when the padding is correct, so an
// improperly formatted key is not an error and not a shorter code path. It is a
// CEK the attacker cannot predict, and the failure surfaces one step later at the
// tag check as jwa.ErrDecryptionFailed — which is what
// TestRSA1_5IsNoDecryptionOracle asserts from the message layer.
//
// Two properties are asserted here that the message layer cannot show. Two
// different encrypted keys give two different CEKs, and one encrypted key gives a
// different CEK each time. A substituted key that was predictable, cached or
// derived from the ciphertext would be one an attacker could tell from a real
// one, which is the "static or random key" leak the standard library documents as
// defeating the mitigation.
func TestRSA1_5SubstitutesARandomKey(t *testing.T) {
	encryption := jwa.A128GCM()

	cek := func(encryptedKey []byte) []byte {
		t.Helper()

		substituted, err := jwa.RSA15().DecryptKey(encryptedKey, rsaKey, encryption, new(jwa.KeyParameters))
		if err != nil {
			t.Fatalf("an improperly formatted key was reported as an error: %v", err)
		}

		if len(substituted) != encryption.KeySize() {
			t.Fatalf("got a %d-octet CEK, want %d", len(substituted), encryption.KeySize())
		}

		return substituted
	}

	first := make([]byte, rsaKey.Size())

	second := make([]byte, rsaKey.Size())
	second[len(second)-1] = 1

	if bytes.Equal(cek(first), cek(second)) {
		t.Error("two improperly formatted keys gave one CEK; the substitution is derived from the ciphertext")
	}

	if bytes.Equal(cek(first), cek(first)) {
		t.Error("one improperly formatted key gave one CEK twice; the substitution is not fresh")
	}

	tooLarge := bytes.Repeat([]byte{0xff}, rsaKey.Size())

	if _, err := jwa.RSA15().DecryptKey(
		tooLarge, rsaKey, encryption, new(jwa.KeyParameters),
	); !errors.Is(err, jwa.ErrDecryptionFailed) {
		t.Errorf("got %v, want ErrDecryptionFailed", err)
	}
}

// TestEveryOctetOfTheTagIsCompared checks that the tag comparison covers the
// whole tag.
//
// rfc-req: RFC7516-S11_5-R01
// MUST — the same sentence. A comparison checking only a prefix would be caught
// by a flip at octet zero and by nothing else, while leaving a forgery within
// reach of far less work than the tag's length suggests.
func TestEveryOctetOfTheTagIsCompared(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{jwa.A128CBCHS256(), jwa.A128GCM()} {
		t.Run(encryption.String(), func(t *testing.T) {
			encrypted := &jwe.Message{ProtectedHeader: &header.Header{
				Algorithm: jwa.A128KW(), EncryptionAlgorithm: encryption,
			}}
			if err := encrypted.Encrypt([]byte(plaintext), wrappingKey()); err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			original := slices.Clone(encrypted.AuthenticationTag)

			for i := range original {
				encrypted.AuthenticationTag = slices.Clone(original)
				encrypted.AuthenticationTag[i] ^= 1

				if _, err := encrypted.Decrypt(wrappingKey()); !errors.Is(err, jwa.ErrDecryptionFailed) {
					t.Errorf("octet %d: got %v, want ErrDecryptionFailed", i, err)
				}
			}
		})
	}
}

func signedToken(t *testing.T) *jwt.Token {
	t.Helper()

	key := jwk.NewKey(
		bytes.Repeat([]byte{1}, 32),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
	)

	token, err := jwt.NewToken(jwt.WithSignature(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("cannot build a signed token: %v", err)
	}

	return token
}

func encryptedToken(t *testing.T) *jwt.Token {
	t.Helper()

	key := jwk.NewKey(
		wrappingKey(),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)

	token, err := jwt.NewToken(jwt.WithEncryption(jwa.A128KW(), jwa.A128GCM(), key))
	if err != nil {
		t.Fatalf("cannot build an encrypted token: %v", err)
	}

	return token
}

type keyPairing struct {
	algorithm     jwa.KeyEncrypter
	encryptionKey any
}

func keyManagement(t *testing.T, encryption jwa.ContentEncrypter) []keyPairing {
	t.Helper()

	symmetric := func(algorithm jwa.KeyEncrypter, size int) keyPairing {
		return keyPairing{algorithm, bytes.Repeat([]byte{7}, size)}
	}

	pairings := []keyPairing{
		{jwa.Dir(), bytes.Repeat([]byte{7}, encryption.KeySize())},
		symmetric(jwa.A128KW(), 16),
		symmetric(jwa.A192KW(), 24),
		symmetric(jwa.A256KW(), 32),
		symmetric(jwa.A128GCMKW(), 16),
		symmetric(jwa.A192GCMKW(), 24),
		symmetric(jwa.A256GCMKW(), 32),
	}

	password := []byte("entrap o'er the arm the wily bird")
	for _, passwordBased := range []jwa.KeyEncrypter{
		jwa.PBES2HS256A128KW(), jwa.PBES2HS384A192KW(), jwa.PBES2HS512A256KW(),
	} {
		pairings = append(pairings, keyPairing{passwordBased, password})
	}

	for _, agreement := range []jwa.KeyEncrypter{
		jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	} {
		pairings = append(pairings, keyPairing{agreement, &agreementKey.PublicKey})
	}

	for _, rsaAlgorithm := range []jwa.KeyEncrypter{jwa.RSAOAEP(), jwa.RSAOAEP256()} {
		pairings = append(pairings, keyPairing{rsaAlgorithm, &rsaKey.PublicKey})
	}

	return pairings
}

var (
	agreementKey *ecdsa.PrivateKey
	rsaKey       *rsa.PrivateKey
)

func init() {
	var err error

	if agreementKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}

	if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
}
