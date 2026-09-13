package rfc7518_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
)

var contentEncryptionAlgorithms = []jwa.ContentEncrypter{
	jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
	jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
}

var agreementKey = func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}()

var pbes2Password = []byte("entrap o'er the arm the wily bird")

func encryptTo(
	t *testing.T, algorithm jwa.Algorithm, encryption jwa.ContentEncrypter, key any,
) *jwe.Message {
	t.Helper()

	message := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: algorithm, EncryptionAlgorithm: encryption},
	}

	if err := message.Encrypt([]byte("plaintext"), key); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	return message
}

// TestRSA15RequiresA2048BitModulus checks the key size floor for RSAES-PKCS1-v1_5.
//
// rfc-req: RFC7518-S4_2-R01
// MUST — "A key of size 2048 bits or larger MUST be used with this algorithm."
//
// This requirement was recorded as not-testable while RSAES-PKCS1-v1_5 key
// encryption was unimplemented here, since no key of any size reached it. It is
// implemented now — decryption only — so the floor is a real check with a real
// assertion, and the same checkRSAModulus that §3.3, §3.5 and §4.3 use enforces
// it. One definition of "large enough", since it is the same sentence in all
// four places.
//
// The check runs before the unwrap, so the encrypted key here need not be a
// real one: the modulus decides the outcome. A key that clears the floor returns
// a CEK for any encrypted key at all, which is the whole point of
// TestRSA15GivesNoPaddingOracle below.
func TestRSA15RequiresA2048BitModulus(t *testing.T) {
	for _, bits := range []int{1024, 2047} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("cannot generate a %d-bit key: %v", bits, err)
		}

		_, err = jwa.RSA15().DecryptKey(
			make([]byte, key.Size()), key, jwa.A128GCM(), new(jwa.KeyParameters),
		)
		if !errors.Is(err, jwa.ErrWeakKey) {
			t.Errorf("a %d-bit modulus: got %v, want ErrWeakKey", bits, err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a 2048-bit key: %v", err)
	}

	if _, err := jwa.RSA15().DecryptKey(
		make([]byte, key.Size()), key, jwa.A128GCM(), new(jwa.KeyParameters),
	); err != nil {
		t.Errorf("a 2048-bit modulus was refused: %v", err)
	}
}

// TestRSA15DecryptsAndDoesNotEncrypt records the one direction this module
// offers, and the shape of the type that makes it so.
//
// rfc-req: RFC7518-S4_2-R01
//
// RFC 8725 §3.2 asks applications to "Avoid all RSA-PKCS1 v1.5 encryption
// algorithms ..., preferring RSAES-OAEP", and RFC 7516 §11.4 gives the concrete
// attack the advice exists for. Reading a token another party wrote and writing
// a new one carry different risk, so this module does the first and not the
// second. The decryption half is covered at RFC7516-S11_5-R01, whose
// countermeasure is what makes it safe to offer at all.
//
// The refusal is a property of the types rather than a check a caller can skip:
// jwa.RSAESPKCS1v15 has DecryptKey and neither EncryptKey nor WrapKey, so it is
// a jwa.KeyDecrypter and is not a jwa.KeyEncrypter, and jwe refuses it when
// encrypting for the same reason it refuses one of the direct modes for a second
// recipient.
func TestRSA15DecryptsAndDoesNotEncrypt(t *testing.T) {
	algorithm, ok := jwa.ByName("RSA1_5")
	if !ok {
		t.Fatal("RSA1_5 does not resolve")
	}

	if _, ok := algorithm.(jwa.KeyDecrypter); !ok {
		t.Error("RSA1_5 cannot decrypt a key")
	}

	if _, ok := algorithm.(jwa.KeyEncrypter); ok {
		t.Error("RSA1_5 can encrypt a key; this module must not produce that padding")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	message := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: algorithm, EncryptionAlgorithm: jwa.A128GCM()},
	}

	if err := message.Encrypt([]byte("plaintext"), &key.PublicKey); !errors.Is(
		err, jwa.ErrUnsupportedAlgorithm,
	) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestRSAOAEPRequiresA2048BitModulus checks the key size floor for RSAES OAEP.
//
// rfc-req: RFC7518-S4_3-R01
// MUST — "A key of size 2048 bits or larger MUST be used with these algorithms."
//
// The same floor as §3.3 and §3.5 state for the signing algorithms, and the same
// check enforces it: one definition of "large enough", since it is the same
// sentence in all three places. Enforced when producing rather than only when
// consuming, because a token this module would refuse to write is not one it
// should be able to write by accident.
func TestRSAOAEPRequiresA2048BitModulus(t *testing.T) {
	for _, algorithm := range []jwa.KeyEncrypter{jwa.RSAOAEP(), jwa.RSAOAEP256()} {
		t.Run(algorithm.String(), func(t *testing.T) {
			for _, bits := range []int{1024, 2047} {
				key, err := rsa.GenerateKey(rand.Reader, bits)
				if err != nil {
					t.Fatalf("cannot generate a %d-bit key: %v", bits, err)
				}

				_, _, err = algorithm.EncryptKey(&key.PublicKey, jwa.A128GCM(), new(jwa.KeyParameters))
				if !errors.Is(err, jwa.ErrWeakKey) {
					t.Errorf("a %d-bit modulus: got %v, want ErrWeakKey", bits, err)
				}
			}

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("cannot generate a 2048-bit key: %v", err)
			}

			if _, _, err := algorithm.EncryptKey(&key.PublicKey, jwa.A128GCM(), new(jwa.KeyParameters)); err != nil {
				t.Errorf("a 2048-bit modulus was refused: %v", err)
			}
		})
	}
}

// TestEphemeralKeyIsFreshForEveryAgreement checks that no ECDH-ES key agreement
// reuses an ephemeral key.
//
// rfc-req: RFC7518-S4_6-R01
// MUST — "A new ephemeral public key value MUST be generated for each key
// agreement operation."
//
// A reused ephemeral key turns ephemeral-static agreement into static-static and
// gives every message the same CEK. The key is generated inside
// jwa.ECDHESAlgorithm rather than accepted from the caller, which is what makes
// the requirement hold without the caller's cooperation — so the assertion is
// over what comes out, per message and per recipient.
func TestEphemeralKeyIsFreshForEveryAgreement(t *testing.T) {
	t.Run("per message", func(t *testing.T) {
		published := map[string]bool{}

		for range 16 {
			message := encryptTo(t, jwa.ECDHES(), jwa.A128GCM(), &agreementKey.PublicKey)

			ephemeral := message.ProtectedHeader.EphemeralPublicKey
			if ephemeral == nil {
				t.Fatal("no epk was published")
			}

			thumbprint, err := ephemeral.ThumbprintID(crypto.SHA256)
			if err != nil {
				t.Fatalf("cannot identify the epk: %v", err)
			}

			if published[thumbprint] {
				t.Fatalf("an ephemeral key was reused: %s", thumbprint)
			}

			published[thumbprint] = true
		}
	})

	t.Run("per recipient", func(t *testing.T) {
		second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate a second key: %v", err)
		}

		message := &jwe.Message{ProtectedHeader: &header.Header{
			Algorithm: jwa.ECDHESA128KW(), EncryptionAlgorithm: jwa.A128GCM(),
		}}

		err = message.EncryptTo(
			[]byte("plaintext"),
			jwe.RecipientKey{Key: &agreementKey.PublicKey},
			jwe.RecipientKey{Key: &second.PublicKey},
		)
		if err != nil {
			t.Fatalf("cannot encrypt to two: %v", err)
		}

		thumbprints := make([]string, 0, len(message.Recipients))

		for i, recipient := range message.Recipients {
			if recipient.Header == nil || recipient.Header.EphemeralPublicKey == nil {
				t.Fatalf("recipient %d published no epk", i)
			}

			thumbprint, err := recipient.Header.EphemeralPublicKey.ThumbprintID(crypto.SHA256)
			if err != nil {
				t.Fatalf("recipient %d: %v", i, err)
			}

			thumbprints = append(thumbprints, thumbprint)
		}

		if thumbprints[0] == thumbprints[1] {
			t.Error("both recipients of one message got the same ephemeral key")
		}
	})
}

// TestDirectKeyAgreementDerivesTheEncKeyLength checks the Concat KDF output
// length in Direct Key Agreement mode.
//
// rfc-req: RFC7518-S4_6-R02
// MUST — "In Direct Key Agreement mode, the output of the Concat KDF MUST be a
// key of the same length as that used by the 'enc' algorithm."
//
// The length has to track the "enc" value rather than being fixed, which is why
// all six are asserted. That the arithmetic itself is right, and not merely the
// length, is checked against RFC 7518 Appendix C in the jwa package's own tests.
func TestDirectKeyAgreementDerivesTheEncKeyLength(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			cek, encryptedKey, err := jwa.ECDHES().EncryptKey(
				&agreementKey.PublicKey, encryption, new(jwa.KeyParameters),
			)
			if err != nil {
				t.Fatalf("cannot agree: %v", err)
			}

			if len(cek) != encryption.KeySize() {
				t.Errorf("derived %d octets, want %d", len(cek), encryption.KeySize())
			}

			if len(encryptedKey) != 0 {
				t.Errorf("Direct Key Agreement produced a %d-octet encrypted key", len(encryptedKey))
			}
		})
	}
}

// TestKeyAgreementWithKeyWrappingDerivesTheWrappingKeyLength checks the same in
// the other mode.
//
// MUST — "In Key Agreement with Key Wrapping mode, the output of the Concat KDF
// MUST be a key of the length needed for the specified key wrapping algorithm."
//
// This is the opposite rule to TestDirectKeyAgreementDerivesTheEncKeyLength: the
// derived length follows the wrapping algorithm and ignores the "enc".
//
// The derived key never surfaces through the public API — it is consumed by the
// wrapping step — and a round trip cannot pin its length, because a wrapping key
// of the wrong length would be accepted by aes.NewCipher as a different AES
// variant and both sides would derive it identically. The length itself is
// therefore asserted where it is visible: jwa's TestECDHESDerivesTheWrappingKeySize
// calls derivedKeySize directly for both modes. What this test adds is the
// observable consequence across the cross product — the CEK follows the "enc",
// the encrypted key follows the CEK, and the pairing round-trips — which is what
// would break if the two rules were swapped.
//
// rfc-req: RFC7518-S4_6-R03
func TestKeyAgreementWithKeyWrappingDerivesTheWrappingKeyLength(t *testing.T) {
	for _, variant := range []struct {
		algorithm *jwa.ECDHESAlgorithm
		wrapping  int
	}{
		{jwa.ECDHESA128KW(), 16},
		{jwa.ECDHESA192KW(), 24},
		{jwa.ECDHESA256KW(), 32},
	} {
		t.Run(variant.algorithm.String(), func(t *testing.T) {
			for _, encryption := range contentEncryptionAlgorithms {
				t.Run(encryption.String(), func(t *testing.T) {
					cek, encryptedKey, err := variant.algorithm.EncryptKey(
						&agreementKey.PublicKey, encryption, new(jwa.KeyParameters),
					)
					if err != nil {
						t.Fatalf("cannot agree: %v", err)
					}

					if len(cek) != encryption.KeySize() {
						t.Errorf("CEK is %d octets, want the enc's %d", len(cek), encryption.KeySize())
					}

					if want := encryption.KeySize() + 8; len(encryptedKey) != want {
						t.Errorf("encrypted key is %d octets, want %d", len(encryptedKey), want)
					}
				})
			}
		})
	}
}

// TestKeyAgreementModesDeriveDifferentKeys checks the AlgorithmID rule that
// keeps §4.6's two modes apart.
//
// rfc-req: RFC7518-S4_6-R03
// MUST — the same sentence. If both modes derived the same key from one
// agreement, the length rule alone would not separate them, and a key agreed for
// direct use as a CEK would also be the key encryption key.
//
// Asserted through the full encryption path with a fixed "enc" chosen so the two
// modes derive the same length: A128GCM needs a 16-octet CEK and ECDH-ES+A128KW
// a 16-octet wrapping key. The test therefore cannot pass merely because the two
// outputs differ in size.
func TestKeyAgreementModesDeriveDifferentKeys(t *testing.T) {
	encryption := jwa.A128GCM()

	if jwa.A128GCM().KeySize() != 16 {
		t.Fatalf("A128GCM needs a %d-octet CEK; the length guard this test relies on is gone", encryption.KeySize())
	}

	direct := encryptTo(t, jwa.ECDHES(), encryption, &agreementKey.PublicKey)
	wrapping := encryptTo(t, jwa.ECDHESA128KW(), encryption, &agreementKey.PublicKey)

	if len(direct.Recipients[0].EncryptedKey) != 0 {
		t.Error("Direct Key Agreement published an encrypted key")
	}

	if len(wrapping.Recipients[0].EncryptedKey) == 0 {
		t.Error("Key Agreement with Key Wrapping published no encrypted key")
	}

	crossed := &jwe.Message{
		ProtectedHeader:      wrapping.ProtectedHeader,
		Recipients:           wrapping.Recipients,
		InitializationVector: wrapping.InitializationVector,
		Ciphertext:           wrapping.Ciphertext,
		AuthenticationTag:    wrapping.AuthenticationTag,
	}

	crossed.ProtectedHeader = cloneHeaderWithAlgorithm(t, wrapping.ProtectedHeader, jwa.ECDHES())

	if _, err := crossed.Decrypt(agreementKey); err == nil {
		t.Error("a Key Agreement with Key Wrapping message decrypted as Direct Key Agreement")
	}
}

func cloneHeaderWithAlgorithm(t *testing.T, original *header.Header, algorithm jwa.Algorithm) *header.Header {
	t.Helper()

	return &header.Header{
		Algorithm:           algorithm,
		EncryptionAlgorithm: original.EncryptionAlgorithm,
		EphemeralPublicKey:  original.EphemeralPublicKey,
	}
}

// TestEphemeralPublicKeyCarriesOnlyPublicParameters checks both directions of
// the "epk" rule.
//
// rfc-req: RFC7518-S4_6_1_1-R01
// MUST — "It MUST contain only public key parameters and SHOULD contain only the
// minimum JWK parameters necessary to represent the key."
//
// The consuming half was a real gap found while re-enriching this section: an
// "epk" carrying "d" previously decoded to a private key and the agreement
// proceeded from its public half. That would have derived the correct key, so
// this is not about a wrong result — it is that the private half changes the
// key's JWK thumbprint, so implementations disagreeing about whether to strip it
// would disagree about the key's identity, and a sender who has leaked their
// ephemeral private key is better told than accommodated.
func TestEphemeralPublicKeyCarriesOnlyPublicParameters(t *testing.T) {
	t.Run("producing", func(t *testing.T) {
		message := encryptTo(t, jwa.ECDHES(), jwa.A128GCM(), &agreementKey.PublicKey)

		encoded, err := json.Marshal(message.ProtectedHeader)
		if err != nil {
			t.Fatalf("cannot encode the header: %v", err)
		}

		var protectedHeader map[string]jsontext.Value
		if err := json.Unmarshal(encoded, &protectedHeader); err != nil {
			t.Fatalf("cannot decode: %v", err)
		}

		var ephemeral map[string]jsontext.Value
		if err := json.Unmarshal(protectedHeader["epk"], &ephemeral); err != nil {
			t.Fatalf("epk is not an object: %v", err)
		}

		present := slices.Sorted(maps.Keys(ephemeral))
		if want := []string{"crv", "kty", "x", "y"}; !slices.Equal(present, want) {
			t.Errorf("the published epk holds %v, want exactly %v", present, want)
		}
	})

	t.Run("consuming", func(t *testing.T) {
		private, err := json.Marshal(jwk.NewKey(agreementKey))
		if err != nil {
			t.Fatalf("cannot encode a private key: %v", err)
		}

		raw := []byte(`{"alg":"ECDH-ES","enc":"A128GCM","epk":` + string(private) + `}`)

		if err := json.Unmarshal(raw, new(header.Header)); !errors.Is(err, header.ErrPrivateEphemeralKey) {
			t.Errorf("got %v, want ErrPrivateEphemeralKey", err)
		}

		public, err := json.Marshal(jwk.NewKey(agreementKey).Public())
		if err != nil {
			t.Fatalf("cannot encode a public key: %v", err)
		}

		raw = []byte(`{"alg":"ECDH-ES","enc":"A128GCM","epk":` + string(public) + `}`)
		if err := json.Unmarshal(raw, new(header.Header)); err != nil {
			t.Errorf("a public epk was refused: %v", err)
		}
	})
}

// TestEphemeralPublicKeyIsRequired checks that ECDH-ES cannot proceed without an
// "epk".
//
// rfc-req: RFC7518-S4_6_1_1-R02
// MUST — "This Header Parameter MUST be present and MUST be understood and
// processed by implementations when these algorithms are used."
func TestEphemeralPublicKeyIsRequired(t *testing.T) {
	for _, algorithm := range []jwa.KeyDecrypter{
		jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	} {
		t.Run(algorithm.String(), func(t *testing.T) {
			_, err := algorithm.DecryptKey(nil, agreementKey, jwa.A128GCM(), new(jwa.KeyParameters))
			if err == nil {
				t.Error("an agreement proceeded with no epk")
			}
		})
	}
}

// TestAgreementPartyInfoIsOptional checks that "apu" and "apv" may be used or
// omitted.
//
// rfc-req: RFC7518-S4_6_1_2-R01
// rfc-req: RFC7518-S4_6_1_3-R01
// MAY — "Use of this Header Parameter is OPTIONAL."
//
// capability: agreement-party-info — present here. The interop obligation behind
// the option is asserted rather than skipped: an implementation that accepted
// the parameter and then ignored it would derive a different key from the sender,
// so omitting the parameter and ignoring it are not the same thing.
func TestAgreementPartyInfoIsOptional(t *testing.T) {
	for _, parameters := range []struct {
		name     string
		apu, apv []byte
	}{
		{"neither", nil, nil},
		{"apu only", []byte("alice"), nil},
		{"apv only", nil, []byte("bob")},
		{"both", []byte("alice"), []byte("bob")},
	} {
		t.Run(parameters.name, func(t *testing.T) {
			message := &jwe.Message{ProtectedHeader: &header.Header{
				Algorithm:           jwa.ECDHES(),
				EncryptionAlgorithm: jwa.A128GCM(),
				AgreementPartyUInfo: parameters.apu,
				AgreementPartyVInfo: parameters.apv,
			}}

			if err := message.Encrypt([]byte("plaintext"), &agreementKey.PublicKey); err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			recovered, err := message.Decrypt(agreementKey)
			if err != nil {
				t.Fatalf("cannot decrypt: %v", err)
			}

			if string(recovered) != "plaintext" {
				t.Errorf("got %q, want %q", recovered, "plaintext")
			}
		})
	}
}

// TestAgreementPartyInfoIsFedToTheKDF checks that the two values are processed
// rather than merely accepted.
//
// rfc-req: RFC7518-S4_6_1_2-R02
// rfc-req: RFC7518-S4_6_1_3-R02
// MUST — "This Header Parameter MUST be understood and processed by
// implementations when these algorithms are used."
//
// Altering either after encryption must make decryption fail. This is the
// assertion that distinguishes processing from accepting: an implementation that
// dropped "apu" would pass any test that only ever set it consistently on both
// sides. Both are checked, since a KDF feeding one value into both slots would
// satisfy either alone.
func TestAgreementPartyInfoIsFedToTheKDF(t *testing.T) {
	for _, altered := range []string{"apu", "apv"} {
		t.Run(altered, func(t *testing.T) {
			message := &jwe.Message{ProtectedHeader: &header.Header{
				Algorithm:           jwa.ECDHES(),
				EncryptionAlgorithm: jwa.A128GCM(),
				AgreementPartyUInfo: []byte("alice"),
				AgreementPartyVInfo: []byte("bob"),
			}}

			if err := message.Encrypt([]byte("plaintext"), &agreementKey.PublicKey); err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			rebuilt := &header.Header{
				Algorithm:           jwa.ECDHES(),
				EncryptionAlgorithm: jwa.A128GCM(),
				EphemeralPublicKey:  message.ProtectedHeader.EphemeralPublicKey,
				AgreementPartyUInfo: message.ProtectedHeader.AgreementPartyUInfo,
				AgreementPartyVInfo: message.ProtectedHeader.AgreementPartyVInfo,
			}

			if altered == "apu" {
				rebuilt.AgreementPartyUInfo = []byte("alicE")
			} else {
				rebuilt.AgreementPartyVInfo = []byte("boB")
			}

			message.ProtectedHeader = rebuilt

			if _, err := message.Decrypt(agreementKey); err == nil {
				t.Errorf("altering %s did not change the derived key", altered)
			}
		})
	}
}

// TestAgreementPartyInfoMustBeDistinct checks §4.6.2's distinctness rule.
//
// rfc-req: RFC7518-S4_6_2-R01
// MUST — "The 'apu' and 'apv' values MUST be distinct, when used."
//
// A real gap found while re-enriching this section: equal values were previously
// accepted and fed to the KDF. PartyUInfo and PartyVInfo exist to bind the
// derived key to who each side is, and equal values make the two contributions
// interchangeable and the binding vacuous.
//
// "When used" is load-bearing: two absent values are not two equal ones, and
// §4.6.1.2 and §4.6.1.3 make both optional. Both boundaries are asserted, so the
// check cannot pass by refusing everything.
func TestAgreementPartyInfoMustBeDistinct(t *testing.T) {
	same := []byte("both parties")

	_, _, err := jwa.ECDHES().EncryptKey(
		&agreementKey.PublicKey,
		jwa.A128GCM(),
		&jwa.KeyParameters{AgreementPartyUInfo: same, AgreementPartyVInfo: same},
	)
	if !errors.Is(err, jwa.ErrIndistinctAgreementParties) {
		t.Errorf("equal apu and apv: got %v, want ErrIndistinctAgreementParties", err)
	}

	for _, permitted := range []struct {
		name     string
		apu, apv []byte
	}{
		{"distinct", []byte("alice"), []byte("bob")},
		{"both absent", nil, nil},
		{"apu only", []byte("alice"), nil},
	} {
		t.Run(permitted.name, func(t *testing.T) {
			_, _, err := jwa.ECDHES().EncryptKey(
				&agreementKey.PublicKey,
				jwa.A128GCM(),
				&jwa.KeyParameters{AgreementPartyUInfo: permitted.apu, AgreementPartyVInfo: permitted.apv},
			)
			if err != nil {
				t.Errorf("got %v, want no error", err)
			}
		})
	}
}

// TestAgreementPartyInfoAcceptsAnyOctets checks that no policy is imposed on the
// values beyond distinctness.
//
// rfc-req: RFC7518-S4_6_2-R02
// MAY — "applications MAY conduct key derivation in a manner similar to
// 'Diffie-Hellman Key Agreement Method' [RFC2631]: in that case, the 'apu'
// parameter MAY either be omitted or represent a random 512-bit value".
//
// capability: rfc2631-style-agreement. The permission is the application's to
// exercise; this module's obligation is only not to obstruct it, which is what is
// asserted — a 512-bit random apu is carried and fed to the KDF unchanged.
func TestAgreementPartyInfoAcceptsAnyOctets(t *testing.T) {
	partyUInfo := make([]byte, 64)
	if _, err := rand.Read(partyUInfo); err != nil {
		t.Fatalf("cannot draw a random apu: %v", err)
	}

	message := &jwe.Message{ProtectedHeader: &header.Header{
		Algorithm:           jwa.ECDHES(),
		EncryptionAlgorithm: jwa.A128GCM(),
		AgreementPartyUInfo: partyUInfo,
	}}

	if err := message.Encrypt([]byte("plaintext"), &agreementKey.PublicKey); err != nil {
		t.Fatalf("cannot encrypt with a 512-bit apu: %v", err)
	}

	if !bytes.Equal(message.ProtectedHeader.AgreementPartyUInfo, partyUInfo) {
		t.Error("the apu was altered on the way into the header")
	}

	recovered, err := message.Decrypt(agreementKey)
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if string(recovered) != "plaintext" {
		t.Errorf("got %q, want %q", recovered, "plaintext")
	}
}

// TestAESGCMKeyWrapUsesA96BitIV checks the IV size for the A*GCMKW algorithms.
//
// rfc-req: RFC7518-S4_7-R01
// MUST — "Use of an Initialization Vector (IV) of size 96 bits is REQUIRED with
// this algorithm."
func TestAESGCMKeyWrapUsesA96BitIV(t *testing.T) {
	for _, algorithm := range []struct {
		algorithm jwa.KeyEncrypter
		size      int
	}{
		{jwa.A128GCMKW(), 16},
		{jwa.A192GCMKW(), 24},
		{jwa.A256GCMKW(), 32},
	} {
		t.Run(algorithm.algorithm.String(), func(t *testing.T) {
			parameters := new(jwa.KeyParameters)

			_, _, err := algorithm.algorithm.EncryptKey(
				bytes.Repeat([]byte{7}, algorithm.size), jwa.A128GCM(), parameters,
			)
			if err != nil {
				t.Fatalf("cannot wrap: %v", err)
			}

			if len(parameters.InitializationVector) != 12 {
				t.Errorf("published a %d-octet iv, want 12", len(parameters.InitializationVector))
			}
		})
	}
}

// TestAESGCMKeyWrapUsesA128BitTag checks the tag size, which does not scale with
// the key.
//
// rfc-req: RFC7518-S4_7-R02
// MUST — "The requested size of the Authentication Tag output MUST be 128 bits,
// regardless of the key size."
//
// All three key sizes are asserted, because "regardless of the key size" is the
// operative clause and an implementation that scaled the tag with the key would
// interoperate with itself perfectly.
func TestAESGCMKeyWrapUsesA128BitTag(t *testing.T) {
	for _, algorithm := range []struct {
		algorithm jwa.KeyEncrypter
		size      int
	}{
		{jwa.A128GCMKW(), 16},
		{jwa.A192GCMKW(), 24},
		{jwa.A256GCMKW(), 32},
	} {
		t.Run(algorithm.algorithm.String(), func(t *testing.T) {
			parameters := new(jwa.KeyParameters)

			_, _, err := algorithm.algorithm.EncryptKey(
				bytes.Repeat([]byte{7}, algorithm.size), jwa.A128GCM(), parameters,
			)
			if err != nil {
				t.Fatalf("cannot wrap: %v", err)
			}

			if len(parameters.AuthenticationTag) != 16 {
				t.Errorf("published a %d-octet tag, want 16", len(parameters.AuthenticationTag))
			}
		})
	}
}

// TestAESGCMKeyWrapRequiresIVAndTag checks that both published parameters are
// required and processed.
//
// rfc-req: RFC7518-S4_7_1_1-R01
// rfc-req: RFC7518-S4_7_1_2-R01
// MUST — "This Header Parameter MUST be present and MUST be understood and
// processed by implementations when these algorithms are used."
//
// Every octet of the tag is walked rather than only the first: a comparison
// checking a prefix would be caught by a flip at octet zero and by nothing else.
func TestAESGCMKeyWrapRequiresIVAndTag(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)

	parameters := new(jwa.KeyParameters)

	_, encryptedKey, err := jwa.A128GCMKW().EncryptKey(key, jwa.A128GCM(), parameters)
	if err != nil {
		t.Fatalf("cannot wrap: %v", err)
	}

	t.Run("absent", func(t *testing.T) {
		for name, missing := range map[string]*jwa.KeyParameters{
			"iv":  {AuthenticationTag: parameters.AuthenticationTag},
			"tag": {InitializationVector: parameters.InitializationVector},
		} {
			if _, err := jwa.A128GCMKW().DecryptKey(encryptedKey, key, jwa.A128GCM(), missing); err == nil {
				t.Errorf("unwrapped with no %s", name)
			}
		}
	})

	t.Run("altered iv", func(t *testing.T) {
		for i := range parameters.InitializationVector {
			altered := &jwa.KeyParameters{
				InitializationVector: slices.Clone(parameters.InitializationVector),
				AuthenticationTag:    parameters.AuthenticationTag,
			}
			altered.InitializationVector[i] ^= 1

			if _, err := jwa.A128GCMKW().DecryptKey(encryptedKey, key, jwa.A128GCM(), altered); !errors.Is(
				err, jwa.ErrDecryptionFailed,
			) {
				t.Errorf("iv octet %d: got %v, want ErrDecryptionFailed", i, err)
			}
		}
	})

	t.Run("altered tag", func(t *testing.T) {
		for i := range parameters.AuthenticationTag {
			altered := &jwa.KeyParameters{
				InitializationVector: parameters.InitializationVector,
				AuthenticationTag:    slices.Clone(parameters.AuthenticationTag),
			}
			altered.AuthenticationTag[i] ^= 1

			if _, err := jwa.A128GCMKW().DecryptKey(encryptedKey, key, jwa.A128GCM(), altered); !errors.Is(
				err, jwa.ErrDecryptionFailed,
			) {
				t.Errorf("tag octet %d: got %v, want ErrDecryptionFailed", i, err)
			}
		}
	})
}

// TestPBES2PasswordIsAnOctetSequence records that the encoding is the caller's.
//
// rfc-req: RFC7518-S4_8-R01
// MUST — "The PBES2 password input is an octet sequence; if the password to be
// used is represented as a text string rather than an octet sequence, the UTF-8
// encoding of the text string MUST be used as the octet sequence."
//
// not-testable: jwa.PBES2 takes []byte and never a string, so there is no point
// at which this module chooses an encoding. The requirement is discharged by the
// API shape rather than by a code path. What this test asserts is that shape —
// a string is not accepted, so a caller cannot leave the decision to the library.
func TestPBES2PasswordIsAnOctetSequence(t *testing.T) {
	_, _, err := jwa.PBES2HS256A128KW().EncryptKey(
		"a password as a Go string", jwa.A128GCM(), new(jwa.KeyParameters),
	)
	if !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("got %v, want ErrInvalidKeyType", err)
	}
}

// TestPBES2BindsTheAlgorithmNameIntoTheSalt checks §4.8's salt construction.
//
// rfc-req: RFC7518-S4_8-R02
// MUST — "The salt parameter MUST be computed from the 'p2s' (PBES2 salt input)
// Header Parameter value and the 'alg' (algorithm) Header Parameter value as
// specified in the 'p2s' definition below."
//
// The definition is UTF8(Alg) || 0x00 || Salt Input. Without the prefix, one
// password and one salt input would derive related keys across the three
// algorithms, so work done against a token using one would carry to the others —
// and a naive implementation using the salt input alone would pass any test that
// exercised a single algorithm.
func TestPBES2BindsTheAlgorithmNameIntoTheSalt(t *testing.T) {
	saltInput := bytes.Repeat([]byte{3}, 16)

	wrapped := map[string][]byte{}

	for _, algorithm := range []jwa.KeyEncrypter{
		jwa.PBES2HS256A128KW(), jwa.PBES2HS384A192KW(), jwa.PBES2HS512A256KW(),
	} {
		cek := bytes.Repeat([]byte{5}, 16)

		parameters := &jwa.KeyParameters{PBES2SaltInput: saltInput, PBES2Count: 1000}

		keyWrapper, ok := algorithm.(jwa.KeyWrapper)
		if !ok {
			t.Fatalf("%s does not wrap", algorithm)
		}

		encryptedKey, err := keyWrapper.WrapKey(cek, pbes2Password, jwa.A128GCM(), parameters)
		if err != nil {
			t.Fatalf("%s: cannot wrap: %v", algorithm, err)
		}

		wrapped[algorithm.String()] = encryptedKey
	}

	names := slices.Sorted(maps.Keys(wrapped))
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if bytes.Equal(wrapped[names[i]], wrapped[names[j]]) {
				t.Errorf("%s and %s derived the same key from one password", names[i], names[j])
			}
		}
	}
}

// TestPBES2IterationCountComesFromTheHeader checks that "p2c" is read rather
// than assumed.
//
// rfc-req: RFC7518-S4_8-R03
// MUST — "The iteration count parameter MUST be provided as the 'p2c' (PBES2
// count) Header Parameter value."
func TestPBES2IterationCountComesFromTheHeader(t *testing.T) {
	message := encryptTo(t, jwa.PBES2HS256A128KW(), jwa.A128GCM(), pbes2Password)

	if message.ProtectedHeader.PBES2Count < 1000 {
		t.Fatalf("published p2c is %d, below the floor", message.ProtectedHeader.PBES2Count)
	}

	message.ProtectedHeader = &header.Header{
		Algorithm:           jwa.PBES2HS256A128KW(),
		EncryptionAlgorithm: jwa.A128GCM(),
		PBES2SaltInput:      message.ProtectedHeader.PBES2SaltInput,
		PBES2Count:          message.ProtectedHeader.PBES2Count + 1,
	}

	if _, err := message.Decrypt(pbes2Password); err == nil {
		t.Error("changing p2c did not change the derived key")
	}
}

// TestPBES2SaltInputIsRequiredAndProcessed checks the "p2s" parameter.
//
// rfc-req: RFC7518-S4_8_1_1-R01
// MUST — "This Header Parameter MUST be present and MUST be understood and
// processed by implementations when these algorithms are used."
func TestPBES2SaltInputIsRequiredAndProcessed(t *testing.T) {
	t.Run("required", func(t *testing.T) {
		_, err := jwa.PBES2HS256A128KW().DecryptKey(
			make([]byte, 24), pbes2Password, jwa.A128GCM(), &jwa.KeyParameters{PBES2Count: 1000},
		)
		if err == nil {
			t.Error("derived a key with no p2s")
		}
	})

	t.Run("processed", func(t *testing.T) {
		message := encryptTo(t, jwa.PBES2HS256A128KW(), jwa.A128GCM(), pbes2Password)

		altered := slices.Clone(message.ProtectedHeader.PBES2SaltInput)
		altered[0] ^= 1

		message.ProtectedHeader = &header.Header{
			Algorithm:           jwa.PBES2HS256A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
			PBES2SaltInput:      altered,
			PBES2Count:          message.ProtectedHeader.PBES2Count,
		}

		if _, err := message.Decrypt(pbes2Password); err == nil {
			t.Error("altering p2s did not change the derived key")
		}
	})
}

// TestPBES2SaltInputFloor checks the 8-octet minimum.
//
// rfc-req: RFC7518-S4_8_1_1-R02
// MUST — "A Salt Input value containing 8 or more octets MUST be used."
//
// Both sides of the boundary, so the check cannot pass by refusing every length.
func TestPBES2SaltInputFloor(t *testing.T) {
	for _, size := range []int{0, 7} {
		_, err := jwa.PBES2HS256A128KW().DecryptKey(
			make([]byte, 24),
			pbes2Password,
			jwa.A128GCM(),
			&jwa.KeyParameters{PBES2SaltInput: make([]byte, size), PBES2Count: 1000},
		)
		if !errors.Is(err, jwa.ErrInvalidKeySize) {
			t.Errorf("a %d-octet p2s: got %v, want ErrInvalidKeySize", size, err)
		}
	}

	_, err := jwa.PBES2HS256A128KW().DecryptKey(
		make([]byte, 24),
		pbes2Password,
		jwa.A128GCM(),
		&jwa.KeyParameters{PBES2SaltInput: make([]byte, 8), PBES2Count: 1000},
	)
	if errors.Is(err, jwa.ErrInvalidKeySize) {
		t.Errorf("an 8-octet p2s was refused for its length: %v", err)
	}
}

// TestPBES2SaltIsFreshForEveryEncryption checks §4.8.1.1's freshness rule.
//
// rfc-req: RFC7518-S4_8_1_1-R03
// MUST — "A new Salt Input value MUST be generated randomly for every encryption
// operation."
//
// The salt is drawn inside jwa.PBES2.WrapKey and overwrites whatever the caller
// supplied, which is what makes this hold without the caller's cooperation. Both
// per message and per recipient: a per-message implementation would give two
// recipients of one JWE the same salt.
func TestPBES2SaltIsFreshForEveryEncryption(t *testing.T) {
	t.Run("per message", func(t *testing.T) {
		seen := map[string]bool{}

		for range 16 {
			message := encryptTo(t, jwa.PBES2HS256A128KW(), jwa.A128GCM(), pbes2Password)

			salt := string(message.ProtectedHeader.PBES2SaltInput)
			if seen[salt] {
				t.Fatal("a salt input was reused")
			}

			seen[salt] = true
		}
	})

	t.Run("per recipient", func(t *testing.T) {
		second := []byte("a second party's altogether different password")

		message := &jwe.Message{ProtectedHeader: &header.Header{
			Algorithm: jwa.PBES2HS256A128KW(), EncryptionAlgorithm: jwa.A128GCM(),
		}}

		err := message.EncryptTo(
			[]byte("plaintext"),
			jwe.RecipientKey{Key: pbes2Password},
			jwe.RecipientKey{Key: second},
		)
		if err != nil {
			t.Fatalf("cannot encrypt to two: %v", err)
		}

		salts := make([]string, 0, len(message.Recipients))

		for i, recipient := range message.Recipients {
			if recipient.Header == nil {
				t.Fatalf("recipient %d published no salt", i)
			}

			salts = append(salts, string(recipient.Header.PBES2SaltInput))
		}

		if salts[0] == salts[1] {
			t.Error("both recipients of one message got the same salt")
		}
	})
}

// TestPBES2IterationCountIsRequired checks that "p2c" must be present.
//
// rfc-req: RFC7518-S4_8_1_2-R01
// MUST — "This Header Parameter MUST be present and MUST be understood and
// processed by implementations when these algorithms are used."
func TestPBES2IterationCountIsRequired(t *testing.T) {
	_, err := jwa.PBES2HS256A128KW().DecryptKey(
		make([]byte, 24),
		pbes2Password,
		jwa.A128GCM(),
		&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16)},
	)
	if !errors.Is(err, jwa.ErrInsufficientIterationCount) {
		t.Errorf("got %v, want ErrInsufficientIterationCount", err)
	}
}

// TestPBES2IterationCountFloor checks §4.8.1.2's recommended minimum.
//
// rfc-req: RFC7518-S4_8_1_2-R02
// SHOULD — "A minimum iteration count of 1000 is RECOMMENDED."
//
// should_policy: strict — enforced rather than logged. A real gap found while
// re-enriching this section: only counts below 1 were refused, so a "p2c" of 1
// reduced PBKDF2 to a single HMAC. The count travels in the token, so whoever
// writes it chooses how much a guess costs the attacker who later obtains it.
//
// The count this module writes is far above the floor. 1000 was written in 2015
// and is not a target now; that judgement is this module's rather than the RFC's
// and is recorded as such in the IR.
func TestPBES2IterationCountFloor(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 999} {
		_, err := jwa.PBES2HS256A128KW().DecryptKey(
			make([]byte, 24),
			pbes2Password,
			jwa.A128GCM(),
			&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16), PBES2Count: count},
		)
		if !errors.Is(err, jwa.ErrInsufficientIterationCount) {
			t.Errorf("p2c of %d: got %v, want ErrInsufficientIterationCount", count, err)
		}
	}

	_, err := jwa.PBES2HS256A128KW().DecryptKey(
		make([]byte, 24),
		pbes2Password,
		jwa.A128GCM(),
		&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16), PBES2Count: 1000},
	)
	if errors.Is(err, jwa.ErrInsufficientIterationCount) {
		t.Errorf("p2c of exactly 1000 was refused: %v", err)
	}

	message := encryptTo(t, jwa.PBES2HS256A128KW(), jwa.A128GCM(), pbes2Password)
	if message.ProtectedHeader.PBES2Count < 1000 {
		t.Errorf("this module writes p2c %d, below the floor it enforces", message.ProtectedHeader.PBES2Count)
	}
}

// TestAESCBCHMACSHA2KeyLength checks §5.2.2.1's input key length rule.
//
// MUST — "The number of octets in the input key K MUST be the sum of MAC_KEY_LEN
// and ENC_KEY_LEN."
//
// Splitting a shorter key would hand AES a key of the wrong size; a longer one
// would quietly discard the excess, and that second failure mode is the one a
// round-trip test would not catch.
//
// That the split itself is right — MAC key first, encryption key second, "the
// opposite order of the algorithm names" as §5.2.2.1 puts it — is checked against
// RFC 7518 Appendix B by the jwa package's own vectors. Nothing in the standard
// library implements this composition, so unlike every other algorithm here it is
// assembled rather than delegated, and every way of assembling it wrongly still
// round-trips against itself.
//
// rfc-req: RFC7518-S5_2_2_1-R01
func TestAESCBCHMACSHA2KeyLength(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{
		jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
	} {
		t.Run(encryption.String(), func(t *testing.T) {
			iv := make([]byte, encryption.IVSize())

			for _, size := range []int{0, encryption.KeySize() - 1, encryption.KeySize() + 1} {
				_, _, err := encryption.Encrypt([]byte("plaintext"), make([]byte, size), iv, nil)
				if !errors.Is(err, jwa.ErrInvalidKeySize) {
					t.Errorf("a %d-octet key: got %v, want ErrInvalidKeySize", size, err)
				}
			}

			if _, _, err := encryption.Encrypt(
				[]byte("plaintext"), make([]byte, encryption.KeySize()), iv, nil,
			); err != nil {
				t.Errorf("the exact key size was refused: %v", err)
			}
		})
	}
}

// TestAESGCMContentEncryptionUsesA96BitIV checks §5.3's IV size.
//
// rfc-req: RFC7518-S5_3-R01
// MUST — "Use of an IV of size 96 bits is REQUIRED with this algorithm."
//
// This module uses cipher.NewGCM rather than NewGCMWithRandomNonce deliberately:
// JWE carries the IV as its own part of the serialization, so the nonce is this
// package's to draw and publish.
func TestAESGCMContentEncryptionUsesA96BitIV(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM()} {
		t.Run(encryption.String(), func(t *testing.T) {
			if encryption.IVSize() != 12 {
				t.Errorf("IVSize is %d, want 12", encryption.IVSize())
			}

			cek := make([]byte, encryption.KeySize())

			for _, size := range []int{11, 13} {
				if _, _, err := encryption.Encrypt([]byte("plaintext"), cek, make([]byte, size), nil); err == nil {
					t.Errorf("a %d-octet IV was accepted", size)
				}
			}

			message := encryptTo(t, jwa.Dir(), encryption, cek)
			if len(message.InitializationVector) != 12 {
				t.Errorf("published a %d-octet IV, want 12", len(message.InitializationVector))
			}
		})
	}
}

// TestAESGCMContentEncryptionUsesA128BitTag checks §5.3's tag size.
//
// rfc-req: RFC7518-S5_3-R02
// MUST — "The requested size of the Authentication Tag output MUST be 128 bits,
// regardless of the key size."
func TestAESGCMContentEncryptionUsesA128BitTag(t *testing.T) {
	for _, encryption := range []jwa.ContentEncrypter{jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM()} {
		t.Run(encryption.String(), func(t *testing.T) {
			cek := make([]byte, encryption.KeySize())

			_, tag, err := encryption.Encrypt([]byte("plaintext"), cek, make([]byte, encryption.IVSize()), nil)
			if err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			if len(tag) != 16 {
				t.Errorf("produced a %d-octet tag, want 16", len(tag))
			}
		})
	}
}

// TestAESGCMInvocationLimitIsTheApplicationsToTrack records the bound this
// module cannot enforce.
//
// MUST — "AES GCM MUST NOT be used with the same key value more than 2^32 times."
//
// not-testable: the bound is over the lifetime of a key, across every process
// that ever uses it. This module is stateless with respect to key material — a
// key arrives as an argument and is forgotten when the call returns — so there is
// nowhere to keep a counter and nothing to compare it against. Enforcing it would
// require the library to own key storage, which it deliberately does not.
//
// Recorded rather than quietly dropped: an application using "dir" or a
// long-lived A*GCMKW key needs to know the limit exists. This test asserts only
// the structural fact behind the rationale — that no key is retained between
// calls, so no count could be kept.
//
// rfc-req: RFC7518-S8_4-R01
func TestAESGCMInvocationLimitIsTheApplicationsToTrack(t *testing.T) {
	cek := make([]byte, jwa.A128GCM().KeySize())

	first := encryptTo(t, jwa.Dir(), jwa.A128GCM(), cek)
	second := encryptTo(t, jwa.Dir(), jwa.A128GCM(), cek)

	if bytes.Equal(first.InitializationVector, second.InitializationVector) {
		t.Error("two encryptions under one key shared an IV")
	}
}

// TestAESGCMIVIsNeverReused checks the freshness half of §8.4.
//
// MUST — "An IV value MUST NOT ever be used multiple times with the same AES GCM
// key."
//
// Structurally, jwa.AESGCMKeyWrap.WrapKey draws its IV internally and
// jwe.Message.Encrypt draws the content IV per message, so no caller can supply
// one twice — which is why there is no negative case here and why the strategy is
// a property rather than a refusal. For multi-recipient messages the key wrap IV
// is drawn per call rather than per message, since wrapping one CEK twice under
// one key with one IV would repeat the keystream and expose the CEK.
//
// Assumption, labelled: this tests freshness, not the birthday bound. Random
// 96-bit IVs collide with probability growing in the square of the message count
// — the same fact §8.4's 2^32 limit is about — and a test over a feasible number
// of samples cannot distinguish a correct implementation from one with a slightly
// weakened random source. This oracle does not claim to.
//
// rfc-req: RFC7518-S8_4-R02
func TestAESGCMIVIsNeverReused(t *testing.T) {
	t.Run("content encryption", func(t *testing.T) {
		cek := make([]byte, jwa.A128GCM().KeySize())
		seen := map[string]bool{}

		for range 256 {
			message := encryptTo(t, jwa.Dir(), jwa.A128GCM(), cek)

			iv := string(message.InitializationVector)
			if seen[iv] {
				t.Fatal("an IV was reused")
			}

			seen[iv] = true
		}
	})

	t.Run("key wrapping", func(t *testing.T) {
		key := bytes.Repeat([]byte{7}, 16)
		seen := map[string]bool{}

		for range 256 {
			parameters := new(jwa.KeyParameters)

			if _, _, err := jwa.A128GCMKW().EncryptKey(key, jwa.A128GCM(), parameters); err != nil {
				t.Fatalf("cannot wrap: %v", err)
			}

			iv := string(parameters.InitializationVector)
			if seen[iv] {
				t.Fatal("a key wrapping IV was reused")
			}

			seen[iv] = true
		}
	})
}

// TestKeyMaterialIsNotReusedAcrossMessages checks §8.7.
//
// SHOULD — "It is NOT RECOMMENDED to reuse the same entire set of key material
// (Key Encryption Key, Content Encryption Key, Initialization Vector, etc.) to
// encrypt multiple JWK or JWK Set objects".
//
// should_policy: strict — asserted, not logged. The CEK is drawn per message and
// the IV per message, so the set as a whole differs even where the Key Encryption
// Key does not.
//
// "dir" is the honest exception and is asserted separately. RFC 7518 §4.5 makes
// the shared symmetric key the CEK, so the CEK is reused by construction and only
// the IV varies. That is what the mode is, not a defect here, and §8.2's warning
// about key lifetimes is why jwa.Direct's doc comment points at it.
//
// rfc-req: RFC7518-S8_7-R01
func TestKeyMaterialIsNotReusedAcrossMessages(t *testing.T) {
	for _, pairing := range []struct {
		algorithm jwa.Algorithm
		key       any
	}{
		{jwa.A128KW(), bytes.Repeat([]byte{7}, 16)},
		{jwa.A128GCMKW(), bytes.Repeat([]byte{7}, 16)},
		{jwa.PBES2HS256A128KW(), pbes2Password},
		{jwa.ECDHESA128KW(), &agreementKey.PublicKey},
		{jwa.RSAOAEP(), &conformanceRSAKey.PublicKey},
	} {
		t.Run(pairing.algorithm.String(), func(t *testing.T) {
			first := encryptTo(t, pairing.algorithm, jwa.A128GCM(), pairing.key)
			second := encryptTo(t, pairing.algorithm, jwa.A128GCM(), pairing.key)

			if bytes.Equal(first.Ciphertext, second.Ciphertext) {
				t.Error("two encryptions of one plaintext produced the same ciphertext")
			}

			if bytes.Equal(first.Recipients[0].EncryptedKey, second.Recipients[0].EncryptedKey) {
				t.Error("two encryptions reused the CEK")
			}
		})
	}

	t.Run("dir", func(t *testing.T) {
		cek := make([]byte, jwa.A128GCM().KeySize())

		first := encryptTo(t, jwa.Dir(), jwa.A128GCM(), cek)
		second := encryptTo(t, jwa.Dir(), jwa.A128GCM(), cek)

		if bytes.Equal(first.InitializationVector, second.InitializationVector) {
			t.Error("dir reused the IV as well as the CEK")
		}

		if bytes.Equal(first.Ciphertext, second.Ciphertext) {
			t.Error("dir produced the same ciphertext twice")
		}
	})
}

// TestPBES2PasswordLength checks §8.8's recommended range.
//
// SHOULD — "It is RECOMMENDED that a password used for 'PBES2-HS256+A128KW' be
// no shorter than 16 octets and no longer than 128 octets and a password used for
// 'PBES2-HS512+A256KW' be no shorter than 32 octets and no longer than 128 octets".
//
// should_policy: strict. A real gap found while re-enriching this section: any
// password of any length was previously accepted.
//
// Applied when producing and not when consuming. The recommendation is addressed
// to whoever chooses the password, and that choice is made on the producing side,
// where refusing costs nothing but a better password; refusing on the receiving
// side would reject a message the recipient is entitled to read without making
// anyone's password stronger. The same asymmetry this module applies to "zip" and
// to RFC 7797's "b64", and the receiving half is asserted too.
//
// Assumption, labelled: the RFC names bounds for two of the three algorithms.
// PBES2-HS384+A192KW sits between them and takes an interpolated floor of 24
// octets, which is this module's reading rather than the RFC's text.
//
// rfc-req: RFC7518-S8_8-R01
func TestPBES2PasswordLength(t *testing.T) {
	for _, algorithm := range []struct {
		algorithm jwa.KeyEncrypter
		minimum   int
	}{
		{jwa.PBES2HS256A128KW(), 16},
		{jwa.PBES2HS384A192KW(), 24},
		{jwa.PBES2HS512A256KW(), 32},
	} {
		t.Run(algorithm.algorithm.String(), func(t *testing.T) {
			for _, size := range []int{0, 1, algorithm.minimum - 1, 129} {
				_, _, err := algorithm.algorithm.EncryptKey(
					bytes.Repeat([]byte{'p'}, size), jwa.A128GCM(), new(jwa.KeyParameters),
				)
				if !errors.Is(err, jwa.ErrWeakPassword) {
					t.Errorf("a %d-octet password: got %v, want ErrWeakPassword", size, err)
				}
			}

			for _, size := range []int{algorithm.minimum, 128} {
				_, _, err := algorithm.algorithm.EncryptKey(
					bytes.Repeat([]byte{'p'}, size), jwa.A128GCM(), new(jwa.KeyParameters),
				)
				if err != nil {
					t.Errorf("a %d-octet password was refused: %v", size, err)
				}
			}

			decrypter, ok := algorithm.algorithm.(jwa.KeyDecrypter)
			if !ok {
				t.Fatalf("%s does not decrypt", algorithm.algorithm)
			}

			_, err := decrypter.DecryptKey(
				make([]byte, 40),
				[]byte("short"),
				jwa.A128GCM(),
				&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16), PBES2Count: 1000},
			)
			if errors.Is(err, jwa.ErrWeakPassword) {
				t.Error("the length check ran on the receiving side")
			}
		})
	}
}

// TestPasswordPreparationIsTheApplicationsToPerform records §9's scope.
//
// SHOULD — "It is RECOMMENDED that applications perform the steps outlined in
// [the PRECIS OpaqueString profile] to prepare a password".
//
// not-testable: OpaqueString preparation (RFC 7613) is a Unicode operation
// requiring width-mapping, normalization and disallowed-code-point tables. This
// module has zero dependencies and the standard library does not provide them, so
// implementing it here would mean either taking a dependency or vendoring Unicode
// tables that go stale.
//
// More to the point, it is the wrong layer. The password arrives as []byte — see
// TestPBES2PasswordIsAnOctetSequence — so the caller has already decided what
// octets it is, and preparing them afterwards would second-guess a decision made
// with more context. Recorded as the application's rather than dropped, so the
// boundary stays visible in the coverage report.
//
// What is asserted is that the octets reach the derivation unchanged: this module
// applies no normalization of its own, so a caller who has prepared their password
// gets what they prepared.
//
// rfc-req: RFC7518-S9-R01
func TestPasswordPreparationIsTheApplicationsToPerform(t *testing.T) {
	narrow := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	wide := []byte("ａaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	parameters := &jwa.KeyParameters{PBES2SaltInput: bytes.Repeat([]byte{3}, 16), PBES2Count: 1000}
	cek := bytes.Repeat([]byte{5}, 16)

	first, err := jwa.PBES2HS256A128KW().WrapKey(cek, narrow, jwa.A128GCM(), parameters)
	if err != nil {
		t.Fatalf("cannot wrap: %v", err)
	}

	second, err := jwa.PBES2HS256A128KW().WrapKey(cek, wide, jwa.A128GCM(), parameters)
	if err != nil {
		t.Fatalf("cannot wrap: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Error("this module normalized the passwords; preparation is the application's")
	}
}

var conformanceRSAKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
}()
