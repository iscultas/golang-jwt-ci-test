package header_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func TestJWEParametersRoundTrip(t *testing.T) {
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	original := &header.Header{
		Algorithm:            jwa.ECDHESA128KW(),
		EncryptionAlgorithm:  jwa.A256CBCHS512(),
		CompressionAlgorithm: header.Deflate,
		EphemeralPublicKey:   jwk.NewKey(&ephemeralKey.PublicKey),
		AgreementPartyUInfo:  []byte("Alice"),
		AgreementPartyVInfo:  []byte("Bob"),
		InitializationVector: bytes.Repeat([]byte{1}, 12),
		AuthenticationTag:    bytes.Repeat([]byte{2}, 16),
		PBES2SaltInput:       bytes.Repeat([]byte{3}, 16),
		PBES2Count:           4096,
	}

	encoded, err := original.Marshal()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	decoded := new(header.Header)
	if err := decoded.Unmarshal(encoded); err != nil {
		t.Fatalf("cannot decode the header: %v", err)
	}

	for _, parameter := range []struct {
		name      string
		got, want any
	}{
		{"alg", decoded.Algorithm, original.Algorithm},
		{"enc", decoded.EncryptionAlgorithm, original.EncryptionAlgorithm},
		{"zip", decoded.CompressionAlgorithm, original.CompressionAlgorithm},
		{"apu", decoded.AgreementPartyUInfo, original.AgreementPartyUInfo},
		{"apv", decoded.AgreementPartyVInfo, original.AgreementPartyVInfo},
		{"iv", decoded.InitializationVector, original.InitializationVector},
		{"tag", decoded.AuthenticationTag, original.AuthenticationTag},
		{"p2s", decoded.PBES2SaltInput, original.PBES2SaltInput},
		{"p2c", decoded.PBES2Count, original.PBES2Count},
	} {
		if !reflect.DeepEqual(parameter.got, parameter.want) {
			t.Errorf("%s: got %v, want %v", parameter.name, parameter.got, parameter.want)
		}
	}

	if decoded.EphemeralPublicKey == nil {
		t.Fatal("epk: got nothing back")
	}

	if !ephemeralKey.PublicKey.Equal(decoded.EphemeralPublicKey.Material()) {
		t.Errorf("epk: got %v, want the key that went in", decoded.EphemeralPublicKey.Material())
	}
}

func TestJWEParametersUseBase64URL(t *testing.T) {
	encoded, err := (&header.Header{
		Algorithm:            jwa.A128GCMKW(),
		EncryptionAlgorithm:  jwa.A128GCM(),
		InitializationVector: []byte{0xfb, 0xff, 0xfe},
	}).MarshalJSON()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	if !strings.Contains(string(encoded), `"iv":"-__-"`) {
		t.Errorf(`got %s, want an iv of "-__-"`, encoded)
	}

	for _, character := range []string{"+", "/", "="} {
		if strings.Contains(string(encoded), character) {
			t.Errorf("got %s, which contains %q and so is not base64url", encoded, character)
		}
	}
}

func TestAbsentAndEmptyOctetParametersStayDistinct(t *testing.T) {
	encoded, err := (&header.Header{Algorithm: jwa.Dir(), EncryptionAlgorithm: jwa.A128GCM()}).MarshalJSON()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	for _, name := range []string{"apu", "apv", "iv", "tag", "p2s", "p2c", "zip", "epk"} {
		if strings.Contains(string(encoded), `"`+name+`"`) {
			t.Errorf("got %s, which names %q though it was never set", encoded, name)
		}
	}
}

func TestUnmarshalingRejectsAnUnusableEnc(t *testing.T) {
	for _, name := range []string{"A128CBC", "a128gcm", "RSA1_5"} {
		t.Run(name, func(t *testing.T) {
			err := new(header.Header).Unmarshal(encode(`{"alg":"dir","enc":"` + name + `"}`))

			if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
				t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
			}
		})
	}
}

func TestKeyParametersTranslate(t *testing.T) {
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	original := &jwa.KeyParameters{
		EphemeralPublicKey:   &ephemeralKey.PublicKey,
		AgreementPartyUInfo:  []byte("Alice"),
		AgreementPartyVInfo:  []byte("Bob"),
		InitializationVector: bytes.Repeat([]byte{1}, 12),
		AuthenticationTag:    bytes.Repeat([]byte{2}, 16),
		PBES2SaltInput:       bytes.Repeat([]byte{3}, 16),
		PBES2Count:           4096,
	}

	joseHeader := new(header.Header)
	if err := joseHeader.SetKeyParameters(original); err != nil {
		t.Fatalf("cannot set the parameters: %v", err)
	}

	if !reflect.DeepEqual(joseHeader.KeyParameters(), original) {
		t.Errorf("the parameters did not survive the crossing:\n got %+v\nwant %+v", joseHeader.KeyParameters(), original)
	}
}

func TestSetKeyParametersPublishesOnlyThePublicHalf(t *testing.T) {
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	joseHeader := &header.Header{Algorithm: jwa.ECDHES(), EncryptionAlgorithm: jwa.A128GCM()}

	if err := joseHeader.SetKeyParameters(&jwa.KeyParameters{EphemeralPublicKey: ephemeralKey}); err != nil {
		t.Fatalf("cannot set the parameters: %v", err)
	}

	encoded, err := joseHeader.MarshalJSON()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	var decoded struct {
		EphemeralPublicKey map[string]jsontext.Value `json:"epk"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot decode the header: %v", err)
	}

	if _, published := decoded.EphemeralPublicKey["d"]; published {
		t.Errorf("got %s, which publishes the ephemeral private key", encoded)
	}
}

func TestSetKeyParametersRejectsASymmetricEphemeralKey(t *testing.T) {
	if err := new(header.Header).SetKeyParameters(
		&jwa.KeyParameters{EphemeralPublicKey: []byte("a shared secret")},
	); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
		t.Errorf("got %v, want ErrUnsupportedKeyType", err)
	}
}
