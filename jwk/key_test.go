package jwk_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

const rsaPrivateKeyPem = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L
hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknj
hMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/F
DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO
pbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBni
Iqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQABAoIBAF+HE7XiWP4J+BWD
7FwfK3V4seb8LINRSzeRNxGhukSaFR/hyyyg/TO3ceaKOxlEZJ3IZ60cHlJAu4U+
XySzNFmxQCjS1mNr7+wejal0s1L8U9P2En6oo8Kd0U85QWgsVqeHaBZOTdqPBsv5
xzSq6AAyJCeOqUVKIbF8sG0XgHWGjMBbPbb/Hf3D1WN4tO2t7fDDekzcJtHUmsJv
b+O1Igpd0pOWYhu8aIzy7uLG4NVNo8eCAUzQc52yUsxRyuuo0/G4JLqrJNBo7JAy
ZNfWeKsI8G7J5+I9lgYot0S/lLNpRlZGPH5Bc5ntc9B2yJH89GOpqpzmLanNF+I3
3CqAAvECgYEA83i+7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxt
PVnwD20R+60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy
qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfsCgYEA3dfO
R9cuYq+0S+mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgT
nCdpYzBcOfW5r370AFXjiWft/NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ+1k
Yd/s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxkCgYAbiw9eRzphr3Lyglb38guP
jG6mm7SXOL8ftVORLzGPlJ1fdygTSiKZjDEiLZ6ZMC57RQ5rl2mAUbIEnhzy1DZU
XjTZdG6AoNM/xqRiEWjm0ADvtB782a25hlzcLebcjbgbYa9HmxIPFTIA3bOrwt+f
0RSazqtjc5vxh6IqROIGPQKBgQCz2UAf1+CAGygVHw5pzZH8TaDDbzatPaQY4CG8
iWURMTV5+sDqG5RS8x8FwymfyWp5bq/POdhjlJJAXukx0L9qAjecbwhunUFRvQlS
KtpE2pR8uFxBv930YXgOHt7vhZtGyhtGie6NNg3XEJo/pM7rWO9atf4vXy3FfDj3
hD9yCQKBgBsjP6eia18kos9baBYCm1lfiXSN40OMqbva2zFsd60CQX5rdBaGM4FC
GRFRRHDqsHpkTfNc6AwGmvgZNCljRg4yR2Q3Q5hYVtwDe5SPqbsZP5h2Ridda8ck
fDueVy0nt0j5kXysGSOslNuGcb0ChWCLXZXVChszuiGus0yoQFUV
-----END RSA PRIVATE KEY-----
`

const rsaModulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

const encodedRsaKey = `{"kty":"RSA","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","n":"` + rsaModulus + `","e":"AQAB","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk","dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0","dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk","qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"}`

const encodedRsaPublicKey = `{"kty":"RSA","n":"` + rsaModulus + `","e":"AQAB"}`

const (
	ellipticCurveX = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
	ellipticCurveY = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
)

const encodedEllipticCurvePublicKey = `{"kty":"EC","crv":"P-256","x":"` + ellipticCurveX + `","y":"` + ellipticCurveY + `"}`

const (
	shortEllipticCurveX = "AMBYpACkjKkY46vh_T87UfUGOtyqq4ycfnm2Fsvz18Q"
	shortEllipticCurveY = "JeCrj5hZ6NB1zO7GtKwq25HCKaNIK1X3VqlBQ5UedYw"
	shortEllipticCurveD = "uVAvwHEixGeXd9XWJCaJyFmXJtClsZqqdNFwxuwyPgQ"
)

const encodedShortEllipticCurveKey = `{"kty":"EC","crv":"P-256","x":"` + shortEllipticCurveX +
	`","y":"` + shortEllipticCurveY + `","d":"` + shortEllipticCurveD + `"}`

const symmetricKeyMaterial = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

const encodedSymmetricKey = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`

func rsaKey(t *testing.T) *jwk.Key {
	t.Helper()

	block, _ := pem.Decode([]byte(rsaPrivateKeyPem))
	if block == nil {
		t.Fatal("cannot decode RSA private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("cannot parse RSA private key: %v", err)
	}

	return jwk.NewKey(privateKey)
}

func rsaPublicKey(t *testing.T) *jwk.Key {
	t.Helper()

	return jwk.NewKey(&rsaKey(t).Material().(*rsa.PrivateKey).PublicKey)
}

func coordinate(t *testing.T, encodedCoordinate string) []byte {
	t.Helper()

	decodedCoordinate, err := base64.RawURLEncoding.DecodeString(encodedCoordinate)
	if err != nil {
		t.Fatalf("cannot decode coordinate: %v", err)
	}

	return decodedCoordinate
}

func uncompressedPoint(t *testing.T, x, y string) []byte {
	t.Helper()

	return append(append([]byte{4}, coordinate(t, x)...), coordinate(t, y)...)
}

func ellipticCurvePublicKey(t *testing.T) *jwk.Key {
	t.Helper()

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressedPoint(t, ellipticCurveX, ellipticCurveY))
	if err != nil {
		t.Fatalf("cannot parse public key: %v", err)
	}

	return jwk.NewKey(publicKey)
}

func oversizedEllipticCurveKey(t *testing.T) *jwk.Key {
	t.Helper()

	return jwk.NewKey(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
		X: new(big.Int).Lsh(big.NewInt(1), 256),
		//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
		Y: new(big.Int).SetBytes(coordinate(t, ellipticCurveY)),
	})
}

func shortEllipticCurveKey(t *testing.T) *jwk.Key {
	t.Helper()

	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), coordinate(t, shortEllipticCurveD))
	if err != nil {
		t.Fatalf("cannot parse private key: %v", err)
	}

	return jwk.NewKey(privateKey)
}

const (
	ed25519Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	ed25519PublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

const encodedEd25519Key = `{"kty":"OKP","crv":"Ed25519","x":"` + ed25519PublicKey + `","d":"` + ed25519Seed + `"}`

const encodedEd25519PublicKey = `{"kty":"OKP","crv":"Ed25519","x":"` + ed25519PublicKey + `"}`

const (
	x25519Scalar    = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"
	x25519PublicKey = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
)

const encodedX25519Key = `{"kty":"OKP","crv":"X25519","x":"` + x25519PublicKey + `","d":"` + x25519Scalar + `"}`

const encodedX25519PublicKey = `{"kty":"OKP","crv":"X25519","x":"` + x25519PublicKey + `"}`

func ed25519Key(t *testing.T) *jwk.Key {
	t.Helper()

	seed, err := base64.RawURLEncoding.DecodeString(ed25519Seed)
	if err != nil {
		t.Fatalf("cannot decode seed: %v", err)
	}

	return jwk.NewKey(ed25519.NewKeyFromSeed(seed))
}

func ed25519PublicKeyJwk(t *testing.T) *jwk.Key {
	t.Helper()

	publicKey, err := base64.RawURLEncoding.DecodeString(ed25519PublicKey)
	if err != nil {
		t.Fatalf("cannot decode public key: %v", err)
	}

	return jwk.NewKey(ed25519.PublicKey(publicKey))
}

func symmetricKey(t *testing.T) *jwk.Key {
	t.Helper()

	material, err := base64.RawURLEncoding.DecodeString(symmetricKeyMaterial)
	if err != nil {
		t.Fatalf("cannot decode symmetric key: %v", err)
	}

	return jwk.NewKey(material)
}

type keyTestCase struct {
	name       string
	key        *jwk.Key
	encodedKey string
}

func keys(t *testing.T) []keyTestCase {
	t.Helper()

	return []keyTestCase{
		{"RSA", rsaKey(t), encodedRsaKey},
		{"RSAPublic", rsaPublicKey(t), encodedRsaPublicKey},
		{"EllipticCurvePublic", ellipticCurvePublicKey(t), encodedEllipticCurvePublicKey},
		{"EllipticCurveShortCoordinate", shortEllipticCurveKey(t), encodedShortEllipticCurveKey},
		{"Ed25519", ed25519Key(t), encodedEd25519Key},
		{"Ed25519Public", ed25519PublicKeyJwk(t), encodedEd25519PublicKey},
		{"Symmetric", symmetricKey(t), encodedSymmetricKey},

		{"AKP", mldsaKey(t), encodedMLDSAKey(t)},
		{"AKPPublic", mldsaPublicKeyJwk(t), encodedMLDSAPublicKey(t)},
	}
}

func TestKeyEncoding(t *testing.T) {
	for _, testCase := range keys(t) {
		t.Run(testCase.name, func(t *testing.T) {
			encodedKey, err := json.Marshal(testCase.key)
			if err != nil {
				t.Fatalf("cannot encode key: %v", err)
			}

			if string(encodedKey) != testCase.encodedKey {
				t.Errorf("got %s, want %s", encodedKey, testCase.encodedKey)
			}
		})
	}
}

func TestKeyDecoding(t *testing.T) {
	for _, testCase := range keys(t) {
		t.Run(testCase.name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(testCase.encodedKey), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			if !reflect.DeepEqual(key, testCase.key) {
				t.Errorf("got %v, want %v", key, testCase.key)
			}
		})
	}
}

func TestEncodingEllipticCurveCoordinateWidth(t *testing.T) {
	encodedKey, err := json.Marshal(shortEllipticCurveKey(t))
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	var parameters map[string]string
	if err := json.Unmarshal(encodedKey, &parameters); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	const coordinateLength = 32

	for _, name := range []string{"x", "y", "d"} {
		t.Run(name, func(t *testing.T) {
			parameter, err := base64.RawURLEncoding.DecodeString(parameters[name])
			if err != nil {
				t.Fatalf("cannot decode %s: %v", name, err)
			}

			if len(parameter) != coordinateLength {
				t.Errorf("got %s of %d octets, want %d", name, len(parameter), coordinateLength)
			}
		})
	}
}

func TestEncodingOversizedEllipticCurveParameter(t *testing.T) {
	_, err := json.Marshal(oversizedEllipticCurveKey(t))
	if !errors.Is(err, jwk.ErrMalformedKey) {
		t.Errorf("got error %v, want %v", err, jwk.ErrMalformedKey)
	}
}

func TestPublicKeyMaterialType(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		encodedKey   string
		materialType string
	}{
		{"RSA", encodedRsaPublicKey, "*rsa.PublicKey"},
		{"EllipticCurve", encodedEllipticCurvePublicKey, "*ecdsa.PublicKey"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(testCase.encodedKey), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			if materialType := fmt.Sprintf("%T", key.Material()); materialType != testCase.materialType {
				t.Errorf("got material %s, want %s", materialType, testCase.materialType)
			}
		})
	}
}

func TestDecodingKeyOnUnsupportedCurve(t *testing.T) {
	key := new(jwk.Key)

	err := json.Unmarshal([]byte(`{"kty":"EC","crv":"P-192","x":"","y":""}`), key)
	if !errors.Is(err, jwk.ErrUnsupportedCurve) {
		t.Fatalf("got error %v, want %v", err, jwk.ErrUnsupportedCurve)
	}

	if key.Material() != nil {
		t.Errorf("got material %v, want none", key.Material())
	}
}

func TestDecodingOctetKeyPairMaterialType(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		encodedKey   string
		materialType string
	}{
		{"Private", encodedEd25519Key, "ed25519.PrivateKey"},
		{"Public", encodedEd25519PublicKey, "ed25519.PublicKey"},
		{"X25519Private", encodedX25519Key, "*ecdh.PrivateKey"},
		{"X25519Public", encodedX25519PublicKey, "*ecdh.PublicKey"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(testCase.encodedKey), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			if materialType := fmt.Sprintf("%T", key.Material()); materialType != testCase.materialType {
				t.Errorf("got material %s, want %s", materialType, testCase.materialType)
			}
		})
	}
}

func requireDecodingError(t *testing.T, err, want error) {
	t.Helper()

	if _, ok := errors.AsType[*jwk.MissingRequiredParameterError](want); ok {
		if _, ok := errors.AsType[*jwk.MissingRequiredParameterError](err); !ok {
			t.Fatalf("got error %v, want a missing parameter error", err)
		}
	} else if !errors.Is(err, want) {
		t.Fatalf("got error %v, want %v", err, want)
	}
}

const zeroEllipticCurveParameter = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

const ellipticCurveOrder = "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVE"

func TestDecodingMalformedEllipticCurve(t *testing.T) {
	for name, testCase := range map[string]struct {
		encodedKey string
		err        error
	}{
		"MissingCurve": {`{"kty":"EC","x":"` + ellipticCurveX + `","y":"` + ellipticCurveY + `"}`, &jwk.MissingRequiredParameterError{}},
		"MissingX":     {`{"kty":"EC","crv":"P-256","y":"` + ellipticCurveY + `"}`, &jwk.MissingRequiredParameterError{}},
		"MissingY":     {`{"kty":"EC","crv":"P-256","x":"` + ellipticCurveX + `"}`, &jwk.MissingRequiredParameterError{}},

		"PointNotOnCurve": {
			`{"kty":"EC","crv":"P-256","x":"` + ellipticCurveX + `","y":"` + shortEllipticCurveY + `"}`,
			jwk.ErrMalformedKey,
		},
		"PointAtInfinity": {
			`{"kty":"EC","crv":"P-256","x":"` + zeroEllipticCurveParameter + `","y":"` + zeroEllipticCurveParameter + `"}`,
			jwk.ErrMalformedKey,
		},
		"OversizedX": {
			`{"kty":"EC","crv":"P-256","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"` + ellipticCurveY + `"}`,
			jwk.ErrMalformedKey,
		},
		"OversizedY": {
			`{"kty":"EC","crv":"P-256","x":"` + ellipticCurveX + `","y":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
			jwk.ErrMalformedKey,
		},

		"MismatchedD": {
			`{"kty":"EC","crv":"P-256","x":"` + ellipticCurveX + `","y":"` + ellipticCurveY +
				`","d":"` + shortEllipticCurveD + `"}`,
			jwk.ErrMalformedKey,
		},
		"ZeroD": {
			`{"kty":"EC","crv":"P-256","x":"` + shortEllipticCurveX + `","y":"` + shortEllipticCurveY +
				`","d":"` + zeroEllipticCurveParameter + `"}`,
			jwk.ErrMalformedKey,
		},
		"DAtCurveOrder": {
			`{"kty":"EC","crv":"P-256","x":"` + shortEllipticCurveX + `","y":"` + shortEllipticCurveY +
				`","d":"` + ellipticCurveOrder + `"}`,
			jwk.ErrMalformedKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			requireDecodingError(t, json.Unmarshal([]byte(testCase.encodedKey), key), testCase.err)

			if key.Material() != nil {
				t.Errorf("got material %v, want none", key.Material())
			}
		})
	}
}

func TestDecodingNonBase64EllipticCurveParameter(t *testing.T) {
	key := new(jwk.Key)

	if err := json.Unmarshal([]byte(`{"kty":"EC","crv":"P-256","x":"!","y":"`+ellipticCurveY+`"}`), key); err == nil {
		t.Fatal("got no error, want a base64 error")
	}

	if key.Material() != nil {
		t.Errorf("got material %v, want none", key.Material())
	}
}

func TestDecodingTrimmedEllipticCurveCoordinate(t *testing.T) {
	const trimmedX = "wFikAKSMqRjjq-H9PztR9QY63KqrjJx-ebYWy_PXxA"

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(strings.Replace(
		encodedShortEllipticCurveKey, shortEllipticCurveX, trimmedX, 1,
	)), key); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	if !reflect.DeepEqual(key, shortEllipticCurveKey(t)) {
		t.Errorf("got %v, want the same key as the full width form", key)
	}
}

func TestDecodingMalformedOctetKeyPair(t *testing.T) {
	const mismatchedSeed = "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	for name, testCase := range map[string]struct {
		encodedKey string
		err        error
	}{
		"UnsupportedCurve": {`{"kty":"OKP","crv":"X448","x":"` + ed25519PublicKey + `"}`, jwk.ErrUnsupportedCurve},
		"MissingCurve":     {`{"kty":"OKP","x":"` + ed25519PublicKey + `"}`, &jwk.MissingRequiredParameterError{}},
		"MissingX":         {`{"kty":"OKP","crv":"Ed25519"}`, &jwk.MissingRequiredParameterError{}},
		"ShortX":           {`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`, jwk.ErrMalformedKey},
		"ShortD":           {`{"kty":"OKP","crv":"Ed25519","x":"` + ed25519PublicKey + `","d":"AAAA"}`, jwk.ErrMalformedKey},
		"MismatchedD":      {`{"kty":"OKP","crv":"Ed25519","x":"` + ed25519PublicKey + `","d":"` + mismatchedSeed + `"}`, jwk.ErrMalformedKey},

		"X25519MissingX": {`{"kty":"OKP","crv":"X25519"}`, &jwk.MissingRequiredParameterError{}},
		"X25519ShortX":   {`{"kty":"OKP","crv":"X25519","x":"AAAA"}`, jwk.ErrMalformedKey},
		"X25519ShortD": {
			`{"kty":"OKP","crv":"X25519","x":"` + x25519PublicKey + `","d":"AAAA"}`, jwk.ErrMalformedKey,
		},
		"X25519MismatchedD": {
			`{"kty":"OKP","crv":"X25519","x":"` + x25519PublicKey + `","d":"` + mismatchedSeed + `"}`,
			jwk.ErrMalformedKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			requireDecodingError(t, json.Unmarshal([]byte(testCase.encodedKey), key), testCase.err)

			if key.Material() != nil {
				t.Errorf("got material %v, want none", key.Material())
			}
		})
	}
}

func TestDecodingMalformedRSA(t *testing.T) {
	const oversizedExponent = "AQAAAAAA"

	mismatchedModulus := "1" + rsaModulus[1:]

	for name, testCase := range map[string]struct {
		encodedKey string
		err        error
	}{
		"MissingN":     {`{"kty":"RSA","e":"AQAB"}`, &jwk.MissingRequiredParameterError{}},
		"MissingE":     {`{"kty":"RSA","n":"` + rsaModulus + `"}`, &jwk.MissingRequiredParameterError{}},
		"NoParameters": {`{"kty":"RSA"}`, &jwk.MissingRequiredParameterError{}},
		"OversizedE":   {`{"kty":"RSA","n":"` + rsaModulus + `","e":"` + oversizedExponent + `"}`, jwk.ErrMalformedKey},
		"SmallE":       {`{"kty":"RSA","n":"` + rsaModulus + `","e":"AQ"}`, jwk.ErrMalformedKey},
		"MismatchedModulus": {
			strings.Replace(encodedRsaKey, rsaModulus, mismatchedModulus, 1), jwk.ErrMalformedKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			requireDecodingError(t, json.Unmarshal([]byte(testCase.encodedKey), key), testCase.err)

			if key.Material() != nil {
				t.Errorf("got material %v, want none", key.Material())
			}
		})
	}
}

func TestPublic(t *testing.T) {
	for _, testCase := range []struct {
		name             string
		encodedKey       string
		encodedPublicKey string
	}{
		{"RSA", encodedRsaKey, encodedRsaPublicKey},
		{"Ed25519", encodedEd25519Key, encodedEd25519PublicKey},
		{"EllipticCurvePublic", encodedEllipticCurvePublicKey, encodedEllipticCurvePublicKey},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(testCase.encodedKey), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			encodedPublicKey, err := json.Marshal(key.Public())
			if err != nil {
				t.Fatalf("cannot encode key: %v", err)
			}

			var got, want map[string]any
			if err := json.Unmarshal(encodedPublicKey, &got); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}
			if err := json.Unmarshal([]byte(testCase.encodedPublicKey), &want); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %s, want %s", encodedPublicKey, testCase.encodedPublicKey)
			}

			for _, parameter := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
				if _, ok := got[parameter]; ok {
					t.Errorf("got a %s member in %s, want none", parameter, encodedPublicKey)
				}
			}
		})
	}

	t.Run("Symmetric", func(t *testing.T) {
		key := new(jwk.Key)
		if err := json.Unmarshal([]byte(encodedSymmetricKey), key); err != nil {
			t.Fatalf("cannot decode key: %v", err)
		}

		if publicKey := key.Public(); publicKey != nil {
			t.Errorf("got key %v, want none", publicKey)
		}
	})

	t.Run("KeySet", func(t *testing.T) {
		decode := func(t *testing.T, encodedKey string) *jwk.Key {
			t.Helper()

			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(encodedKey), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			return key
		}

		keySet := jwk.NewKeySet(
			decode(t, encodedRsaKey), decode(t, encodedSymmetricKey), decode(t, encodedEd25519Key),
		)

		publicKeySet := keySet.Public()

		if len(publicKeySet.Keys) != 2 {
			t.Fatalf("got %d keys, want 2", len(publicKeySet.Keys))
		}

		encodedKeySet, err := json.Marshal(publicKeySet)
		if err != nil {
			t.Fatalf("cannot encode key set: %v", err)
		}

		for _, parameter := range []string{`"d":`, `"p":`, `"q":`, `"k":`} {
			if strings.Contains(string(encodedKeySet), parameter) {
				t.Errorf("got a %s member in %s, want none", parameter, encodedKeySet)
			}
		}

		if len(keySet.Keys) != 3 {
			t.Errorf("got %d keys in the original set, want 3", len(keySet.Keys))
		}

		if _, ok := keySet.Keys[0].Material().(*rsa.PrivateKey); !ok {
			t.Errorf("got material %T in the original set, want *rsa.PrivateKey", keySet.Keys[0].Material())
		}
	})
}

func TestPublicPreservesParameters(t *testing.T) {
	key := ed25519Key(t)
	jwk.WithID("2010-12-29")(key)
	jwk.WithPublicKeyUse(jwk.Signature)(key)
	jwk.WithOperations(jwk.Verify)(key)
	jwk.WithAlgorithm(jwa.EdDSA())(key)

	publicKey := key.Public()

	encodedPublicKey, err := json.Marshal(publicKey)
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	var members map[string]any
	if err := json.Unmarshal(encodedPublicKey, &members); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	for parameter, want := range map[string]any{
		"kid": "2010-12-29", "use": "sig", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519",
	} {
		if got := members[parameter]; got != want {
			t.Errorf("got %s %v, want %v", parameter, got, want)
		}
	}

	if got := members["key_ops"]; !reflect.DeepEqual(got, []any{"verify"}) {
		t.Errorf("got key_ops %v, want [verify]", got)
	}
}

func TestKeySetSelection(t *testing.T) {
	material := func(t *testing.T, id string) []byte {
		t.Helper()

		return []byte("key material of " + id)
	}

	signing := jwk.NewKey(
		material(t, "signing"),
		jwk.WithID("signing"),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
		jwk.WithAlgorithm(jwa.HS256()),
	)
	encryption := jwk.NewKey(
		material(t, "encryption"),
		jwk.WithID("encryption"),
		jwk.WithPublicKeyUse(jwk.Encryption),
	)
	unrestricted := jwk.NewKey(material(t, "unrestricted"))

	signOnly := jwk.NewKey(
		material(t, "sign only"),
		jwk.WithID("signing"),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign),
		jwk.WithAlgorithm(jwa.HS256()),
	)

	for _, testCase := range []struct {
		name        string
		keySet      *jwk.KeySet
		id          string
		expectedKey *jwk.Key
	}{
		{"Empty", jwk.NewKeySet(), "", nil},
		{"OnlyUnsuitable", jwk.NewKeySet(encryption), "", nil},
		{"UnknownKeyId", jwk.NewKeySet(signing), "other", nil},
		{"SkipsUnsuitable", jwk.NewKeySet(encryption, signing), "", signing},
		{"PrefersMatchingKeyId", jwk.NewKeySet(unrestricted, signing), "signing", signing},
		{"FallsBackToUnrestricted", jwk.NewKeySet(encryption, unrestricted), "", unrestricted},
		{"KeyOpsExcludeTheOperation", jwk.NewKeySet(signOnly), "signing", nil},
		{"KeyOpsExcludeOnlyTheWrongKey", jwk.NewKeySet(signOnly, signing), "signing", signing},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := testCase.keySet.Key(
				jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.HS256(), testCase.id,
			)

			if testCase.expectedKey == nil {
				if !errors.Is(err, jwk.ErrNoSuitableKey) {
					t.Fatalf("got key %v and error %v, want %v", key, err, jwk.ErrNoSuitableKey)
				}

				return
			}

			if err != nil {
				t.Fatalf("cannot select key: %v", err)
			}

			if key != testCase.expectedKey {
				t.Errorf("got key %v, want %v", key, testCase.expectedKey)
			}
		})
	}
}

func TestEncodingUnsupportedKeyType(t *testing.T) {
	t.Run("UnrecognizedMaterial", func(t *testing.T) {
		_, err := json.Marshal(jwk.NewKey(42))
		if !errors.Is(err, jwk.ErrUnsupportedKeyType) {
			t.Errorf("got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
		}
	})

	t.Run("DecodedFromUnimplementedKeyType", func(t *testing.T) {
		key := new(jwk.Key)
		if err := json.Unmarshal([]byte(`{"kty":"bogus"}`), key); err != nil {
			t.Fatalf("cannot decode key: %v", err)
		}

		_, err := json.Marshal(key)
		if !errors.Is(err, jwk.ErrUnsupportedKeyType) {
			t.Errorf("got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
		}
	})

	t.Run("NISTCurveUnderCryptoECDH", func(t *testing.T) {
		for name, curve := range map[string]ecdh.Curve{
			"P-256": ecdh.P256(), "P-384": ecdh.P384(), "P-521": ecdh.P521(),
		} {
			t.Run(name, func(t *testing.T) {
				privateKey, err := curve.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("cannot generate a key: %v", err)
				}

				for half, material := range map[string]any{
					"private": privateKey, "public": privateKey.PublicKey(),
				} {
					t.Run(half, func(t *testing.T) {
						key := jwk.NewKey(material)

						if keyType := key.Type(); keyType != "" {
							t.Errorf("got kty %q, want none", keyType)
						}

						if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
							t.Errorf("got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
						}

						if _, err := key.Thumbprint(crypto.SHA256); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
							t.Errorf("got thumbprint error %v, want %v", err, jwk.ErrUnsupportedKeyType)
						}
					})
				}
			})
		}
	})
}

func TestX25519RoundTrip(t *testing.T) {
	for name, document := range map[string]string{
		"private": encodedX25519Key,
		"public":  encodedX25519PublicKey,
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(document), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			if keyType := key.Type(); keyType != jwk.OctetKeyPair {
				t.Errorf("got kty %q, want %q", keyType, jwk.OctetKeyPair)
			}

			encoded, err := json.Marshal(key)
			if err != nil {
				t.Fatalf("cannot encode key: %v", err)
			}

			if string(encoded) != document {
				t.Errorf("got %s, want %s", encoded, document)
			}
		})
	}

	t.Run("PublicHalf", func(t *testing.T) {
		privateKey := new(jwk.Key)
		if err := json.Unmarshal([]byte(encodedX25519Key), privateKey); err != nil {
			t.Fatalf("cannot decode key: %v", err)
		}

		if !privateKey.IsPrivate() {
			t.Error("an X25519 key with a d reports itself public")
		}

		publicKey := privateKey.Public()
		if publicKey.IsPrivate() {
			t.Error("the public half reports itself private")
		}

		encoded, err := json.Marshal(publicKey)
		if err != nil {
			t.Fatalf("cannot encode the public half: %v", err)
		}

		if string(encoded) != encodedX25519PublicKey {
			t.Errorf("got %s, want %s", encoded, encodedX25519PublicKey)
		}

		privateThumbprint, err := privateKey.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("cannot thumbprint the private key: %v", err)
		}

		publicThumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("cannot thumbprint the public key: %v", err)
		}

		if !bytes.Equal(privateThumbprint, publicThumbprint) {
			t.Errorf("the two halves thumbprint differently: %x and %x", privateThumbprint, publicThumbprint)
		}
	})
}

func TestEncodingEmptyKeySet(t *testing.T) {
	for name, keySet := range map[string]*jwk.KeySet{
		"ZeroValue": new(jwk.KeySet),
		"Public":    jwk.NewKeySet(jwk.NewKey([]byte("secret"))).Public(),
	} {
		t.Run(name, func(t *testing.T) {
			encodedKeySet, err := json.Marshal(keySet)
			if err != nil {
				t.Fatalf("cannot encode key set: %v", err)
			}

			if string(encodedKeySet) != `{"keys":[]}` {
				t.Errorf(`got %s, want {"keys":[]}`, encodedKeySet)
			}
		})
	}
}

func TestCandidatesReturnsEveryUsableKey(t *testing.T) {
	plain := jwk.NewKey(mustGenerateP256(t).Public())
	identified := jwk.NewKey(mustGenerateP256(t).Public(), jwk.WithID("second"))
	forEncryption := jwk.NewKey(mustGenerateP256(t).Public(), jwk.WithPublicKeyUse(jwk.Encryption))

	keySet := jwk.NewKeySet(plain, identified, forEncryption)

	candidates := keySet.Candidates(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.ES256(), "")
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(candidates))
	}

	for _, candidate := range candidates {
		if candidate == forEncryption {
			t.Error("a key published for encryption was offered for verification")
		}
	}

	ranked := keySet.Candidates(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.ES256(), "second")
	if len(ranked) != 2 || ranked[0] != identified {
		t.Errorf("got %d candidates led by %v, want 2 led by the identified key", len(ranked), ranked[0])
	}

	if candidates[0] != plain {
		t.Error("equally weighted candidates were reordered")
	}

	bound := jwk.NewKey(mustGenerateP256(t).Public(), jwk.WithAlgorithm(jwa.ES256()))

	if got := jwk.NewKeySet(bound).Candidates(
		jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.RS256(), "",
	); len(got) != 0 {
		t.Errorf("got %d candidates for an algorithm the key excludes, want 0", len(got))
	}
}

func mustGenerateP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	return privateKey
}

func TestX509URLRoundTrip(t *testing.T) {
	x509URL, err := url.Parse("https://example.com/certificates")
	if err != nil {
		t.Fatalf("cannot parse url: %v", err)
	}

	key := ed25519Key(t)
	jwk.WithX509URL(x509URL)(key)

	encodedKey, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	var members map[string]any
	if err := json.Unmarshal(encodedKey, &members); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	if got := members["x5u"]; got != "https://example.com/certificates" {
		t.Errorf("got x5u %v, want https://example.com/certificates", got)
	}

	decodedKey := new(jwk.Key)
	if err := json.Unmarshal(encodedKey, decodedKey); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	reencodedKey, err := json.Marshal(decodedKey)
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	var reencodedMembers map[string]any
	if err := json.Unmarshal(reencodedKey, &reencodedMembers); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	if got := reencodedMembers["x5u"]; got != "https://example.com/certificates" {
		t.Errorf("got x5u %v after a round trip, want https://example.com/certificates", got)
	}
}

const certificateChainURL = "https://example.com/certificates"

func signingKeyWithEveryParameter(t *testing.T) (*jwk.Key, *x509.Certificate) {
	t.Helper()

	privateKey := generateKey(t)
	certificate := issue(t, privateKey, privateKey, nil, x509.KeyUsageDigitalSignature)

	sha1Digest := sha1.Sum(certificate.Raw)
	sha256Digest := sha256.Sum256(certificate.Raw)

	x509URL, err := url.Parse(certificateChainURL)
	if err != nil {
		t.Fatalf("cannot parse url: %v", err)
	}

	key := jwk.NewKey(
		&privateKey.PublicKey,
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
		jwk.WithAlgorithm(jwa.ES256()),
		jwk.WithID("2010-12-29"),
		jwk.WithX509URL(x509URL),
		jwk.WithX509CertificateChain([]*x509.Certificate{certificate}),
		jwk.WithX509CertificateSHA1Thumbprint(base64.RawURLEncoding.EncodeToString(sha1Digest[:])),
		jwk.WithX509CertificateSHA256Thumbprint(base64.RawURLEncoding.EncodeToString(sha256Digest[:])),
	)

	return key, certificate
}

func checkEveryParameter(t *testing.T, key *jwk.Key, certificate *x509.Certificate) {
	t.Helper()

	sha1Digest := sha1.Sum(certificate.Raw)
	sha256Digest := sha256.Sum256(certificate.Raw)

	if got := key.PublicKeyUse(); got != jwk.Signature {
		t.Errorf("PublicKeyUse gives %q, want %q", got, jwk.Signature)
	}

	if got, want := key.Operations(), []jwk.Operation{jwk.Sign, jwk.Verify}; !reflect.DeepEqual(got, want) {
		t.Errorf("Operations gives %v, want %v", got, want)
	}

	if got := key.Algorithm(); got != jwa.ES256() {
		t.Errorf("Algorithm gives %v, want %v", got, jwa.ES256())
	}

	if got := key.ID(); got != "2010-12-29" {
		t.Errorf("ID gives %q, want %q", got, "2010-12-29")
	}

	if got := key.X509URL(); got == nil || got.String() != certificateChainURL {
		t.Errorf("X509URL gives %v, want %v", got, certificateChainURL)
	}

	chain := key.X509CertificateChain()
	if len(chain) != 1 {
		t.Fatalf("X509CertificateChain gives %d certificates, want 1", len(chain))
	}

	if !bytes.Equal(chain[0].Raw, certificate.Raw) {
		t.Errorf("X509CertificateChain gives a different certificate")
	}

	if got, want := key.X509CertificateSHA1Thumbprint(),
		base64.RawURLEncoding.EncodeToString(sha1Digest[:]); got != want {
		t.Errorf("X509CertificateSHA1Thumbprint gives %q, want %q", got, want)
	}

	if got, want := key.X509CertificateSHA256Thumbprint(),
		base64.RawURLEncoding.EncodeToString(sha256Digest[:]); got != want {
		t.Errorf("X509CertificateSHA256Thumbprint gives %q, want %q", got, want)
	}
}

func TestAccessorsGiveEachOption(t *testing.T) {
	key, certificate := signingKeyWithEveryParameter(t)

	checkEveryParameter(t, key, certificate)
}

func TestAccessorsGiveEachDecodedMember(t *testing.T) {
	key, certificate := signingKeyWithEveryParameter(t)

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	decodedKey := new(jwk.Key)
	if err := json.Unmarshal(document, decodedKey); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	checkEveryParameter(t, decodedKey, certificate)
}

func TestAccessorsCopyWhatACallerCanChange(t *testing.T) {
	key, certificate := signingKeyWithEveryParameter(t)

	operations := key.Operations()
	operations[0] = jwk.Decrypt

	otherKey := generateKey(t)

	chain := key.X509CertificateChain()
	chain[0] = issue(t, otherKey, otherKey, nil, x509.KeyUsageDigitalSignature)

	changedURL := key.X509URL()
	changedURL.Path = "/a different path"

	checkEveryParameter(t, key, certificate)
}

func TestAccessorsAcceptANilKey(t *testing.T) {
	var key *jwk.Key

	if got := key.Material(); got != nil {
		t.Errorf("Material gives %v, want nil", got)
	}

	if got := key.Type(); got != "" {
		t.Errorf("Type gives %q, want an empty value", got)
	}

	if got := key.IsPrivate(); got {
		t.Error("IsPrivate gives true, want false")
	}

	if got := key.Public(); got != nil {
		t.Errorf("Public gives %v, want nil", got)
	}

	if got := key.PublicKeyUse(); got != "" {
		t.Errorf("PublicKeyUse gives %q, want an empty value", got)
	}

	if got := key.Operations(); got != nil {
		t.Errorf("Operations gives %v, want nil", got)
	}

	if got := key.Algorithm(); got != nil {
		t.Errorf("Algorithm gives %v, want nil", got)
	}

	if got := key.ID(); got != "" {
		t.Errorf("ID gives %q, want an empty value", got)
	}

	if got := key.X509URL(); got != nil {
		t.Errorf("X509URL gives %v, want nil", got)
	}

	if got := key.X509CertificateChain(); got != nil {
		t.Errorf("X509CertificateChain gives %v, want nil", got)
	}

	if got := key.X509CertificateSHA1Thumbprint(); got != "" {
		t.Errorf("X509CertificateSHA1Thumbprint gives %q, want an empty value", got)
	}

	if got := key.X509CertificateSHA256Thumbprint(); got != "" {
		t.Errorf("X509CertificateSHA256Thumbprint gives %q, want an empty value", got)
	}
}

func TestKeySetPublicAcceptsANilKeySet(t *testing.T) {
	var keySet *jwk.KeySet

	if got := keySet.Public(); got != nil {
		t.Errorf("Public gives %v, want nil", got)
	}
}

func TestDecodingMalformedOctetSequence(t *testing.T) {
	for name, encodedKey := range map[string]string{
		"MissingK": `{"kty":"oct"}`,
		"EmptyK":   `{"kty":"oct","k":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			requireDecodingError(
				t, json.Unmarshal([]byte(encodedKey), key), &jwk.MissingRequiredParameterError{},
			)

			if key.Material() != nil {
				t.Errorf("got material %v, want none", key.Material())
			}
		})
	}
}

func TestDecodingUnencodableOctetSequence(t *testing.T) {
	for name, encodedKey := range map[string]string{
		"NotBase64":        `{"kty":"oct","k":"not base64url"}`,
		"Padded":           `{"kty":"oct","k":"AAA="}`,
		"StandardAlphabet": `{"kty":"oct","k":"++//"}`,
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			if err := json.Unmarshal([]byte(encodedKey), key); err == nil {
				t.Fatal("a key with an unencodable k decoded without an error")
			}

			if key.Material() != nil {
				t.Errorf("got material %v, want none", key.Material())
			}
		})
	}
}

func TestDecodingUnknownAlgorithm(t *testing.T) {
	for name, encodedKey := range map[string]string{
		"UnregisteredName": `{"kty":"oct","k":"AAAA","alg":"HS999"}`,
		"NotAnAlgorithm":   `{"kty":"oct","k":"AAAA","alg":"hello"}`,
		"WrongCase":        `{"kty":"oct","k":"AAAA","alg":"hs256"}`,
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			err := json.Unmarshal([]byte(encodedKey), key)
			if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
				t.Fatalf("got error %v, want ErrUnsupportedAlgorithm", err)
			}

			if key.Algorithm() != nil {
				t.Errorf("got algorithm %v, want none", key.Algorithm())
			}
		})
	}
}
