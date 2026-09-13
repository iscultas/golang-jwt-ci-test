package jwa_test

import (
	"crypto/fips140"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jws"
)

const symmetricKeyMaterial = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

const rsaPrivateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDpuyhepqrhr17R
SEuInHu5CpTVhkPTvUorZg6y3qPTEXvVv3/2OKZx1gEUCEiek2Gd2gGMuGR7lPQB
T4ksw+r6CMNeFVvLaYav2F9q2CBY+0YmUTl0o2irYkksCMizVKMkICYd3rggasIZ
eh0llxtF40IPmE9KgX/IJkinUS95bn3sBQ7tKI1tRqK/grtsiXhmqxBgmDH2u3Q4
c1TPP20ia7bgqEJO0FetoIBJZiLphxsfo9b6sliSDfIAl4V+IeHU7GjPZ1DTxa6c
GubaLMCz/pI42FlFQMYiVxEF0voUeM3bwyM5Or6BuCm7W3ezJUknO+8QIsX71z5P
Dfa8Sj8ZAgMBAAECggEAG4H0WVdiKxd5oEXS5ewMv5VYON0JZIUVko/7UN/VBgU7
vsc/5xl5tVILZHEpIsiTp4E9x3L4GHdKVFEpAsS4Bd88Jvl6iTENMerUJ/3xqKdB
9UZ/7ZNBwVHa7LzH6hse7CSAd+l7YA1QdLEjdwYWpp39a1pwkoM1J7ghutdaL/8w
Z773vLS75UuEb9i1a/2xmUxeotckeaPASWVXZX9O3FOUiokJzhl+IaZzSGTeT1Qa
lBik0dLmo6khQMijrRii1fYG7Ht5C14oblJwjqJ0Oji5VfJYJSchreTsSa7zHC9X
tgcguEtCQKVqflYi2lsU2tBtb4heI5gqUuu6B6BzpQKBgQD7Kxkn9tIHcyOUFjIh
VM7iCt9+59UzWI9ae1Gvayk9a/UXklFm23DooC3wr7bghW2aC2rMQ81VMXZniSul
qG5hn+6p36IXNgBCIcCWr7cJlbYBTwq1XYpDMP8Xc7Ual1MCiAae6MUFahVlGj09
fi3GCv66AFM2DyynoOB6SMPZSwKBgQDuOjAgU58Xavi/fUyTsmTNjhSGDBHHZU8e
g2zUdfP88W27SC4Fdy4J0Ovojn6LkewaNt3WKHMFWaErR0PlwGHjGHOkofVNCcRe
SiGHIJGRIC1MSSu7nrelQtcOXHj9Bi1U/Wml46lRAmeeGmjEdo3K8ECEnwkGtx6g
RQceiwIOqwKBgFKc1mVitaploKowssRr1LBcyy4+qs18r4ofTbrZEHN3cuIR6lxe
iUC6juG/qfMnb+lfH/2Xv43p+vwLDiQqxkOuCx4sxG/F/0fBOktV+Gpap8a+bNNC
tRtsnjrkgAkDBPasLyFNhqBFSEw82S/EtOGS9D3RpYz+aL2qGKugC2sJAoGAfWDq
i1j3Vh/aow2TC/jLzNOGQbaAdO0A4xJQaNFbhDichADNF9tNw6TNRCwateIq3PEb
d+b6AkrV5C0xsu25lwf7dR44OD93thhV5QRjGHpS3N91wN0b0kKHZOuOUby6hwyI
WeKj7hrR5ggIM74hijk/+4yn93zRBZDO2mhWwNkCgYEAsKxdi+PmS+Ko1SQg9AMx
QiDVYBLCmhKKfMgjqGwDCUGGCZiFDioq0kxMOitZGBPnYJSI0D+JaLv1sZER47w+
9Kqj1xGPaizJtu4p2WZ7ccjZ8DAf3ZAJ/e3PZDZUwxAWPW5zIhFFpkUNO94aOiWC
cEPVE2HToVdcp4P48FrOLXY=
-----END PRIVATE KEY-----
`

const rsaPublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6bsoXqaq4a9e0UhLiJx7
uQqU1YZD071KK2YOst6j0xF71b9/9jimcdYBFAhInpNhndoBjLhke5T0AU+JLMPq
+gjDXhVby2mGr9hfatggWPtGJlE5dKNoq2JJLAjIs1SjJCAmHd64IGrCGXodJZcb
ReNCD5hPSoF/yCZIp1EveW597AUO7SiNbUaiv4K7bIl4ZqsQYJgx9rt0OHNUzz9t
Imu24KhCTtBXraCASWYi6YcbH6PW+rJYkg3yAJeFfiHh1Oxoz2dQ08WunBrm2izA
s/6SONhZRUDGIlcRBdL6FHjN28MjOTq+gbgpu1t3syVJJzvvECLF+9c+Tw32vEo/
GQIDAQAB
-----END PUBLIC KEY-----
`

const es256PrivateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZSADrPwYKqlLShdd
YX2Xz2lUJjkaIXijJ3zkB4tWXjmhRANCAATEAceMguKw6FbqbZ8GWTJdpzh0pLI8
FvyQcG/4JrgQtAZlKHC/l4Sit2DUOdyFsP0XAWOEJfxlpB51W3j3TyIL
-----END PRIVATE KEY-----
`

const es256PublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExAHHjILisOhW6m2fBlkyXac4dKSy
PBb8kHBv+Ca4ELQGZShwv5eEordg1DnchbD9FwFjhCX8ZaQedVt4908iCw==
-----END PUBLIC KEY-----
`

const es384PrivateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDRHbT1Fp1jEjV/OKJr
qsm+9nrwh1xk/EO4oKGOLvXleeh6gFcV+2frL88Y1WGLzgWhZANiAASNNQBh0RE7
483yvFmyM5FCPsMe8hejyKwjJTEnp242kV+Qr0KJS6Jj1tQHP4tuoQGO9PDPl+y3
jm39KGJfSxpfDIQ0/qcMRLOa1jdEwICooO/nF9GZZ4kzXsOIaBVhV+U=
-----END PRIVATE KEY-----
`

const es384PublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEjTUAYdERO+PN8rxZsjORQj7DHvIXo8is
IyUxJ6duNpFfkK9CiUuiY9bUBz+LbqEBjvTwz5fst45t/ShiX0saXwyENP6nDESz
mtY3RMCAqKDv5xfRmWeJM17DiGgVYVfl
-----END PUBLIC KEY-----
`

const es512PrivateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBuxRZToSpAqIsGT2E
5eLdaimMyfWb7lNb/4qwdL+wwwfDb580TZg6AmdVaGr3IAP95TIFdha8UUL8s+lY
gLVTpruhgYkDgYYABABNqLtreA9HfBAc/gw3HSzg3gaY5sbPokuJ4zVaheRA/fH3
8app1Oxxk1f+imHLxsoDfi1Dp/6cvuY4VPdwTy7TlwFVVhULuNNzssmZZJRWUqEi
NfiamFwQt/xfobydvhpX+zzHc8ddDneU1+D5AfiNLOAGasiFRXjJciW4jWusKyZ4
rw==
-----END PRIVATE KEY-----
`

const es512PublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQATai7a3gPR3wQHP4MNx0s4N4GmObG
z6JLieM1WoXkQP3x9/GqadTscZNX/ophy8bKA34tQ6f+nL7mOFT3cE8u05cBVVYV
C7jTc7LJmWSUVlKhIjX4mphcELf8X6G8nb4aV/s8x3PHXQ53lNfg+QH4jSzgBmrI
hUV4yXIluI1rrCsmeK8=
-----END PUBLIC KEY-----
`

func decodeSymmetricKey(t *testing.T) []byte {
	t.Helper()

	key, err := base64.RawURLEncoding.DecodeString(symmetricKeyMaterial)
	if err != nil {
		t.Fatalf("cannot decode symmetric key: %v", err)
	}

	return key
}

func parsePrivateKey(t *testing.T, privateKeyPem string) any {
	t.Helper()

	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		t.Fatal("cannot decode private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("cannot parse private key: %v", err)
	}

	return key
}

func parsePublicKey(t *testing.T, publicKeyPem string) any {
	t.Helper()

	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		t.Fatal("cannot decode public key PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("cannot parse public key: %v", err)
	}

	return key
}

type signerVerifier interface {
	jwa.Signer
	jwa.Verifier
}

func TestByName(t *testing.T) {
	names := []string{
		"none",
		"HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512",
		"EdDSA", "Ed25519",

		"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",

		"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
		"A128GCM", "A192GCM", "A256GCM",

		"dir",
		"RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
		"A128KW", "A192KW", "A256KW",
		"A128GCMKW", "A192GCMKW", "A256GCMKW",
		"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
		"PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(name)
			if !ok {
				t.Fatalf("%s is not registered", name)
			}

			if algorithm.String() != name {
				t.Errorf("got %s, want %s", algorithm, name)
			}
		})
	}

	t.Run("Unregistered", func(t *testing.T) {
		for _, name := range []string{"", "hs256", "HS255", "ECDH-1PU"} {
			if algorithm, ok := jwa.ByName(name); ok {
				t.Errorf("%q resolved to %s, want no match", name, algorithm)
			}
		}
	})

	t.Run("Algorithms", func(t *testing.T) {
		algorithms := jwa.Algorithms()

		if len(algorithms) != len(names) {
			t.Fatalf("got %d algorithms, want %d", len(algorithms), len(names))
		}

		if !slices.IsSortedFunc(algorithms, func(a, b jwa.Algorithm) int {
			return strings.Compare(a.String(), b.String())
		}) {
			t.Error("got unsorted algorithms, want sorted ones")
		}
	})
}

func TestUnsupportedAlgorithm(t *testing.T) {
	err := jwa.UnsupportedAlgorithm("ECDH-1PU")

	if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got error %v, want %v", err, jwa.ErrUnsupportedAlgorithm)
	}

	if !strings.Contains(err.Error(), "ECDH-1PU") {
		t.Errorf("got %q, want it to name the offending algorithm", err)
	}
}

func splitJwt(encodedJwt string) (unsignedToken []byte, encodedSignature string) {
	before, after, _ := strings.CutLast(encodedJwt, ".")

	return []byte(before), after
}

func unsignedToken(encodedJwt string) []byte {
	unsignedToken, _ := splitJwt(encodedJwt)

	return unsignedToken
}

func assertSigns(t *testing.T, algorithm jwa.Signer, key any, encodedJwt string) {
	t.Helper()

	unsignedToken, expectedSignature := splitJwt(encodedJwt)

	signature, err := algorithm.Sign(unsignedToken, key)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if encodedSignature := base64.RawURLEncoding.EncodeToString(signature); encodedSignature != expectedSignature {
		t.Errorf("got %s, want %s", encodedSignature, expectedSignature)
	}
}

func assertVerifies(t *testing.T, algorithm jwa.Verifier, key any, encodedJwt string) {
	t.Helper()

	parts := strings.Split(encodedJwt, ".")

	signature := new(jws.Signature)
	if err := signature.Unmarshal(parts[0], parts[2]); err != nil {
		t.Fatalf("cannot decode signature: %v", err)
	}

	if err := algorithm.Verify(unsignedToken(encodedJwt), signature.Signature, key); err != nil {
		t.Errorf("got unverified token, want verified one: %v", err)
	}
}

const randomSeed = 1

func seedRandom(t *testing.T) {
	t.Helper()

	if fips140.Version() == "v1.0.0" {
		t.Skip("cryptotest.SetGlobalRandom is unsupported against the v1.0.0 Go Cryptographic Module")
	}

	cryptotest.SetGlobalRandom(t, randomSeed)
}

func assertSignsDeterministically(
	t *testing.T, algorithm signerVerifier, privateKey, publicKey any, encodedJwt, expectedSignature string,
) {
	t.Helper()

	seedRandom(t)

	assertPinnedSignature(t, algorithm, privateKey, publicKey, encodedJwt, expectedSignature)
}

func assertPinnedSignature(
	t *testing.T, algorithm signerVerifier, privateKey, publicKey any, encodedJwt, expectedSignature string,
) {
	t.Helper()

	unsignedToken := unsignedToken(encodedJwt)

	signature, err := algorithm.Sign(unsignedToken, privateKey)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if encodedSignature := base64.RawURLEncoding.EncodeToString(signature); encodedSignature != expectedSignature {
		t.Errorf("got %s, want %s", encodedSignature, expectedSignature)
	}

	if err := algorithm.Verify(unsignedToken, signature, publicKey); err != nil {
		t.Errorf("got unverified signature, want verified one: %v", err)
	}
}

func TestHmacSha2(t *testing.T) {
	key := decodeSymmetricKey(t)

	for _, testCase := range []struct {
		algorithm  signerVerifier
		encodedJwt string
	}{
		{jwa.HS256(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.LGyv4nF987S4V9z9qm-803XzhHTFe0o82-JsLGEZCjQ"},
		{jwa.HS384(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.VMTe7ghsLJjKmxnzUrHo1JC4XZJ1hcqxmbTehCLg85z9X8o6SO3SvJXghNiKOB4p"},
		{jwa.HS512(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.HEx0adBavfcTPJ37ZJ1jW3r2JAm6LivHbbxEu8tSdx_zh1Jz0crGJEPt4uhgoRrz5e_ltQcof3ua27w6nj9kDA"},
	} {
		t.Run(testCase.algorithm.String(), func(t *testing.T) {
			t.Run("Signing", func(t *testing.T) {
				assertSigns(t, testCase.algorithm, key, testCase.encodedJwt)
			})

			t.Run("Verifying", func(t *testing.T) {
				assertVerifies(t, testCase.algorithm, key, testCase.encodedJwt)
			})
		})
	}
}

func TestRsassaPkcs1V15(t *testing.T) {
	privateKey := parsePrivateKey(t, rsaPrivateKeyPem)
	publicKey := parsePublicKey(t, rsaPublicKeyPem)

	for _, testCase := range []struct {
		algorithm  signerVerifier
		encodedJwt string
	}{
		{jwa.RS256(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.Gqvjt_J1YHSFr56prGdJhyP3rYCj0pavE2RppXQmnRcc0oJWhRtVgpHfPMiIn_l5_frhQAPMjsk2i4ZchlaOmd1nd1ORSopXeeVp9LnijkTca2k5valjafTFMpuitBZcncsEpv5L22UZJFuLXkZROCZpsZaV5txC0_VHgsO2LJQcQVMqq5BTThPqam9S6DecoPe6H6hqhTLjZwanRmhfNyhH8PB2wQoT84-WLNuQEW_96cKgpKpte1ZZ0EidGVvv7MvvRP9JxiEBH1_b4HN5j2XMbZ4I_zWrNvDV7bKrebIiYmTefdsctLhD-wir4MP85R8gnXu1buHnEtAi8dPAIQ"},
		{jwa.RS384(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.HekPSA7D17ldQIE9eGkPKQgzMvsTNjDvL15RSh3kLXGxmGufbZPR9PGK4cK0UgGqT9Kvg1OHlRSEzBuU936FPSTjC0TlSSWpZj5V3HG9khgn_TdkQJ9B39uGAM0aQAmboNZEmtB1etc_4-JWjwJYSCeSGus_mXs4u_GFZA0QWVk7kkQoSW6pAAIJrGGt017b8u3LoU0XkIHoFghUdh55XGOvflJNV3OWHlxZBOY6vD3_rmF5CErahxkqKB4DTqz5Boy4sxnDPhlYi-Hf7byYDElaLC5Ld7tI9tMXnGY-LpfmHjgfqUl8wimYas_bKMchpFxx5v7LgfgE9TwOkZED0A"},
		{jwa.RS512(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.R1wQmxkXOl0YiJkIYfbMolyGEKNVBmG-b0hGwItyQ8GfYRNkCoEaB52HhegE_cX5XL_207AuTAl6-noPm2Vd6arqnFZUmNtnyQvqlIQIBzHE2zPXRqLgigFGCJw3SN8C0QMGaAeMZo5E5YsyeJaBno21A2z0JElt9Mi0zTbGTDks3iU-UhtpfPgo5w2_AMwhy36NFpwngDECF_28QEXwxRhG3XmYkj-I4ldA5S64CGfQYD84uEWSNVriWBFGuWJP6CZ6l-L-Mwj3wvAURwAmT26dsyYPUiyftMQiaW8uFpQ_RVWMKdTFsoYxmrcnKwJShqv6g_YJ5HbQTlHRrhYbPg"},
	} {
		t.Run(testCase.algorithm.String(), func(t *testing.T) {
			t.Run("Signing", func(t *testing.T) {
				assertSigns(t, testCase.algorithm, privateKey, testCase.encodedJwt)
			})

			t.Run("Verifying", func(t *testing.T) {
				assertVerifies(t, testCase.algorithm, publicKey, testCase.encodedJwt)
			})
		})
	}
}

func TestRsassaPss(t *testing.T) {
	privateKey := parsePrivateKey(t, rsaPrivateKeyPem)
	publicKey := parsePublicKey(t, rsaPublicKeyPem)

	for _, testCase := range []struct {
		algorithm  signerVerifier
		encodedJwt string
		signature  string
	}{
		{jwa.PS256(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.nCboaj0SOmXLAdBfZz5Nj0nau0rTAvL3MLWHz4yMin9Grtle8-heKMiII7BE7m-XwFe1RNVRWszd1cj18BxxVufVRtTNv0oPnLmqvMKmP3UGfolu_puU0aHJNihTjdgCXSH2ICzqODiB7FBnHyDIULojlmzRrBjAj0LrJCMtYJ_OD2jw2Fa88b6iETj05B-njPmLBLay9QsBq1ubxTuK-mFycdHe-POvAM7cLtHtkTwRqlcmpy9YzS92QOvXYGLgfPaIMJw95_3uRZo3AvjxoC-z7pdfc608_v7NBm6u_kRwT2rzg4djXIeuNvOdUhH8cCeYV0ynj7RrgCzpI9lJ6w", "F1yHcJT7ZmPPth1eDnSqBmwhJ_X6o3aUgXXb9YyuOICxRhALcX8diESgcW7nMPBX-zkaMO0KJUwwxaLR9LBCV6KhMvGk3K2Ejqv0UoilngDlxXtcbegCf1gav9-gYKgHZedAXYXOSEPgsNVNi7M6spPJFh26x3N0lJi5IhVrsR3Q8K9CwOhPwJ5YM92etOZ5BVNZjiTen0OBepdKmQjtIwuOpPg-FRZukuMbrfZQXBPXErrsAhO3Eg6Pum-ahbkqFvqJhoJcPYz7LvzK_fbI8GRkjp7-CsIoZiuA7D4Ig0Y8ktPW9AKE1yUnUu8Yb9D6U02YC4q5E9I2yTcFFWecmQ"},
		{jwa.PS384(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.jWuuf3MKdyJx48I29vDn1zCdjxyqXrYpMhdfzVrrQmL2-ArKXnjV8773UV1iSbism2SEXLFqKEfySy4VE1KeUiYmsueAZsRxy1-TUykkwpqO4oH73Qu2EHBszFt7d7DYmxfx6lxcfQRS-Hudnz2M3mAB4I_2yEGD9vRDgsWQxfbJNVQRe70llmUzkVX75J3X4K7uEQxQr-25Jd80jNFYkJoYCfpMVOm2lE4I4Pu5khWqW4QnqKt87xC4vJj-c3Sna5v315-M68kT4UMqDYdn2fqx1E7BZwVM1FH_m97Oe-Ouj7-d-TRPVoaY3mVFm963Vn8WX776WG3Wa7uon_59gg", "x-0VojdNk2AngwqdpULClhLEUGRNM-vT_Y6yUQAZ0bPz3oCtVnVz7huReCsON8dp279aIQlF6QObCnqvCGKgt385y8w55Kzxu-hSNbL1vcqrCX8gaDXaa7tsFl0boZ5A4yY5M6MAv4NCv5q5Wg8EyfAk2MhTrirzcq3Mj6-qpTUoczU9aAy9omad3v3M63sWh0x2NpukrEuxyr_BSTAZvF4eVgsT8PtTbp3HhEM4SxdUk4E9zBF7NDUGJtxG5aKISpjAyHjwD2KGW_o25C6riL6WAafLgyc8YcIfHQD0Bx-evEOly3XmFF-Zo51WbN1EKb-ae5xl3WuqBlmjl-2Taw"},
		{jwa.PS512(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.bvfMZr8ZAjZwhAC124ZLRhMoCdBowUhw2UDjUUL9CVuMeFUe7MGQXJsqBK8D5k4GCO7MKYFnEZ9aVWiVF9wuXAmtLVQKitGPZQbUwmtKqGfM3YBGPCxB7I9_ojN82l_HXboAASmZrSMRbEjHG4FWTpscq9uosNlWd9qZ-WY2JQ8v_T45CDnO5addpR2_Yu_X5vhacAZ2pVXIJN9H6T97hcvWKcJo_G12vCZtvP78mDEbH0J7yUptEzgU-guobGP7pC37D8HXJ-dJGRuTf0x-arZNNyFFkRRs4aEfhWwIUNdDWU-k3dcTgzKVNNP_KUXTswuKms0APeTFFRnJj3yRXw", "RR2BJlVFicda9uofILJWIDBOxojNWytwpnZwscS8oECXlwJRK1e6tb-FKInKRSXAGtKMJbioAQJSTlx55fBBmy_6Vbyeb9Y7d6X7G2wP685GmXu57wx2asmKMKk8UNoedfOMcFLjy5Vykzt4w58ywftv8fZgNp0JSA2kFoe3VysZo2WIzYrMbQHkuqOb3uF8_cUEeFgOA-Gk2-SMK2eBKogWMG6JLAtsVawGIbgvY4r1DiNQNllhE0ESZnpB9bsLRb_e2X0wmg_2F9bjnvXapJ-q6Uv36qpJRlrPgR6J5RK-Xl3Y3bI6b2r7cSqQ1kSbgt2cHifBMxNLf6HnNslu-A"},
	} {
		t.Run(testCase.algorithm.String(), func(t *testing.T) {
			t.Run("Signing", func(t *testing.T) {
				assertSignsDeterministically(
					t, testCase.algorithm, privateKey, publicKey, testCase.encodedJwt, testCase.signature,
				)
			})

			t.Run("Verifying", func(t *testing.T) {
				assertVerifies(t, testCase.algorithm, publicKey, testCase.encodedJwt)
			})
		})
	}
}

func TestEcdsa(t *testing.T) {
	for _, testCase := range []struct {
		algorithm     signerVerifier
		privateKeyPem string
		publicKeyPem  string
		encodedJwt    string
		signature     string
	}{
		{jwa.ES256(), es256PrivateKeyPem, es256PublicKeyPem, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.wFRn3l03KADMQvOE3keZ23ZVV2V80mvvb53tiROsC6_E4ICKu94r7dpLH4Dq2nJbk6saNWJ1IQQZZrl2iNu4Ow", "mOJTlyYMfHyBA_B4xY2WacvzrcGpnbFF8H5W37TFQxrCDnY9K-SOFdhd83DoZaENOGBK6aVUvdPNf01K-ulBww"},
		{jwa.ES384(), es384PrivateKeyPem, es384PublicKeyPem, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.vYdHVVXOyBDHzKsUPqav7e78jyQt84rOfD1wrRp5YFU5uO1UGfzvlAV6q2u0nJ1ordZ4MF1Ou7eMayld7QtTQdkX3YgrD-Lxtz46vKoSt_1PDcbGH8_0ylMaW0b83-XE", "SqCK4yCXeeomlWVaizZc_9sbL_QYMPlAfOF3uJEzD_kIks9MSXH3EyaarqfBeBv4fVXJo6iGZczv07h9a1IVX5KsNF7YhHwIjIjVMghfSeuINUsvgecMselmdM8Q36nM"},
		{jwa.ES512(), es512PrivateKeyPem, es512PublicKeyPem, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.AFCIqeSuQgjYLMi5ZAZSJNlQzz0WNuAX2-GTgCMJ--IPM2bJVMj5jGw4AIT15mVAh2xooG07f9CmagF52FGwjEVaARMGOdy3y62oG4_U3vugI1HeubyxH32I1t8usmUz8P5ocTY7c84lhf7X-N1Bk6S82dVDR5CsuyxDaaAwGrE3Dd9l", "AEv4yw5nZ2D3BgHwl1OT0ijxBs1m1ehbMpEjC59C3p9qXlki3IbZMDF4mc1yia6hNCi8l7Rnh7XQkeBdizYd53tbAGUL4zJ-jRt9MBFTwFkbkA1BTRf07RHunN_KvdOle9liLKgXMC-lNi899KHP-ti513TbNSPicDk_H0nzktu4uZsO"},
	} {
		t.Run(testCase.algorithm.String(), func(t *testing.T) {
			privateKey := parsePrivateKey(t, testCase.privateKeyPem)
			publicKey := parsePublicKey(t, testCase.publicKeyPem)

			t.Run("Signing", func(t *testing.T) {
				assertPinnedSignature(
					t, testCase.algorithm, privateKey, publicKey, testCase.encodedJwt, testCase.signature,
				)
			})

			t.Run("Verifying", func(t *testing.T) {
				assertVerifies(t, testCase.algorithm, publicKey, testCase.encodedJwt)
			})
		})
	}
}

func TestNone(t *testing.T) {
	encodedJwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ."

	t.Run("Signing", func(t *testing.T) {
		assertSigns(t, jwa.None(), nil, encodedJwt)
	})

	t.Run("Verifying", func(t *testing.T) {
		assertVerifies(t, jwa.None(), nil, encodedJwt)
	})
}
