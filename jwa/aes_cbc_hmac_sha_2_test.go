package jwa_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("cannot decode %q: %v", value, err)
	}

	return decoded
}

func TestAESCBCHMACSHA2ReproducesAppendixB(t *testing.T) {
	for _, vector := range aesCBCHMACSHA2Vectors {
		t.Run(vector.name, func(t *testing.T) {
			ciphertext, tag, err := vector.algorithm.Encrypt(
				decodeHex(t, vector.p), decodeHex(t, vector.k), decodeHex(t, vector.iv), decodeHex(t, vector.a),
			)
			if err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			for _, output := range []struct {
				name      string
				got, want []byte
			}{
				{"E", ciphertext, decodeHex(t, vector.e)},
				{"T", tag, decodeHex(t, vector.t)},
			} {
				if !bytes.Equal(output.got, output.want) {
					t.Errorf("%s mismatch:\n got %x\nwant %x", output.name, output.got, output.want)
				}
			}
		})
	}
}

func TestAESCBCHMACSHA2DecryptsAppendixB(t *testing.T) {
	for _, vector := range aesCBCHMACSHA2Vectors {
		t.Run(vector.name, func(t *testing.T) {
			plaintext, err := vector.algorithm.Decrypt(
				decodeHex(t, vector.e),
				decodeHex(t, vector.k),
				decodeHex(t, vector.iv),
				decodeHex(t, vector.a),
				decodeHex(t, vector.t),
			)
			if err != nil {
				t.Fatalf("cannot decrypt: %v", err)
			}

			if want := decodeHex(t, vector.p); !bytes.Equal(plaintext, want) {
				t.Errorf("P mismatch:\n got %x\nwant %x", plaintext, want)
			}
		})
	}
}

func TestAESCBCHMACSHA2RejectsTamperedInput(t *testing.T) {
	for _, vector := range aesCBCHMACSHA2Vectors {
		t.Run(vector.name, func(t *testing.T) {
			for _, tampered := range []string{"ciphertext", "iv", "aad", "tag"} {
				t.Run(tampered, func(t *testing.T) {
					length := 1
					if tampered == "tag" {
						length = len(decodeHex(t, vector.t))
					}

					for i := range length {
						ciphertext := decodeHex(t, vector.e)
						iv := decodeHex(t, vector.iv)
						additionalAuthenticatedData := decodeHex(t, vector.a)
						tag := decodeHex(t, vector.t)

						switch tampered {
						case "ciphertext":
							ciphertext[i] ^= 1
						case "iv":
							iv[i] ^= 1
						case "aad":
							additionalAuthenticatedData[i] ^= 1
						case "tag":
							tag[i] ^= 1
						}

						_, err := vector.algorithm.Decrypt(
							ciphertext, decodeHex(t, vector.k), iv, additionalAuthenticatedData, tag,
						)

						if !errors.Is(err, jwa.ErrDecryptionFailed) {
							t.Errorf("octet %d: got %v, want ErrDecryptionFailed", i, err)
						}
					}
				})
			}
		})
	}
}

func TestAESCBCHMACSHA2RejectsAShortTag(t *testing.T) {
	for _, vector := range aesCBCHMACSHA2Vectors {
		t.Run(vector.name, func(t *testing.T) {
			tag := decodeHex(t, vector.t)

			for length := range tag {
				_, err := vector.algorithm.Decrypt(
					decodeHex(t, vector.e),
					decodeHex(t, vector.k),
					decodeHex(t, vector.iv),
					decodeHex(t, vector.a),
					tag[:length],
				)

				if !errors.Is(err, jwa.ErrDecryptionFailed) {
					t.Errorf("%d-octet tag: got %v, want ErrDecryptionFailed", length, err)
				}
			}
		})
	}
}

func TestAESCBCHMACSHA2RejectsWrongKeySize(t *testing.T) {
	for _, vector := range aesCBCHMACSHA2Vectors {
		t.Run(vector.name, func(t *testing.T) {
			cek := decodeHex(t, vector.k)

			for _, size := range []int{len(cek) - 1, len(cek) + 1, 0} {
				_, _, err := vector.algorithm.Encrypt(
					[]byte("plaintext"), make([]byte, size), decodeHex(t, vector.iv), nil,
				)

				if !errors.Is(err, jwa.ErrInvalidKeySize) {
					t.Errorf("%d-octet key: got %v, want ErrInvalidKeySize", size, err)
				}
			}
		})
	}
}

func TestAESCBCHMACSHA2PadsAWholeNumberOfBlocks(t *testing.T) {
	algorithm := jwa.A128CBCHS256()

	cek := make([]byte, algorithm.KeySize())
	iv := make([]byte, algorithm.IVSize())

	for _, length := range []int{0, 1, 15, 16, 17, 31, 32} {
		plaintext := bytes.Repeat([]byte{16}, length)

		ciphertext, tag, err := algorithm.Encrypt(plaintext, cek, iv, nil)
		if err != nil {
			t.Fatalf("%d octets: cannot encrypt: %v", length, err)
		}

		if want := (length/16 + 1) * 16; len(ciphertext) != want {
			t.Errorf("%d octets: got a %d-octet ciphertext, want %d", length, len(ciphertext), want)
		}

		decrypted, err := algorithm.Decrypt(ciphertext, cek, iv, nil, tag)
		if err != nil {
			t.Fatalf("%d octets: cannot decrypt: %v", length, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("%d octets: round trip changed the plaintext: got %x, want %x", length, decrypted, plaintext)
		}
	}
}
