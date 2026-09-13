// Package jwa supplies the algorithms of JSON Web Algorithms, RFC 7518.
//
// The package has three groups of algorithms:
//
//   - Signature algorithms sign and verify a JWS. They are "alg" values. See
//     [Signer] and [Verifier].
//   - Content encryption algorithms encrypt the JWE Plaintext with a Content
//     Encryption Key. They are "enc" values. See [ContentEncrypter].
//   - Key management algorithms give protection to the Content Encryption Key
//     for each recipient. They are "alg" values. See [KeyEncrypter] and
//     [KeyDecrypter].
//
// A function supplies each algorithm, for example [HS256] or [A128GCM].
// [ByName] finds an algorithm from its "alg" or "enc" name, and [Algorithms]
// gives all of them.
//
// Two parts of RFC 7518 are different here. RSA1_5 decrypts and does not
// encrypt. See [RSAESPKCS1v15] for the cause. [None] is available, but it
// accepts all tokens with an empty signature, thus a caller must remove it from
// a verification allowlist.
package jwa

import (
	"crypto"
	"crypto/rand"
	// crypto.Hash.New panics on a hash that nothing has linked in. Registering
	// them is this package's own business rather than its callers': importing jwa
	// and signing with it must not depend on some other package happening to pull
	// the same implementations in.
	//
	// SHA-1 is here for RSA-OAEP alone, whose parameters RFC 7518 section 4.3
	// inherits from RFC 3447 Appendix A.2.1. No signature algorithm in this
	// package uses it, and none should.
	_ "crypto/sha1" //nolint:gosec // RSA-OAEP only, per the comment above. No signature algorithm here uses it.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Algorithm is the interface that all algorithms in this package supply. String
// gives the "alg" or "enc" value of the algorithm, as the IANA registry has it.
type Algorithm interface {
	String() string
}

// Signer is an "alg" algorithm that signs a JWS.
//
// Sign accepts the key material as an untyped value. Each algorithm gives the type
// that it accepts, and gives [ErrInvalidKeyType] for a different type.
type Signer interface {
	Algorithm
	Sign(token []byte, key any) ([]byte, error)
}

// Verifier is an "alg" algorithm that verifies a JWS.
//
// Verify gives a nil error only for a correct signature. It gives
// [ErrSignatureMismatch] for a signature that the key and the token do not
// agree with, [ErrInvalidKeyType] or [ErrWeakKey] for a key that the algorithm
// cannot use, and [ErrMalformedSignature] for a signature of a length that the
// algorithm cannot make.
//
// One error result is necessary, and not an error with a second result. Two
// results give four conditions, but only three conditions are possible.
// Different algorithms then use different results for the same incorrect
// signature.
type Verifier interface {
	Algorithm
	Verify(unsignedToken, signature []byte, key any) error
}

// ContentEncrypter is an "enc" algorithm. It does authenticated encryption of
// the JWE Plaintext with a Content Encryption Key.
//
// The IV is a parameter, and the algorithm does not make one. The serialization
// keeps the IV as one part, thus a recipient supplies it again on decryption. A
// parameter also lets this package do the published test vectors again, because
// those vectors give the IV.
//
// Encrypt gives the tag apart from the ciphertext, for the same cause: the
// serialization keeps the two apart, also where the mode attaches them.
type ContentEncrypter interface {
	Algorithm

	// KeySize is the necessary length of the CEK in octets. Each algorithm fixes
	// this length. There is no negotiation, and no other length is correct.
	KeySize() int

	// IVSize is the necessary length of the IV in octets.
	IVSize() int

	// Encrypt gives the ciphertext and the authentication tag as two values.
	Encrypt(plaintext, cek, iv, additionalAuthenticatedData []byte) (ciphertext, tag []byte, err error)
	// Decrypt gives the plaintext. It gives [ErrDecryptionFailed] for each
	// failure that depends on the token.
	Decrypt(ciphertext, cek, iv, additionalAuthenticatedData, tag []byte) (plaintext []byte, err error)
}

// KeyParameters holds the JOSE header parameters that a key management algorithm
// writes on encryption and reads again on decryption. They are "epk", "apu" and
// "apv" for ECDH-ES, "iv" and "tag" for the AES GCM key wrapping algorithms, and
// "p2s" and "p2c" for PBES2.
//
// This type is necessary because the dependency goes in the other direction: the
// header package uses jwa, thus jwa cannot name a header.Header. This struct
// is between the two packages, and the header package changes the values in the
// two directions.
type KeyParameters struct {
	// EphemeralPublicKey is "epk". It holds a public key in the same any type that
	// the other parts of this package use for key material. For the three NIST
	// curves this is an [*ecdsa.PublicKey].
	EphemeralPublicKey any

	// AgreementPartyUInfo and AgreementPartyVInfo are "apu" and "apv". The two are
	// optional. The Concat KDF receives the two values, thus a recipient that
	// removes one derives a different key.
	AgreementPartyUInfo []byte
	AgreementPartyVInfo []byte

	// InitializationVector and AuthenticationTag are "iv" and "tag". They belong
	// to the key wrap operation. They are different from the IV and the tag of the
	// JWE content.
	InitializationVector []byte
	AuthenticationTag    []byte

	// PBES2SaltInput and PBES2Count are "p2s" and "p2c".
	PBES2SaltInput []byte
	PBES2Count     int
}

// KeyEncrypter is an "alg" algorithm on the producer side. It selects a Content
// Encryption Key and makes the JWE Encrypted Key.
//
// EncryptKey gives the CEK and does not accept one, because two of the five key
// management modes do not encrypt a CEK. Direct encryption uses the symmetric key
// as the CEK, and direct key agreement uses the agreed secret. The two modes give an
// empty encrypted key and a CEK that the caller did not select. The algorithm
// makes this decision, thus the caller does not see the difference.
type KeyEncrypter interface {
	Algorithm

	EncryptKey(key any, encryption ContentEncrypter, parameters *KeyParameters) (cek, encryptedKey []byte, err error)
}

// KeyWrapper is the part of [KeyEncrypter] that can encrypt a Content Encryption
// Key which it did not select. All "alg" algorithms supply it, but the two direct
// modes do not.
//
// This difference is the function of the interface. A JWE for some recipients
// encrypts the content one time and does the key management step again for each
// recipient. Thus each JWE Encrypted Key must hold the same CEK, and the
// algorithm must accept one. Direct encryption cannot do this: the symmetric
// key is the CEK, and Direct Key Agreement makes the agreed secret the CEK. A
// producer selects no part of the two values, thus the two modes cannot send to
// a second recipient. The missing WrapKey method makes this a property of the
// types, and not a check that a person can ignore.
type KeyWrapper interface {
	KeyEncrypter

	// WrapKey encrypts a CEK that is available, and writes each parameter that
	// the recipient needs. It is the second step of EncryptKey, after EncryptKey
	// selects a CEK.
	WrapKey(
		cek []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
	) (encryptedKey []byte, err error)
}

// KeyDecrypter is an "alg" algorithm on the recipient side. DecryptKey
// reads the JWE Encrypted Key and gives the Content Encryption Key.
type KeyDecrypter interface {
	Algorithm

	DecryptKey(
		encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
	) (cek []byte, err error)
}

func encryptKey(
	algorithm KeyWrapper, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	cek, err := GenerateContentEncryptionKey(encryption)
	if err != nil {
		return nil, nil, err
	}

	encryptedKey, err := algorithm.WrapKey(cek, key, encryption, parameters)
	if err != nil {
		return nil, nil, err
	}

	return cek, encryptedKey, nil
}

// GenerateContentEncryptionKey returns a new CEK of the length that the "enc"
// algorithm gives.
//
// This package exports it for the multi-recipient condition. There the caller makes the
// CEK one time for the message and then wraps it for each recipient. Thus no key
// management algorithm selects it.
func GenerateContentEncryptionKey(encryption ContentEncrypter) ([]byte, error) {
	cek := make([]byte, encryption.KeySize())

	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}

	return cek, nil
}

func checkContentEncryptionKeySize(encryption ContentEncrypter, cek []byte) error {
	if len(cek) != encryption.KeySize() {
		return ErrDecryptionFailed
	}

	return nil
}

var registry = func() map[string]Algorithm {
	registry := map[string]Algorithm{}

	for _, algorithm := range []Algorithm{
		none,
		hs256, hs384, hs512,
		rs256, rs384, rs512,
		es256, es384, es512,
		ps256, ps384, ps512,
		eddsa, ed25519Algorithm,

		mldsa44, mldsa65, mldsa87,

		a128cbcHS256, a192cbcHS384, a256cbcHS512,
		a128gcm, a192gcm, a256gcm,

		direct,
		rsa15, rsaOAEP, rsaOAEP256,
		a128kw, a192kw, a256kw,
		a128gcmkw, a192gcmkw, a256gcmkw,
		ecdhES, ecdhESA128KW, ecdhESA192KW, ecdhESA256KW,
		pbes2HS256A128KW, pbes2HS384A192KW, pbes2HS512A256KW,
	} {
		registry[algorithm.String()] = algorithm
	}

	return registry
}()

// ByName returns the algorithm with the given "alg" or "enc" value, and reports
// whether such an algorithm is available.
//
// The "alg" and "enc" names are in one map. IANA keeps two registries, but the
// names in them are disjoint. Thus one lookup is sufficient for a JOSE header
// and for a JWK "alg" member.
//
// The interface that each caller applies keeps the two groups apart. The jws
// package applies a [Signer] or a [Verifier]. The jwe package applies a
// [KeyEncrypter] or a [ContentEncrypter].
func ByName(name string) (Algorithm, bool) {
	algorithm, ok := registry[name]

	return algorithm, ok
}

// Algorithms returns each algorithm of this package, in the sequence of their
// names.
//
// A caller that uses the result as a verification allowlist must remove [None]
// first. None accepts all tokens with an empty signature.
//
// The result holds [RSAESPKCS1v15] also. A caller that uses it as a decryption
// allowlist thus accepts RSA1_5, which the default configuration of the jwt
// package does not accept.
func Algorithms() []Algorithm {
	algorithms := make([]Algorithm, 0, len(registry))
	for _, algorithm := range registry {
		algorithms = append(algorithms, algorithm)
	}

	slices.SortFunc(algorithms, func(a, b Algorithm) int { return strings.Compare(a.String(), b.String()) })

	return algorithms
}

// ErrUnsupportedAlgorithm is the error for an "alg" member that names an
// algorithm which this package does not supply.
var ErrUnsupportedAlgorithm = errors.New("jwa: unsupported algorithm")

// UnsupportedAlgorithm returns an [ErrUnsupportedAlgorithm] that names the
// value. It is for packages that read an "alg" member through [ByName].
func UnsupportedAlgorithm(name string) error {
	return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, name)
}

// ErrInvalidKeyType is the error from Sign and Verify for key material that does
// not have the type that the algorithm accepts.
var ErrInvalidKeyType = errors.New("jwa: invalid key type")

// ErrMalformedSignature is the error from Verify for a signature that the
// algorithm cannot make, for all keys.
var ErrMalformedSignature = errors.New("jwa: malformed signature")

// ErrSignatureMismatch is the error from Verify for a signature that has the
// correct syntax, but that the key and the token do not agree with. It is the
// usual result of verification with the incorrect key.
//
// A signature that no key can make gives [ErrMalformedSignature] and not this
// error. That error shows a malformed token. This error shows only that the
// signature and the key do not agree.
var ErrSignatureMismatch = errors.New("jwa: signature does not match")

// ErrWeakKey is the error for a key that has the correct syntax but is smaller
// than the algorithm accepts.
//
// Each family has a minimum. The minimum HMAC key length is the length of the
// hash output, and the minimum RSA modulus is 2048 bits.
//
// Verify gives this error, and Sign gives it also. A verifier that accepts a
// small key accepts a signature that is easier to forge than its "alg" value
// shows. That is the full damage. As in other parts of this module, a signature
// that this package does not write is not a signature that it accepts.
var ErrWeakKey = errors.New("jwa: key too small for algorithm")

// ErrInvalidKeySize is the error for a Content Encryption Key that does not have
// the length that its algorithm gives.
//
// It is different from [ErrWeakKey]. A short HMAC secret is a weak example of a
// correct key. But each algorithm has one CEK length, and a different length is
// a different algorithm.
var ErrInvalidKeySize = errors.New("jwa: wrong key size for algorithm")

// ErrInvalidInitializationVector is the error for an IV that does not have the
// length that its algorithm gives.
//
// Only the encryption path gives this error. On the decryption path an incorrect
// length comes from the token, thus that path gives [ErrDecryptionFailed].
var ErrInvalidInitializationVector = errors.New("jwa: wrong initialization vector size for algorithm")

// ErrDecryptionFailed is the one error for each decryption failure with a cause
// in the token. Examples are a tag that does not agree, an incorrect length, bad
// padding, and an unwrap that did not verify.
//
// One error, and not some errors, is correct. A recipient must not show an
// attacker which check rejected a message. A decryption oracle from those
// distinctions changes a rejected ciphertext into a plaintext that an attacker
// can read.
//
// A failure with a cause in the key of the recipient, and not in the token,
// keeps a different error. A key of the incorrect type or length is such a
// failure. An attacker selects no part of that key.
var ErrDecryptionFailed = errors.New("jwa: decryption failed")

// ErrDirectKeyManagement is the error from the two direct modes. It occurs when
// such a mode must encrypt a Content Encryption Key that it did not select.
//
// Direct encryption uses the symmetric key that the two parties hold as the CEK.
// Direct Key Agreement uses the agreed secret. Thus the two modes cannot
// transmit a CEK from a different source. A JWE for some recipients makes that
// necessary, and thus cannot use these modes. This is a property of the
// algorithms, not a limit of this package. See [KeyWrapper].
var ErrDirectKeyManagement = errors.New("jwa: direct key management cannot encrypt a given key")

func invalidKeyType(algorithm Algorithm, key any, expected string) error {
	return fmt.Errorf("%w: %s: got %T, want %s", ErrInvalidKeyType, algorithm, key, expected)
}

type signingAlgorithm struct {
	name string
	hash crypto.Hash
}

// String returns the "alg" value of this algorithm.
func (algorithm *signingAlgorithm) String() string {
	return algorithm.name
}

func (algorithm *signingAlgorithm) digest(token []byte) ([]byte, error) {
	hash := algorithm.hash.New()

	if _, err := hash.Write(token); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

type symmetricAlgorithm struct {
	name string

	keySize int
}

// String returns the "alg" or "enc" value of this algorithm.
func (algorithm *symmetricAlgorithm) String() string { return algorithm.name }

func (algorithm *symmetricAlgorithm) checkKeySize(secret []byte) error {
	if len(secret) != algorithm.keySize {
		return fmt.Errorf(
			"%w: %s: got %d octets, want %d", ErrInvalidKeySize, algorithm, len(secret), algorithm.keySize,
		)
	}

	return nil
}

func (algorithm *symmetricAlgorithm) secret(key any) ([]byte, error) {
	octets, err := secretOctets(algorithm, key)
	if err != nil {
		return nil, err
	}

	if err := algorithm.checkKeySize(octets); err != nil {
		return nil, err
	}

	return octets, nil
}

func secretOctets(algorithm Algorithm, key any) ([]byte, error) {
	octets, ok := key.([]byte)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "[]byte")
	}

	return octets, nil
}
