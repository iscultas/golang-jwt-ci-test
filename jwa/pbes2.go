package jwa

import (
	"crypto"
	"crypto/pbkdf2"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"slices"
)

// PBES2 is password-based key encryption. PBKDF2 changes a password into a key
// encryption key. That key then wraps the CEK with AES Key Wrap.
//
// The security of PBES2 comes from a value that a person selected. No other
// algorithm here has this property. PBKDF2 increases the work that one try
// makes necessary, but it cannot make a weak password strong.
//
// The iteration count sets that work, and it moves in the token as "p2c". Thus
// a sender tells a recipient how much work to do. To obey such a value with no
// limit is a denial of service. [maximumPBES2Count] below gives that limit.
type PBES2 struct {
	name string

	hash crypto.Hash

	keyWrap *AESKeyWrap

	password passwordSize
}

var (
	pbes2HS256A128KW = &PBES2{"PBES2-HS256+A128KW", crypto.SHA256, a128kw, passwordSize{16, 128}}
	pbes2HS384A192KW = &PBES2{"PBES2-HS384+A192KW", crypto.SHA384, a192kw, passwordSize{24, 128}}
	pbes2HS512A256KW = &PBES2{"PBES2-HS512+A256KW", crypto.SHA512, a256kw, passwordSize{32, 128}}
)

// PBES2HS256A128KW returns PBKDF2 with HMAC-SHA-256 and AES-128 key wrapping.
func PBES2HS256A128KW() *PBES2 { return pbes2HS256A128KW }

// PBES2HS384A192KW returns PBKDF2 with HMAC-SHA-384 and AES-192 key wrapping.
func PBES2HS384A192KW() *PBES2 { return pbes2HS384A192KW }

// PBES2HS512A256KW returns PBKDF2 with HMAC-SHA-512 and AES-256 key wrapping.
func PBES2HS512A256KW() *PBES2 { return pbes2HS512A256KW }

// String returns the "alg" value of this algorithm, for example
// "PBES2-HS256+A128KW".
func (algorithm *PBES2) String() string { return algorithm.name }

const (
	minimumPBES2SaltInputSize = 8

	defaultPBES2SaltInputSize = 16

	defaultPBES2Count = 600_000

	minimumPBES2Count = 1000

	maximumPBES2Count = 10_000_000
)

type passwordSize struct{ minimum, maximum int }

// ErrWeakPassword is the error for a password that is not in the recommended
// range.
//
// This package gives the error when it encrypts only. The recommendation is for
// the person who selects the password, and that selection occurs on the
// producer side. To reject a password there makes only a better password
// necessary. On the recipient side a different person made the selection, and
// made it before. To reject the message there does not make the password
// strong. It also keeps a message from a recipient with the right to read it.
// The same asymmetry applies to "zip" and to "b64": do not write a value that
// you continue to read.
var ErrWeakPassword = errors.New("jwa: password outside the recommended length")

// ErrExcessiveIterationCount is the error for a "p2c" value above the limit that
// this package calculates.
//
// The error is different from [ErrDecryptionFailed], and this is correct. The
// count is public in the header, thus this error gives an attacker no new data.
// A sender can select a very high count for a correct token. A recipient must
// be able to see the difference between that condition and an incorrect
// password.
var ErrExcessiveIterationCount = errors.New("jwa: PBES2 iteration count too high")

// ErrInsufficientIterationCount is the error for a "p2c" value below the
// recommended minimum of 1000.
//
// The error is different from [ErrDecryptionFailed] for the same cause as its
// opposite. The count is public in the header, thus this error gives an
// attacker no new data. A token can have a count one thousand times too small.
// A recipient must see the difference between that condition and an incorrect
// password.
var ErrInsufficientIterationCount = errors.New("jwa: PBES2 iteration count too low")

func (algorithm *PBES2) newHash() func() hash.Hash { return algorithm.hash.New }

func (algorithm *PBES2) derive(key any, parameters *KeyParameters) ([]byte, error) {
	password, err := secretOctets(algorithm, key)
	if err != nil {
		return nil, err
	}

	if len(parameters.PBES2SaltInput) < minimumPBES2SaltInputSize {
		return nil, fmt.Errorf(
			"%w: %s: got a %d-octet salt input, want at least %d",
			ErrInvalidKeySize, algorithm, len(parameters.PBES2SaltInput), minimumPBES2SaltInputSize,
		)
	}

	if parameters.PBES2Count < minimumPBES2Count {
		return nil, fmt.Errorf(
			"%w: %s: p2c is %d, want at least %d",
			ErrInsufficientIterationCount, algorithm, parameters.PBES2Count, minimumPBES2Count,
		)
	}

	if parameters.PBES2Count > maximumPBES2Count {
		return nil, fmt.Errorf(
			"%w: %s: p2c is %d, want at most %d", ErrExcessiveIterationCount, algorithm, parameters.PBES2Count, maximumPBES2Count,
		)
	}

	salt := slices.Concat([]byte(algorithm.name), []byte{0}, parameters.PBES2SaltInput)

	return pbkdf2.Key(algorithm.newHash(), string(password), salt, parameters.PBES2Count, algorithm.keyWrap.keySize)
}

// EncryptKey returns a new CEK and the JWE Encrypted Key that holds it. It makes
// the CEK and then wraps it.
func (algorithm *PBES2) EncryptKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	return encryptKey(algorithm, key, encryption, parameters)
}

func (algorithm *PBES2) checkPassword(key any) error {
	password, err := secretOctets(algorithm, key)
	if err != nil {
		return err
	}

	if len(password) < algorithm.password.minimum || len(password) > algorithm.password.maximum {
		return fmt.Errorf(
			"%w: %s: got %d octets, want %d to %d",
			ErrWeakPassword, algorithm, len(password), algorithm.password.minimum, algorithm.password.maximum,
		)
	}

	return nil
}

// WrapKey returns the JWE Encrypted Key for the given cek. It writes the "p2s"
// and "p2c" values into parameters.
//
// WrapKey makes a new salt for each call. It does not read a salt from
// parameters. RFC 7518 section 4.8.1.1 makes this necessary: "A new Salt Input
// value MUST be generated randomly for each encryption operation." A new salt
// for each call, and not for each message, keeps two recipients of one JWE from
// the use of one salt.
//
// WrapKey gives [ErrWeakPassword] for a password that is not in the recommended
// range.
func (algorithm *PBES2) WrapKey(
	cek []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	if err := algorithm.checkPassword(key); err != nil {
		return nil, err
	}

	saltInput := make([]byte, defaultPBES2SaltInputSize)
	if _, err := rand.Read(saltInput); err != nil {
		return nil, err
	}

	parameters.PBES2SaltInput = saltInput
	parameters.PBES2Count = defaultPBES2Count

	keyEncryptionKey, err := algorithm.derive(key, parameters)
	if err != nil {
		return nil, err
	}

	return algorithm.keyWrap.WrapKey(cek, keyEncryptionKey, encryption, parameters)
}

// DecryptKey returns the CEK from the JWE Encrypted Key. It reads the "p2s" and
// "p2c" values from parameters.
//
// DecryptKey gives [ErrInsufficientIterationCount] or
// [ErrExcessiveIterationCount] for a "p2c" value that is not in the limits of
// this package. It does not apply the password length range. See [ErrWeakPassword].
func (algorithm *PBES2) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	keyEncryptionKey, err := algorithm.derive(key, parameters)
	if err != nil {
		return nil, err
	}

	return algorithm.keyWrap.DecryptKey(encryptedKey, keyEncryptionKey, encryption, parameters)
}
