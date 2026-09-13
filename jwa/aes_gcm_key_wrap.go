package jwa

import (
	"crypto/cipher"
	"crypto/rand"
	"slices"
)

// AESGCMKeyWrap is key wrapping with AES GCM. It encrypts the CEK with a
// symmetric key that the two parties hold. The mode makes an IV and an
// authentication tag, and the caller writes these as the "iv" and "tag" Header
// Parameters.
//
// These two parameters make this algorithm different from [AESKeyWrap]. They are
// also a risk. GCM becomes very weak if a nonce occurs two times. Two wrap
// operations with one key and one IV give the authentication subkey to an
// attacker. The attacker can then make an incorrect tag. Thus
// [AESGCMKeyWrap.WrapKey]
// makes a new random IV for each operation.
type AESGCMKeyWrap struct {
	symmetricAlgorithm
}

var (
	a128gcmkw = &AESGCMKeyWrap{symmetricAlgorithm{"A128GCMKW", 16}}
	a192gcmkw = &AESGCMKeyWrap{symmetricAlgorithm{"A192GCMKW", 24}}
	a256gcmkw = &AESGCMKeyWrap{symmetricAlgorithm{"A256GCMKW", 32}}
)

// A128GCMKW returns AES-128 GCM key wrapping. The key encryption key has 16
// octets.
func A128GCMKW() *AESGCMKeyWrap { return a128gcmkw }

// A192GCMKW returns AES-192 GCM key wrapping. The key encryption key has 24
// octets.
func A192GCMKW() *AESGCMKeyWrap { return a192gcmkw }

// A256GCMKW returns AES-256 GCM key wrapping. The key encryption key has 32
// octets.
func A256GCMKW() *AESGCMKeyWrap { return a256gcmkw }

func (algorithm *AESGCMKeyWrap) aead(key any) (cipher.AEAD, error) {
	kek, err := algorithm.secret(key)
	if err != nil {
		return nil, err
	}

	return newGCM(kek)
}

// EncryptKey returns a new CEK and the JWE Encrypted Key that holds it. It
// makes the CEK and then wraps it.
//
// EncryptKey writes the "iv" and "tag" values into parameters. The caller must
// put them in the JOSE header. A recipient cannot decrypt the key without
// them.
func (algorithm *AESGCMKeyWrap) EncryptKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	return encryptKey(algorithm, key, encryption, parameters)
}

// WrapKey returns the JWE Encrypted Key for the given cek. It writes the "iv"
// and "tag" values into parameters.
//
// WrapKey makes a new IV for each call. It does not read an IV from parameters.
// RFC 7518 section 4.7.1.1 gives this length: "Use of an IV of size 96 bits is
// REQUIRED with this algorithm."
//
// A new IV for each call, and not for each message, is necessary when a message
// goes to more than one recipient. To wrap one CEK two times with the same key
// and the same IV uses the GCM keystream again. This gives the CEK to an
// attacker.
//
// The Additional Authenticated Data is empty, as RFC 7518 section 4.7 gives it:
// "The Additional Authenticated Data value used is the empty octet string." The
// key wrap operation thus gives no protection to the header. The JWE content
// encryption gives that protection.
func (algorithm *AESGCMKeyWrap) WrapKey(
	cek []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	aead, err := algorithm.aead(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, gcmIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	sealed := aead.Seal(nil, iv, cek, nil)

	parameters.InitializationVector = iv
	parameters.AuthenticationTag = sealed[len(sealed)-gcmTagSize:]

	return sealed[:len(sealed)-gcmTagSize], nil
}

// DecryptKey returns the CEK. It reads the "iv" and "tag" values from
// parameters.
//
// DecryptKey gives [ErrDecryptionFailed] in four conditions:
//
//   - the "iv" or "tag" value is missing
//   - the "iv" or "tag" value has the incorrect length
//   - the authentication check does not agree
//   - the CEK does not have the length that encryption gives
//
// All four conditions come from the token, thus one error is necessary for all
// of them.
func (algorithm *AESGCMKeyWrap) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	aead, err := algorithm.aead(key)
	if err != nil {
		return nil, err
	}

	if len(parameters.InitializationVector) != gcmIVSize || len(parameters.AuthenticationTag) != gcmTagSize {
		return nil, ErrDecryptionFailed
	}

	cek, err := aead.Open(
		nil,
		parameters.InitializationVector,
		slices.Concat(encryptedKey, parameters.AuthenticationTag),
		nil,
	)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if err := checkContentEncryptionKeySize(encryption, cek); err != nil {
		return nil, err
	}

	return cek, nil
}
