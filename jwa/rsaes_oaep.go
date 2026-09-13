package jwa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// RSAESOAEP is key encryption with RSAES-OAEP. It makes a new CEK and encrypts
// it with the public key of the recipient.
//
// These two algorithms are the RSA key management that this package writes.
// RSA1_5, the other RSA key management algorithm of RFC 7518, decrypts only. See
// [RSAESPKCS1v15].
type RSAESOAEP struct {
	name string

	hash crypto.Hash
}

var (
	rsaOAEP = &RSAESOAEP{"RSA-OAEP", crypto.SHA1}

	rsaOAEP256 = &RSAESOAEP{"RSA-OAEP-256", crypto.SHA256}
)

// RSAOAEP returns RSAES-OAEP with SHA-1 and MGF1-SHA-1. Use [RSAOAEP256] for
// new work.
func RSAOAEP() *RSAESOAEP { return rsaOAEP }

// RSAOAEP256 returns RSAES-OAEP with SHA-256 and MGF1-SHA-256.
func RSAOAEP256() *RSAESOAEP { return rsaOAEP256 }

// String returns the "alg" value of this algorithm, "RSA-OAEP" or
// "RSA-OAEP-256".
func (algorithm *RSAESOAEP) String() string { return algorithm.name }

// EncryptKey returns a new CEK and the JWE Encrypted Key that holds it. It makes
// the CEK and then wraps it.
func (algorithm *RSAESOAEP) EncryptKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	return encryptKey(algorithm, key, encryption, parameters)
}

// WrapKey returns the JWE Encrypted Key for the given cek. It accepts only an
// [*rsa.PublicKey].
//
// RFC 7518 section 4.3 gives a minimum modulus: "A key of size 2048 bits or
// larger MUST be used with these algorithms." WrapKey gives [ErrWeakKey] for a
// smaller modulus.
//
// The OAEP label is empty, because these algorithms have no label. A recipient
// that supplies a label cannot decrypt the key.
func (algorithm *RSAESOAEP) WrapKey(
	cek []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "*rsa.PublicKey")
	}

	if err := checkRSAModulus(algorithm, publicKey.N); err != nil {
		return nil, err
	}

	return rsa.EncryptOAEP(algorithm.hash.New(), rand.Reader, publicKey, cek, nil)
}

// DecryptKey returns the CEK from the JWE Encrypted Key. It accepts only an
// [*rsa.PrivateKey] with a modulus of 2048 bits or more.
//
// DecryptKey gives [ErrDecryptionFailed] for all bad ciphertexts. It does not
// keep the error from the standard library.
//
// OAEP does not prevent all the attacks that broke PKCS #1 v1.5. The Manger
// attack finds a plaintext from an oracle. That oracle shows only the
// difference between an integer-too-large failure and a decode failure. Thus a
// recipient must give the same error for all bad ciphertexts. The crypto/rsa
// package keeps this difference out of its timing, and this error is the other
// half of that protection.
func (algorithm *RSAESOAEP) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "*rsa.PrivateKey")
	}

	if err := checkRSAModulus(algorithm, privateKey.N); err != nil {
		return nil, err
	}

	cek, err := rsa.DecryptOAEP(algorithm.hash.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if err := checkContentEncryptionKeySize(encryption, cek); err != nil {
		return nil, err
	}

	return cek, nil
}
