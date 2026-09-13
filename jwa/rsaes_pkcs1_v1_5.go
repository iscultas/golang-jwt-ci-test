package jwa

import "crypto/rsa"

// RSAESPKCS1v15 is key encryption with RSAES-PKCS1-v1_5. This package decrypts
// with it and does not encrypt with it. It reads a JWE that names RSA1_5, and it
// writes no such JWE.
//
// The type has no EncryptKey method and no WrapKey method, thus it is a
// [KeyDecrypter] and not a [KeyEncrypter]. The two directions have different
// risk. To read a message is a decision of one recipient. To write one puts a
// ciphertext with this padding on the network, where an attacker can collect it
// and use it.
//
// RFC 8725 section 3.2 asks each application to "Avoid all RSA-PKCS1 v1.5
// encryption algorithms ..., preferring RSAES-OAEP". Use [RSAOAEP256] for new
// work.
//
// RFC 7516 section 11.4 gives the attack that this advice is about, which is the
// Bleichenbacher adaptive chosen ciphertext attack on PKCS #1 v1.5 padding. That
// attack needs an oracle that tells correct padding from incorrect padding.
// [RSAESPKCS1v15.DecryptKey] gives no such oracle.
//
// The standard library is more careful than that, and this type keeps its
// warning: the protections are "limited and fragile", and they stop if a later
// operation shows the difference between a real key and a substituted one. Thus
// this type is for a producer that a recipient cannot change, and [RSAOAEP256] is
// for each other condition.
type RSAESPKCS1v15 struct{}

var rsa15 = &RSAESPKCS1v15{}

// RSA15 returns RSAES-PKCS1-v1_5 key decryption.
func RSA15() *RSAESPKCS1v15 { return rsa15 }

// String returns the "alg" value of this algorithm, "RSA1_5".
func (algorithm *RSAESPKCS1v15) String() string { return "RSA1_5" }

// DecryptKey returns the CEK from the JWE Encrypted Key. It accepts only an
// [*rsa.PrivateKey].
//
// RFC 7518 section 4.2 gives a minimum modulus: "A key of size 2048 bits or
// larger MUST be used with this algorithm." DecryptKey gives [ErrWeakKey] for a
// smaller modulus. That length is a property of the key of the recipient, and an
// attacker selects no part of it.
//
// DecryptKey gives no indication of incorrect padding. It makes a random CEK of
// the length that the "enc" algorithm gives, and the unwrap writes the octets of
// the message on that value only when the padding is correct. The two conditions
// take the same time and give the same result to a caller. An unwrap that did not
// occur thus becomes an unsuccessful tag check in the content decryption, which
// is [ErrDecryptionFailed].
//
// This behavior is the countermeasure to the Bleichenbacher attack. RFC 7516
// section 11.5 recommends it, and the same section makes the single error
// necessary: "the recipient MUST NOT distinguish between format, padding, and
// length errors of encrypted keys." An attacker who can tell correct padding from
// incorrect padding can find the plaintext of a ciphertext that the attacker
// cannot decrypt. Thus this method does not report that difference, and a caller
// must not add such a report.
//
// A failure that the padding has no part in gives [ErrDecryptionFailed]. The
// example is an encrypted key that is not less than the modulus. The modulus is
// public, thus each party can make that comparison.
func (algorithm *RSAESPKCS1v15) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, invalidKeyType(algorithm, key, "*rsa.PrivateKey")
	}

	if err := checkRSAModulus(algorithm, privateKey.N); err != nil {
		return nil, err
	}

	cek, err := GenerateContentEncryptionKey(encryption)
	if err != nil {
		return nil, err
	}

	//nolint:staticcheck // The deprecation is the position this type takes. RFC 7519 section 8 makes RSA1_5 necessary, and this function is the one part of the standard library that gives the countermeasure of RFC 7516 section 11.5. To decrypt with rsa.DecryptPKCS1v15 in its place would make the oracle that this type exists to close.
	if err := rsa.DecryptPKCS1v15SessionKey(nil, privateKey, encryptedKey, cek); err != nil {
		return nil, ErrDecryptionFailed
	}

	return cek, nil
}
