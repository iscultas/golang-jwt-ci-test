package jwa

import "fmt"

// Direct is "dir", the direct encryption mode. The two parties agree on a
// symmetric key before use, and that key is the Content Encryption Key. Direct
// does not wrap the key.
//
// Direct is the one key management algorithm that does no cryptography. It
// supplies the two rules that make the mode safe. The agreed key has the same
// length that the "enc" algorithm gives, and the JWE Encrypted Key is empty.
//
// Read RFC 7518 section 8.2 before you select this mode. The same CEK encrypts
// all messages. Thus the mode has none of the key lifetime properties of the
// modes that wrap a key.
//
// Direct does not supply [KeyWrapper], and this is correct. The CEK is the agreed
// key, thus there is no other CEK that this mode can transmit. A JWE for more
// than one recipient thus cannot use it. Because the method is missing, the jwe
// package rejects this mode at the type level. This is more safe than a check in
// the code.
type Direct struct{}

var direct = &Direct{}

// Dir returns the "dir" direct encryption algorithm. See [Direct] for the
// properties of this mode.
func Dir() *Direct { return direct }

// String returns the "alg" value "dir".
func (algorithm *Direct) String() string { return "dir" }

func (algorithm *Direct) sharedKey(key any, encryption ContentEncrypter) ([]byte, error) {
	cek, err := secretOctets(algorithm, key)
	if err != nil {
		return nil, err
	}

	if len(cek) != encryption.KeySize() {
		return nil, fmt.Errorf(
			"%w: %s with %s: got %d octets, want %d",
			ErrInvalidKeySize, algorithm, encryption, len(cek), encryption.KeySize(),
		)
	}

	return cek, nil
}

// EncryptKey returns the agreed key as the Content Encryption Key, and an empty
// JWE Encrypted Key. RFC 7518 section 4.5 gives this value: "An empty octet
// sequence is used as the JWE Encrypted Key value."
//
// EncryptKey gives [ErrInvalidKeySize] if the agreed key does not have the
// length that encryption gives.
func (algorithm *Direct) EncryptKey(
	key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, []byte, error) {
	cek, err := algorithm.sharedKey(key, encryption)
	if err != nil {
		return nil, nil, err
	}

	return cek, []byte{}, nil
}

// DecryptKey returns the agreed key as the Content Encryption Key.
//
// DecryptKey gives [ErrDecryptionFailed] if encryptedKey is not empty. A JWE
// Encrypted Key with octets in it shows that the sender did not use "dir", also
// if the header gives a different indication. To ignore those octets can let a
// token transmit key data that no recipient reads. It can also let this
// algorithm accept a serialization that it does not write.
func (algorithm *Direct) DecryptKey(
	encryptedKey []byte, key any, encryption ContentEncrypter, parameters *KeyParameters,
) ([]byte, error) {
	cek, err := algorithm.sharedKey(key, encryption)
	if err != nil {
		return nil, err
	}

	if len(encryptedKey) != 0 {
		return nil, ErrDecryptionFailed
	}

	return cek, nil
}
