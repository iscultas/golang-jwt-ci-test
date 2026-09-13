package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/internal/curve"
)

// ErrUnavailableHash is the error for a hash function that the binary does not
// contain.
//
// [crypto.Hash.New] panics for such a hash. A caller that names a hash which the
// program did not import gets this error and not a stack trace.
var ErrUnavailableHash = errors.New("jwk: unavailable hash")

type thumbprintMember struct {
	name  string
	value string
}

func ellipticCurveThumbprintMembers(publicKey *ecdsa.PublicKey) ([]thumbprintMember, error) {
	curveName, x, y, err := ellipticCurveParameters(publicKey)
	if err != nil {
		return nil, err
	}

	return []thumbprintMember{
		{"crv", curveName},
		{"kty", string(EllipticCurve)},
		{"x", x},
		{"y", y},
	}, nil
}

func rsaThumbprintMembers(publicKey *rsa.PublicKey) []thumbprintMember {
	return []thumbprintMember{
		{"e", bigIntToBase64(big.NewInt(int64(publicKey.E)))},
		{"kty", string(RSA)},
		{"n", bigIntToBase64(publicKey.N)},
	}
}

func octetKeyPairThumbprintMembers(curve string, publicKey []byte) []thumbprintMember {
	return []thumbprintMember{
		{"crv", curve},
		{"kty", string(OctetKeyPair)},
		{"x", base64url.Encode(publicKey)},
	}
}

func akpThumbprintMembers(material any) ([]thumbprintMember, error) {
	publicKey, ok := mldsaPublicKey(material)
	if !ok {
		return nil, fmt.Errorf("%w: %T holds no parameter set", ErrUnsupportedKeyType, material)
	}

	return []thumbprintMember{
		{"alg", mldsaAlgorithms[publicKey.Parameters()].String()},
		{"kty", string(AlgorithmKeyPair)},
		{"pub", base64url.Encode(publicKey.Bytes())},
	}, nil
}

func (key *Key) thumbprintMembers() ([]thumbprintMember, error) {
	switch material := key.material.(type) {
	case *ecdsa.PublicKey:
		return ellipticCurveThumbprintMembers(material)
	case *ecdsa.PrivateKey:
		return ellipticCurveThumbprintMembers(&material.PublicKey)
	case *rsa.PublicKey:
		return rsaThumbprintMembers(material), nil
	case *rsa.PrivateKey:
		return rsaThumbprintMembers(&material.PublicKey), nil
	case ed25519.PublicKey:
		return octetKeyPairThumbprintMembers(Ed25519, material), nil
	case ed25519.PrivateKey:
		return octetKeyPairThumbprintMembers(Ed25519, material.Public().(ed25519.PublicKey)), nil //nolint:forcetypeassert // Public of an ed25519.PrivateKey returns an ed25519.PublicKey, by the contract of that method.
	case *ecdh.PublicKey:
		if material.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: %T on %s", ErrUnsupportedKeyType, material, curve.Name(material.Curve()))
		}

		return octetKeyPairThumbprintMembers(X25519, material.Bytes()), nil
	case *ecdh.PrivateKey:
		if material.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: %T on %s", ErrUnsupportedKeyType, material, curve.Name(material.Curve()))
		}

		return octetKeyPairThumbprintMembers(X25519, material.PublicKey().Bytes()), nil
	case *mldsa.PublicKey, *mldsa.PrivateKey:
		return akpThumbprintMembers(material)
	case []byte:
		return []thumbprintMember{
			{"k", base64url.Encode(material)},
			{"kty", string(OctetSequence)},
		}, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key.material)
	}
}

func canonicalJSONSize(members []thumbprintMember) int {
	size := len("{}")

	for _, member := range members {
		size += len(member.name) + len(member.value) + len(`"":"",`)
	}

	return size
}

func canonicalJSON(destination []byte, members []thumbprintMember) ([]byte, error) {
	canonical := append(destination, '{')

	for index, member := range members {
		if index != 0 {
			canonical = append(canonical, ',')
		}

		var err error

		if canonical, err = jsontext.AppendQuote(canonical, member.name); err != nil {
			return nil, err
		}

		canonical = append(canonical, ':')

		if canonical, err = jsontext.AppendQuote(canonical, member.value); err != nil {
			return nil, err
		}
	}

	return append(canonical, '}'), nil
}

// Thumbprint returns the JWK Thumbprint of the key. It applies hash to the
// canonical JSON of the members that the type of the key makes necessary.
//
// The thumbprint does not include the other members, for example "kid" and "alg". Thus
// a new name for a key does not change its thumbprint. A private key and its
// public half give the same value. See [Key.ThumbprintID] for the base64url
// representation that a "kid" value uses.
//
// Thumbprint gives [ErrUnavailableHash] for a hash function that the binary does
// not contain, and [ErrUnsupportedKeyType] for material that this package cannot
// write.
func (key *Key) Thumbprint(hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("%w: %s", ErrUnavailableHash, hash)
	}

	members, err := key.thumbprintMembers()
	if err != nil {
		return nil, err
	}

	buffer := base64url.GetBuffer()
	defer base64url.PutBuffer(buffer)

	buffer.Grow(canonicalJSONSize(members))

	canonicalKey, err := canonicalJSON(buffer.AvailableBuffer(), members)
	if err != nil {
		return nil, err
	}

	digest := hash.New()

	if _, err := digest.Write(canonicalKey); err != nil {
		return nil, err
	}

	return digest.Sum(nil), nil
}

// ThumbprintID returns the thumbprint of the key in the representation for a
// "kid" value: base64url, with no padding.
//
// Give the result to [WithID] to name a key by its content. A JWK Set and the
// tokens that point to it then agree on the name with no other communication.
func (key *Key) ThumbprintID(hash crypto.Hash) (string, error) {
	thumbprint, err := key.Thumbprint(hash)
	if err != nil {
		return "", err
	}

	return base64url.Encode(thumbprint), nil
}

// ThumbprintURIPrefix is the JWK Thumbprint URI prefix. It shows that a JWK
// Thumbprint comes after it.
const ThumbprintURIPrefix = "urn:ietf:params:oauth:jwk-thumbprint"

// ErrUnregisteredHashName is the error for a hash function with no row in the
// IANA "Named Information Hash Algorithm" registry. Such a hash has no name for a
// JWK Thumbprint URI.
//
// RFC 9278 section 4 makes the identifier in such a URI come from the "Hash Name
// String" column of that registry. A URI that names a different value "is not
// considered valid".
var ErrUnregisteredHashName = errors.New("jwk: hash has no Named Information registry name")

var hashNames = map[crypto.Hash]string{
	crypto.SHA256: "sha-256",
	crypto.SHA384: "sha-384",
	crypto.SHA512: "sha-512",
}

var hashesByName = func() map[string]crypto.Hash {
	hashes := make(map[string]crypto.Hash, len(hashNames))
	for hash, name := range hashNames {
		hashes[name] = hash
	}

	return hashes
}()

// ThumbprintURI returns the thumbprint of the key as a JWK Thumbprint URI. The
// URI holds the prefix, the registered name of the hash, and the thumbprint,
// with a colon between each part. Thus a thumbprint can be a key identifier
// where a URI is necessary.
//
// SHA-256 is mandatory to implement. Give [crypto.SHA256] if a peer does not
// give a different hash.
//
// ThumbprintURI gives [ErrUnregisteredHashName] for a hash with no row in the
// IANA registry.
func (key *Key) ThumbprintURI(hash crypto.Hash) (string, error) {
	name, ok := hashNames[hash]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnregisteredHashName, hash)
	}

	thumbprintID, err := key.ThumbprintID(hash)
	if err != nil {
		return "", err
	}

	return ThumbprintURIPrefix + ":" + name + ":" + thumbprintID, nil
}

// ErrMalformedThumbprintURI is the error for a string that does not have the
// shape of a JWK Thumbprint URI. That shape is the prefix, a hash algorithm
// identifier, and a JWK Thumbprint value, with a colon between each part.
//
// A URI with the correct shape but an unregistered hash identifier gives
// [ErrUnregisteredHashName], because the registry does not name that hash.
var ErrMalformedThumbprintURI = errors.New("jwk: malformed JWK Thumbprint URI")

// ParseThumbprintURI reads a JWK Thumbprint URI. It gives the hash that the URI
// names and the thumbprint that the URI holds. It is the opposite of
// [Key.ThumbprintURI], for an application that gets such a URI as a key
// identifier.
//
// The octets come back decoded and not in their base64url representation. Thus
// a caller can compare them directly with the result of [Key.Thumbprint]. This
// function also checks the encoding for the caller.
//
// ParseThumbprintURI makes four checks. RFC 9278 gives three of them:
//
//   - the prefix
//   - the shape with colons
//   - the rule that an identifier which is not in the IANA "Named Information
//     Hash Algorithm Registry" makes the URI "not considered valid"
//
// This package adds the fourth check, which is the width of the thumbprint. A
// "sha-256" URI that holds twenty octets names a digest that SHA-256 cannot
// make, and a reader can only reject it.
func ParseThumbprintURI(uri string) (crypto.Hash, []byte, error) {
	rest, ok := strings.CutPrefix(uri, ThumbprintURIPrefix+":")
	if !ok {
		return 0, nil, fmt.Errorf("%w: %s", ErrMalformedThumbprintURI, uri)
	}

	name, encodedThumbprint, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, nil, fmt.Errorf("%w: no thumbprint after the hash name: %s", ErrMalformedThumbprintURI, uri)
	}

	hash, ok := hashesByName[name]
	if !ok {
		return 0, nil, fmt.Errorf("%w: %s", ErrUnregisteredHashName, name)
	}

	thumbprint, err := base64url.Decode(encodedThumbprint)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrMalformedThumbprintURI, err)
	}

	if len(thumbprint) != hash.Size() {
		return 0, nil, fmt.Errorf(
			"%w: %s names a %d-octet digest, but the thumbprint is %d",
			ErrMalformedThumbprintURI, name, hash.Size(), len(thumbprint),
		)
	}

	return hash, thumbprint, nil
}
