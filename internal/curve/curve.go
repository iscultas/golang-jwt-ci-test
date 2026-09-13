// Package curve names the elliptic curves of crypto/ecdh for error messages.
//
// The [ecdh.Curve] interface has no String method, and the types that have it
// are unexported. Thus each package that must name a curve holds the names. This
// package holds them one time.
package curve

import "crypto/ecdh"

// Ed25519 is the "crv" value for Ed25519 keys.
const Ed25519 = "Ed25519"

// X25519 is the "crv" value for X25519 keys.
const X25519 = "X25519"

// Name returns the "crv" value of a crypto/ecdh curve. A reader compares this
// name with a header.
//
// Name gives "unknown curve" for a curve that this module does not know, and for
// the nil curve of a zero valued key. Thus a caller can put the result in an
// error message and no panic occurs.
func Name(curve ecdh.Curve) string {
	switch curve {
	case ecdh.X25519():
		return X25519
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	}

	return "unknown curve"
}
