package curve_test

import (
	"crypto/ecdh"
	"testing"

	"github.com/iscultas/jwt-go/internal/curve"
)

func TestNameGivesTheRegisteredCurveName(t *testing.T) {
	for _, test := range []struct {
		name  string
		curve ecdh.Curve
		want  string
	}{
		{"X25519", ecdh.X25519(), "X25519"},
		{"P256", ecdh.P256(), "P-256"},
		{"P384", ecdh.P384(), "P-384"},
		{"P521", ecdh.P521(), "P-521"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := curve.Name(test.curve); got != test.want {
				t.Errorf("Name gives %q, want %q", got, test.want)
			}
		})
	}
}

func TestNameAcceptsTheNilCurve(t *testing.T) {
	if got := curve.Name(nil); got != "unknown curve" {
		t.Errorf("Name gives %q, want %q", got, "unknown curve")
	}
}
