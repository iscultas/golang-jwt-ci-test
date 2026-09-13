package jwa

import (
	"crypto/elliptic"
	"testing"
)

func TestCurveNameNamesEachCurve(t *testing.T) {
	for _, test := range []struct {
		curve elliptic.Curve
		want  string
	}{
		{elliptic.P256(), "P-256"},
		{elliptic.P384(), "P-384"},
		{elliptic.P521(), "P-521"},
	} {
		t.Run(test.want, func(t *testing.T) {
			if got := curveName(test.curve); got != test.want {
				t.Errorf("curveName gives %q, want %q", got, test.want)
			}
		})
	}
}

func TestCurveNameAcceptsTheNilCurve(t *testing.T) {
	if got := curveName(nil); got != "curveless" {
		t.Errorf("curveName gives %q, want %q", got, "curveless")
	}
}
