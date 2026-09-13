package jwt_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
)

func TestConfirmationThumbprintIsWritten(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	thumbprint, err := signingKey.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot calculate a thumbprint: %v", err)
	}

	token := newToken(
		t,
		jwt.WithConfirmation(jwt.Confirmation{Thumbprint: thumbprint}),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)

	encodedToken, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize the token: %v", err)
	}

	encodedPayload, err := base64.RawURLEncoding.DecodeString(strings.Split(encodedToken, ".")[1])
	if err != nil {
		t.Fatalf("cannot decode the payload: %v", err)
	}

	claims := make(map[string]any)
	if err := json.Unmarshal(encodedPayload, &claims); err != nil {
		t.Fatalf("cannot decode the claims: %v", err)
	}

	confirmation, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("got cnf %v, want an object", claims["cnf"])
	}

	if got := confirmation["jkt"]; got != thumbprint {
		t.Errorf("got jkt %v, want %q", got, thumbprint)
	}

	if len(confirmation) != 1 {
		t.Errorf("got cnf %v, want jkt alone", confirmation)
	}
}

func TestConfirmationRoundTrip(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	thumbprint, err := signingKey.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot calculate a thumbprint: %v", err)
	}

	token := newToken(
		t,
		jwt.WithConfirmation(jwt.Confirmation{Thumbprint: thumbprint, KeyID: "the key"}),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)

	encodedToken, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize the token: %v", err)
	}

	decoded := unmarshalToken(t, encodedToken)

	confirmation, err := decoded.Confirmation()
	if err != nil {
		t.Fatalf("cannot read the confirmation: %v", err)
	}

	if confirmation.Thumbprint != thumbprint {
		t.Errorf("got thumbprint %q, want %q", confirmation.Thumbprint, thumbprint)
	}

	if confirmation.KeyID != "the key" {
		t.Errorf("got kid %q, want %q", confirmation.KeyID, "the key")
	}
}
