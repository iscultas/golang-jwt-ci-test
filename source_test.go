package jwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

type countingSource struct {
	sets     []*jwk.KeySet
	gets     int
	refreshs int
	failure  error
}

func (source *countingSource) Get(context.Context) (*jwk.KeySet, error) {
	source.gets++

	if source.failure != nil {
		return nil, source.failure
	}

	return source.sets[0], nil
}

func (source *countingSource) Refresh(context.Context) (*jwk.KeySet, error) {
	source.refreshs++

	if source.failure != nil {
		return nil, source.failure
	}

	if source.refreshs < len(source.sets) {
		return source.sets[source.refreshs], nil
	}

	return source.sets[len(source.sets)-1], nil
}

type staticSource struct {
	set  *jwk.KeySet
	gets int
}

func (source *staticSource) Get(context.Context) (*jwk.KeySet, error) {
	source.gets++

	return source.set, nil
}

func signedWith(t *testing.T) (string, *jwk.Key) {
	t.Helper()

	privateKey := ed25519Key(t)

	serialized, err := newToken(t, jwt.WithSignature(jwa.EdDSA(), privateKey)).Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	return serialized, privateKey.Public()
}

func eddsaOnly() jwt.VerificationConfig {
	return jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.EdDSA()))
}

func TestVerifyGetsTheKeysAgainForAnUnknownKey(t *testing.T) {
	serialized, publicKey := signedWith(t)

	source := &countingSource{sets: []*jwk.KeySet{
		jwk.NewKeySet(),
		jwk.NewKeySet(publicKey),
	}}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	if err := token.Verify(t.Context(), source, eddsaOnly()); err != nil {
		t.Fatalf("the token did not verify with the keys of the second set: %v", err)
	}

	if source.gets != 1 || source.refreshs != 1 {
		t.Errorf("got %d gets and %d refreshes, want 1 and 1", source.gets, source.refreshs)
	}
}

func TestVerifyDoesNotGetTheKeysAgainForASignatureThatFails(t *testing.T) {
	serialized, _ := signedWith(t)

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot make a key: %v", err)
	}

	source := &countingSource{sets: []*jwk.KeySet{jwk.NewKeySet(jwk.NewKey(publicKey))}}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	if err := token.Verify(t.Context(), source, eddsaOnly()); !errors.Is(err, jwt.ErrUnverified) {
		t.Fatalf("got error %v, want ErrUnverified", err)
	}

	if source.refreshs != 0 {
		t.Errorf("got %d refreshes, want 0: a token that no key signed made a request", source.refreshs)
	}
}

func TestVerifyMakesOneAttemptWithASourceThatDoesNotRefresh(t *testing.T) {
	serialized, _ := signedWith(t)

	source := &staticSource{set: jwk.NewKeySet()}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	if err := token.Verify(t.Context(), source, eddsaOnly()); !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Fatalf("got error %v, want ErrNoSuitableKey", err)
	}

	if source.gets != 1 {
		t.Errorf("got %d gets, want 1", source.gets)
	}
}

func TestVerifyReportsTheTokenAndTheRefusalTogether(t *testing.T) {
	serialized, _ := signedWith(t)

	tooSoon := errors.New("too soon")

	source := &refusingSource{set: jwk.NewKeySet(), refusal: tooSoon}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	err = token.Verify(t.Context(), source, eddsaOnly())

	if !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Errorf("got error %v, want it to hold ErrNoSuitableKey", err)
	}

	if !errors.Is(err, tooSoon) {
		t.Errorf("got error %v, want it to hold the refusal of the source", err)
	}
}

type refusingSource struct {
	set     *jwk.KeySet
	refusal error
}

func (source *refusingSource) Get(context.Context) (*jwk.KeySet, error) { return source.set, nil }

func (source *refusingSource) Refresh(context.Context) (*jwk.KeySet, error) {
	return nil, source.refusal
}

func TestVerifyGivesTheErrorOfTheSource(t *testing.T) {
	serialized, _ := signedWith(t)

	unavailable := errors.New("the store of keys is not available")

	source := &countingSource{failure: unavailable}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	if err := token.Verify(t.Context(), source, eddsaOnly()); !errors.Is(err, unavailable) {
		t.Fatalf("got error %v, want the error of the source", err)
	}

	if source.refreshs != 0 {
		t.Errorf("got %d refreshes, want 0: a source that cannot give keys was asked two times", source.refreshs)
	}
}

func TestVerifyWithNoSourceIsNoKeys(t *testing.T) {
	serialized, _ := signedWith(t)

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	if err := token.Verify(t.Context(), nil, eddsaOnly()); !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Fatalf("got error %v, want ErrNoSuitableKey", err)
	}
}

func TestAKeySetIsASourceThatDoesNotRefresh(t *testing.T) {
	set := jwk.NewKeySet(ed25519Key(t).Public())

	var source jwk.Source = set

	got, err := source.Get(t.Context())
	if err != nil {
		t.Fatalf("a key set gave an error: %v", err)
	}

	if got != set {
		t.Error("a key set gave a different set")
	}

	if _, refreshes := source.(jwk.Refresher); refreshes {
		t.Error("a key set is a jwk.Refresher, thus verification gets the same keys two times")
	}
}

func TestANilKeySetGivesNoKeys(t *testing.T) {
	var set *jwk.KeySet

	got, err := set.Get(t.Context())
	if err != nil {
		t.Fatalf("a nil key set gave an error: %v", err)
	}

	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestVerifySignatureGetsTheKeysAgain(t *testing.T) {
	privateKey := ed25519Key(t)

	token := newToken(t, jwt.WithSignature(jwa.EdDSA(), privateKey))

	if _, err := token.Marshal(); err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	source := &countingSource{sets: []*jwk.KeySet{
		jwk.NewKeySet(),
		jwk.NewKeySet(privateKey.Public()),
	}}

	signatures := token.Signatures()
	if len(signatures) != 1 {
		t.Fatalf("got %d signatures, want 1", len(signatures))
	}

	err := token.VerifySignature(t.Context(), signatures[0], source, eddsaOnly())
	if err != nil {
		t.Fatalf("the signature did not verify with the keys of the second set: %v", err)
	}

	if source.refreshs != 1 {
		t.Errorf("got %d refreshes, want 1", source.refreshs)
	}
}

func TestSourceFuncGivesWhatTheFunctionGives(t *testing.T) {
	set := jwk.NewKeySet(ed25519Key(t).Public())

	got, err := jwk.SourceFunc(func(context.Context) (*jwk.KeySet, error) {
		return set, nil
	}).Get(t.Context())
	if err != nil {
		t.Fatalf("got an error: %v", err)
	}

	if got != set {
		t.Error("got a different set")
	}

	unavailable := errors.New("no keys")

	if _, err := jwk.SourceFunc(func(context.Context) (*jwk.KeySet, error) {
		return nil, unavailable
	}).Get(t.Context()); !errors.Is(err, unavailable) {
		t.Errorf("got error %v, want the error of the function", err)
	}
}

func TestSourceFuncVerifies(t *testing.T) {
	serialized, publicKey := signedWith(t)

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	source := jwk.SourceFunc(func(context.Context) (*jwk.KeySet, error) {
		return jwk.NewKeySet(publicKey), nil
	})

	if err := token.Verify(t.Context(), source, eddsaOnly()); err != nil {
		t.Fatalf("the token did not verify: %v", err)
	}
}

func TestNestedDecryptGetsTheKeysAgainOneTime(t *testing.T) {
	signingKey := ed25519Key(t)

	encryptionKey := jwk.NewKey(
		make([]byte, 32),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.Encrypt, jwk.Decrypt),
	)

	serialized, err := newToken(
		t,
		jwt.WithSignature(jwa.EdDSA(), signingKey),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), encryptionKey),
	).Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	source := &countingSource{sets: []*jwk.KeySet{
		jwk.NewKeySet(encryptionKey),
		jwk.NewKeySet(encryptionKey, signingKey.Public()),
	}}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	config := jwt.NewDecryptionConfig(
		jwt.WithRequiredNestedToken(),
		jwt.WithVerification(jwt.WithAlgorithms(jwa.EdDSA())),
	)

	if err := token.Decrypt(t.Context(), source, config); err != nil {
		t.Fatalf("the nested token did not verify with the keys of the second set: %v", err)
	}

	if !token.Verified() {
		t.Error("the claims of a nested token that verified are not marked authentic")
	}

	if source.refreshs != 1 {
		t.Errorf("got %d refreshes, want 1", source.refreshs)
	}
}

func TestDecryptGetsTheKeysAgainForAnUnknownDecryptionKey(t *testing.T) {
	encryptionKey := jwk.NewKey(
		make([]byte, 32),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.Encrypt, jwk.Decrypt),
	)

	serialized, err := newToken(
		t, jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), encryptionKey),
	).Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	source := &countingSource{sets: []*jwk.KeySet{
		jwk.NewKeySet(),
		jwk.NewKeySet(encryptionKey),
	}}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read token: %v", err)
	}

	if err := token.Decrypt(t.Context(), source, jwt.DefaultDecryptionConfig); err != nil {
		t.Fatalf("the token did not decrypt with the keys of the second set: %v", err)
	}

	if source.refreshs != 1 {
		t.Errorf("got %d refreshes, want 1", source.refreshs)
	}
}
