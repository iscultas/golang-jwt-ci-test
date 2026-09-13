package jwt_test

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

const (
	receiptType = "receipt+jwt"

	amountClaim = "amount"
)

var (
	errNotAReceipt      = errors.New("receipt: not a receipt")
	errUnsignedReceipt  = errors.New("receipt: a receipt must be signed")
	errIncompletePolicy = errors.New("receipt: the profile needs an expected audience")
	errUnexpectedSigner = errors.New("receipt: the signature is not the header key's")
)

var receiptClaims = []string{"iss", "sub", "jti", "iat", amountClaim}

var receiptAlgorithms = []jwa.Algorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()}

func permitted(algorithm jwa.Algorithm) bool { return slices.Contains(receiptAlgorithms, algorithm) }

func withReceipt(amount string) func(*jwt.Token) error {
	return func(token *jwt.Token) error {
		for _, option := range []func(*jwt.Token) error{
			jwt.WithType(receiptType),
			jwt.WithPrivateClaim(amountClaim, amount),
			jwt.WithIssuanceRule(checkReceiptIssuance, bindReceiptKeys),
		} {
			if err := option(token); err != nil {
				return err
			}
		}

		return nil
	}
}

func checkReceiptIssuance(token *jwt.Token) error {
	if err := token.RequireClaims(receiptClaims...); err != nil {
		return err
	}

	for _, pending := range token.Pending() {
		if !permitted(pending.Algorithm) {
			return fmt.Errorf("%w: %v", errUnsignedReceipt, pending.Algorithm)
		}

		if pending.Key == nil {
			return errUnsignedReceipt
		}
	}

	return nil
}

func bindReceiptKeys(token *jwt.Token) error {
	for i, pending := range token.Pending() {
		publicKey := pending.Key.Public()

		thumbprint, err := publicKey.ThumbprintID(crypto.SHA256)
		if err != nil {
			return err
		}

		if err := token.AddProtectedHeader(
			i, header.WithJWK(publicKey), header.WithKeyID(thumbprint),
		); err != nil {
			return err
		}
	}

	return nil
}

func withReceiptProfile() func(*jwt.VerificationConfig) {
	return func(config *jwt.VerificationConfig) {
		for _, option := range []func(*jwt.VerificationConfig){
			jwt.WithRule(checkReceipt),
			jwt.WithExpectedType(receiptType),
			jwt.WithRequiredAlgorithms(receiptAlgorithms...),
			jwt.WithHeaderKey(receiptKeyPolicy),
		} {
			option(config)
		}
	}
}

func receiptKeyPolicy(_ *jwk.Key, protected *header.Header) error {
	if protected.Type != receiptType {
		return errNotAReceipt
	}

	if protected.JWK == nil {
		return errors.New("receipt: no jwk header parameter")
	}

	return nil
}

func checkReceipt(_ context.Context, token *jwt.Token, config jwt.VerificationConfig) error {
	if len(config.ExpectedAudience()) == 0 {
		return errIncompletePolicy
	}

	for _, signature := range token.Signatures() {
		if signature.ProtectedHeader.Type != receiptType {
			return fmt.Errorf("%w: typ is %q", errNotAReceipt, signature.ProtectedHeader.Type)
		}

		if !permitted(signature.ProtectedHeader.Algorithm) {
			return fmt.Errorf("%w: alg is %v", errUnsignedReceipt, signature.ProtectedHeader.Algorithm)
		}

		if err := token.VerifySignature(context.Background(),
			signature, jwk.NewKeySet(signature.ProtectedHeader.JWK), config,
		); err != nil {
			return fmt.Errorf("%w: %w", errUnexpectedSigner, err)
		}
	}

	return token.RequireClaims(receiptClaims...)
}

func newReceipt(t testing.TB, key *jwk.Key, options ...func(*jwt.Token) error) *jwt.Token {
	t.Helper()

	issuedAt := time.Now()

	token, err := jwt.NewToken(append([]func(*jwt.Token) error{
		jwt.WithIssuer("https://shop.example"),
		jwt.WithSubject("customer-7"),
		jwt.WithAudience("https://ledger.example"),
		jwt.WithID("receipt-1"),
		jwt.WithIssuedAt(&issuedAt),
		withReceipt("42.00"),
		jwt.WithSignature(jwa.ES256(), key),
	}, options...)...)
	if err != nil {
		t.Fatalf("cannot build the receipt: %v", err)
	}

	return token
}

func receiptConfig(options ...func(*jwt.VerificationConfig)) jwt.VerificationConfig {
	return jwt.NewVerificationConfig(append([]func(*jwt.VerificationConfig){
		jwt.WithExpectedIssuer("https://shop.example"),
		jwt.WithExpectedAudience("https://ledger.example"),
		withReceiptProfile(),
	}, options...)...)
}

func TestExtensionRoundTrips(t *testing.T) {
	key := jwk.NewKey(generateKey(t))

	encoded, err := newReceipt(t, key).Marshal()
	if err != nil {
		t.Fatalf("cannot serialize the receipt: %v", err)
	}

	token, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse the receipt: %v", err)
	}

	if err := token.Verify(t.Context(), nil, receiptConfig()); err != nil {
		t.Fatalf("the receipt did not verify: %v", err)
	}
}

func TestExtensionSetsItsMediaType(t *testing.T) {
	token := newReceipt(t, jwk.NewKey(generateKey(t)))

	if _, err := token.Marshal(); err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	if got := token.Type(); got != receiptType {
		t.Errorf("Type is %q, want %q", got, receiptType)
	}

	for _, signature := range token.Signatures() {
		if got := signature.ProtectedHeader.Type; got != receiptType {
			t.Errorf("the protected header's typ is %q, want %q", got, receiptType)
		}
	}
}

func TestExtensionRefusesToIssueWithoutItsClaims(t *testing.T) {
	issuedAt := time.Now()

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://shop.example"),
		jwt.WithIssuedAt(&issuedAt),
		withReceipt("42.00"),
		jwt.WithSignature(jwa.ES256(), jwk.NewKey(generateKey(t))),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	_, err = token.Marshal()
	if !errors.Is(err, jwt.ErrMissingRequiredClaim) {
		t.Fatalf("got %v, want ErrMissingRequiredClaim", err)
	}

	for _, name := range []string{"sub", "jti"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name %q: %v", name, err)
		}
	}
}

func TestExtensionRefusesAForbiddenAlgorithmAtIssue(t *testing.T) {
	issuedAt := time.Now()

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://shop.example"),
		jwt.WithSubject("customer-7"),
		jwt.WithID("receipt-1"),
		jwt.WithIssuedAt(&issuedAt),
		withReceipt("42.00"),
		jwt.WithSignature(jwa.None(), nil),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	if _, err := token.Marshal(); !errors.Is(err, errUnsignedReceipt) {
		t.Fatalf("got %v, want the profile's refusal", err)
	}
}

func TestExtensionDerivesAHeaderPerSignature(t *testing.T) {
	first, second := jwk.NewKey(generateKey(t)), jwk.NewKey(generateKey(t))

	token := newReceipt(t, first, jwt.WithSignature(jwa.ES256(), second))

	if _, err := token.MarshalJSON(); err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	signatures := token.Signatures()
	if len(signatures) != 2 {
		t.Fatalf("got %d signatures, want 2", len(signatures))
	}

	for i, key := range []*jwk.Key{first, second} {
		want, err := key.Public().ThumbprintID(crypto.SHA256)
		if err != nil {
			t.Fatalf("cannot compute the thumbprint: %v", err)
		}

		if got := signatures[i].ProtectedHeader.KeyID; got != want {
			t.Errorf("signature %d carries kid %q, want %q", i, got, want)
		}

		got, err := signatures[i].ProtectedHeader.JWK.ThumbprintID(crypto.SHA256)
		if err != nil {
			t.Fatalf("cannot compute the header key's thumbprint: %v", err)
		}

		if got != want {
			t.Errorf("signature %d carries another signature's key", i)
		}
	}

	if err := token.Verify(t.Context(), nil, receiptConfig(jwt.WithAllSignatures())); err != nil {
		t.Fatalf("the two-signer receipt did not verify: %v", err)
	}
}

func TestExtensionAddProtectedHeaderReportsABadIndex(t *testing.T) {
	token := newReceipt(t, jwk.NewKey(generateKey(t)))

	for _, i := range []int{-1, 7} {
		if err := token.AddProtectedHeader(i, header.WithKeyID("x")); !errors.Is(err, jwt.ErrNoSuchSignature) {
			t.Errorf("AddProtectedHeader(%d) returned %v, want ErrNoSuchSignature", i, err)
		}
	}
}

func TestExtensionRejectsAnOrdinaryJWT(t *testing.T) {
	key := jwk.NewKey(generateKey(t))
	issuedAt := time.Now()

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://shop.example"),
		jwt.WithSubject("customer-7"),
		jwt.WithAudience("https://ledger.example"),
		jwt.WithID("receipt-1"),
		jwt.WithIssuedAt(&issuedAt),
		jwt.WithPrivateClaim(amountClaim, "42.00"),
		jwt.WithSignature(jwa.ES256(), key),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	if err := token.Verify(t.Context(), jwk.NewKeySet(key.Public()), receiptConfig()); !errors.Is(err, errNotAReceipt) {
		t.Fatalf("got %v, want the profile's refusal", err)
	}
}

func TestExtensionRuleRefusesAnIncompletePolicy(t *testing.T) {
	key := jwk.NewKey(generateKey(t))

	config := jwt.NewVerificationConfig(
		jwt.WithExpectedIssuer("https://shop.example"),
		withReceiptProfile(),
	)

	if got := config.ExpectedAudience(); len(got) != 0 {
		t.Fatalf("ExpectedAudience is %q, want empty", got)
	}

	if err := newReceipt(t, key).Verify(t.Context(), nil, config); !errors.Is(err, errIncompletePolicy) {
		t.Fatalf("got %v, want the profile's refusal to run", err)
	}
}

func TestExtensionNarrowsAlgorithmsUnderEitherOrder(t *testing.T) {
	key := jwk.NewKey(generateKey(t))

	encoded, err := newReceipt(t, key).Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	orders := map[string][]func(*jwt.VerificationConfig){
		"profile last":  {jwt.WithAlgorithms(jwa.RS256()), withReceiptProfile()},
		"profile first": {withReceiptProfile(), jwt.WithAlgorithms(jwa.RS256())},
	}

	for name, options := range orders {
		t.Run(name, func(t *testing.T) {
			token, err := jwt.Unmarshal(encoded)
			if err != nil {
				t.Fatalf("cannot parse: %v", err)
			}

			config := jwt.NewVerificationConfig(append([]func(*jwt.VerificationConfig){
				jwt.WithExpectedIssuer("https://shop.example"),
				jwt.WithExpectedAudience("https://ledger.example"),
			}, options...)...)

			if err := token.Verify(t.Context(), nil, config); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
				t.Fatalf("got %v, want ErrForbiddenAlgorithm", err)
			}
		})
	}
}

func TestExtensionVerifiesAgainstTheKeyTheProfileNames(t *testing.T) {
	signer, other := jwk.NewKey(generateKey(t)), jwk.NewKey(generateKey(t))

	token := newReceipt(t, signer)

	if _, err := token.Marshal(); err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	signature := token.Signatures()[0]

	if err := token.VerifySignature(t.Context(),
		signature, jwk.NewKeySet(signer.Public()), receiptConfig(),
	); err != nil {
		t.Fatalf("the signature did not verify under its own key: %v", err)
	}

	if err := token.VerifySignature(t.Context(),
		signature, jwk.NewKeySet(other.Public()), jwt.NewVerificationConfig(),
	); err == nil {
		t.Fatal("the signature verified under a key that did not make it")
	}
}

func TestExtensionVerifySignatureRefusesAnUndescribedSignature(t *testing.T) {
	token := newReceipt(t, jwk.NewKey(generateKey(t)))

	if err := token.VerifySignature(t.Context(), nil, nil, receiptConfig()); !errors.Is(
		err, jwt.ErrUnverifiableSignature,
	) {
		t.Fatalf("got %v, want ErrUnverifiableSignature", err)
	}
}

func TestExtensionReadsTheCallersPolicy(t *testing.T) {
	config := jwt.NewVerificationConfig(
		jwt.WithExpectedIssuer("https://shop.example"),
		jwt.WithExpectedAudience("https://ledger.example"),
		jwt.WithLeeway(30*time.Second),
		jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()),
	)

	if got := config.ExpectedIssuer(); got != "https://shop.example" {
		t.Errorf("ExpectedIssuer is %q", got)
	}

	if got := config.Leeway(); got != 30*time.Second {
		t.Errorf("Leeway is %v", got)
	}

	if got := config.Algorithms(); len(got) != 2 {
		t.Errorf("Algorithms returned %d entries, want 2", len(got))
	}

	config.Algorithms()[0] = jwa.RS256()

	if got := config.Algorithms()[0]; got != jwa.ES256() {
		t.Errorf("Algorithms is not a copy: the caller's policy became %v", got)
	}
}

func TestExtensionSignaturesIsACopy(t *testing.T) {
	token := newReceipt(t, jwk.NewKey(generateKey(t)))

	if _, err := token.Marshal(); err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	signatures := token.Signatures()
	signatures[0] = nil

	if token.Signatures()[0] == nil {
		t.Error("Signatures is not a copy: a rule removed a signature from the token")
	}
}
