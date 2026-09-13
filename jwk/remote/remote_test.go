package remote_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jwk/remote"
	"github.com/iscultas/jwt-go/jws"
)

func publishedKeySet(t *testing.T) []byte {
	t.Helper()

	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	key := jwk.NewKey(
		material,
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Verify),
		jwk.WithAlgorithm(jwa.ES256()),
		jwk.WithID("2026-08"),
	)

	document, err := json.Marshal(jwk.NewKeySet(key).Public())
	if err != nil {
		t.Fatalf("cannot marshal the JWK Set: %v", err)
	}

	return document
}

func server(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	requests := new(atomic.Int64)

	testServer := httptest.NewTLSServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			handler(writer, request)
		},
	))
	t.Cleanup(testServer.Close)

	return testServer, requests
}

func source(t *testing.T, testServer *httptest.Server, options ...func(*remote.Source)) *remote.Source {
	t.Helper()

	keys, err := remote.NewSource(
		testServer.URL,
		append([]func(*remote.Source){remote.WithHTTPClient(testServer.Client())}, options...)...,
	)
	if err != nil {
		t.Fatalf("cannot make the key source: %v", err)
	}

	return keys
}

func TestNewSourceRefusesAnAddressThatIsNotHTTPS(t *testing.T) {
	for _, address := range []string{
		"http://issuer.example/.well-known/jwks.json",
		"ftp://issuer.example/jwks.json",
		"/.well-known/jwks.json",
		"https:///jwks.json",
	} {
		t.Run(address, func(t *testing.T) {
			if _, err := remote.NewSource(address); !errors.Is(err, remote.ErrInsecureURL) {
				t.Errorf("got error %v, want %v", err, remote.ErrInsecureURL)
			}
		})
	}
}

func TestNewSourceMakesNoRequest(t *testing.T) {
	document := publishedKeySet(t)

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(document)
	})

	source(t, testServer)

	if got := requests.Load(); got != 0 {
		t.Errorf("got %d requests, want 0", got)
	}
}

func TestGetKeepsTheKeys(t *testing.T) {
	document := publishedKeySet(t)

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = writer.Write(document)
	})

	set := source(t, testServer)

	for range 5 {
		got, err := set.Get(t.Context())
		if err != nil {
			t.Fatalf("cannot get the keys: %v", err)
		}

		if len(got.Keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(got.Keys))
		}

		if got.Keys[0].ID() != "2026-08" {
			t.Errorf("got the key %q, want %q", got.Keys[0].ID(), "2026-08")
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("got %d requests, want 1", got)
	}
}

func TestGetGivesTheSetItHoldsAndNotACopy(t *testing.T) {
	document := publishedKeySet(t)

	testServer, _ := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = writer.Write(document)
	})

	set := source(t, testServer)

	first, err := set.Get(t.Context())
	if err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	second, err := set.Get(t.Context())
	if err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	if first != second {
		t.Error("two calls inside the refresh interval gave two sets")
	}
}

func TestGetGetsTheKeysAgainAfterTheInterval(t *testing.T) {
	document := publishedKeySet(t)

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(document)
	})

	now := time.Unix(1000, 0)

	set := source(
		t, testServer,
		remote.WithRefreshInterval(time.Minute),
		remote.WithMinimumInterval(time.Second),
		remote.WithClock(func() time.Time { return now }),
	)

	if _, err := set.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	now = now.Add(30 * time.Second)

	if _, err := set.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("got %d requests inside the interval, want 1", got)
	}

	now = now.Add(time.Minute)

	if _, err := set.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	if got := requests.Load(); got != 2 {
		t.Errorf("got %d requests after the interval, want 2", got)
	}
}

func TestRefreshObeysTheMinimumInterval(t *testing.T) {
	document := publishedKeySet(t)

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(document)
	})

	now := time.Unix(1000, 0)

	set := source(
		t, testServer,
		remote.WithMinimumInterval(30*time.Second),
		remote.WithClock(func() time.Time { return now }),
	)

	if _, err := set.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	for range 3 {
		if _, err := set.Refresh(t.Context()); !errors.Is(err, remote.ErrTooSoon) {
			t.Fatalf("got error %v, want %v", err, remote.ErrTooSoon)
		}
	}

	if _, err := set.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys inside the throttle: %v", err)
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("got %d requests inside the minimum interval, want 1", got)
	}

	now = now.Add(31 * time.Second)

	if _, err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("cannot refresh after the minimum interval: %v", err)
	}

	if got := requests.Load(); got != 2 {
		t.Errorf("got %d requests after the minimum interval, want 2", got)
	}
}

func TestGetGivesTheErrorOfTheLastRequestInsideTheThrottle(t *testing.T) {
	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	})

	now := time.Unix(1000, 0)

	set := source(
		t, testServer,
		remote.WithMinimumInterval(30*time.Second),
		remote.WithClock(func() time.Time { return now }),
	)

	if _, err := set.Get(t.Context()); !errors.Is(err, remote.ErrUnexpectedStatus) {
		t.Fatalf("got error %v, want %v", err, remote.ErrUnexpectedStatus)
	}

	_, err := set.Get(t.Context())

	if !errors.Is(err, remote.ErrTooSoon) {
		t.Errorf("got error %v, want %v", err, remote.ErrTooSoon)
	}

	if !errors.Is(err, remote.ErrUnexpectedStatus) {
		t.Errorf("got error %v, want it to hold %v", err, remote.ErrUnexpectedStatus)
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("got %d requests, want 1", got)
	}
}

func TestRequestErrors(t *testing.T) {
	oversized := "{\"keys\":[]}" + strings.Repeat(" ", 1024)

	for _, testCase := range []struct {
		name          string
		handler       http.HandlerFunc
		options       []func(*remote.Source)
		expectedError error
	}{
		{
			"NotFound",
			func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusNotFound)
			},
			nil,
			remote.ErrUnexpectedStatus,
		},
		{
			"NotJSON",
			func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte("<html>not a key set</html>"))
			},
			nil,
			remote.ErrMalformedKeySet,
		},
		{
			"DuplicateMember",
			func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(`{"keys":[],"keys":[]}`))
			},
			nil,
			remote.ErrMalformedKeySet,
		},
		{
			"Oversized",
			func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(oversized))
			},
			[]func(*remote.Source){remote.WithResponseLimit(64)},
			remote.ErrOversizedKeySet,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testServer, _ := server(t, testCase.handler)

			set := source(t, testServer, testCase.options...)

			if _, err := set.Get(t.Context()); !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}

func TestGetMakesOneRequestForManyCallers(t *testing.T) {
	document := publishedKeySet(t)

	release := make(chan struct{})

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = writer.Write(document)
	})

	set := source(t, testServer)

	const callers = 16

	var group sync.WaitGroup

	arrived := make(chan struct{}, callers)

	errs := make([]error, callers)

	for i := range callers {
		group.Go(func() {
			arrived <- struct{}{}

			_, errs[i] = set.Get(t.Context())
		})
	}

	for range callers {
		<-arrived
	}

	close(release)
	group.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d got error %v", i, err)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("got %d requests, want 1", got)
	}
}

func TestGetObeysTheContext(t *testing.T) {
	release := make(chan struct{})

	testServer, _ := server(t, func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	})

	t.Cleanup(func() { close(release) })

	set := source(t, testServer)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := set.Get(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, want %v", err, context.Canceled)
	}
}

func TestNewSourceRefusesAnAddressItCannotRead(t *testing.T) {
	if _, err := remote.NewSource("https://issuer.example/%zz"); err == nil {
		t.Error("an address that is not a URI was accepted")
	}
}

func TestGetGivesTheKeysItHoldsInsideTheMinimumInterval(t *testing.T) {
	document := publishedKeySet(t)

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(document)
	})

	now := time.Unix(1000, 0)

	set := source(
		t, testServer,
		remote.WithRefreshInterval(time.Second),
		remote.WithMinimumInterval(time.Minute),
		remote.WithClock(func() time.Time { return now }),
	)

	if _, err := set.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	now = now.Add(10 * time.Second)

	got, err := set.Get(t.Context())
	if err != nil {
		t.Fatalf("cannot get the keys that the set holds: %v", err)
	}

	if len(got.Keys) != 1 {
		t.Errorf("got %d keys, want 1", len(got.Keys))
	}

	if count := requests.Load(); count != 1 {
		t.Errorf("got %d requests, want 1", count)
	}
}

func TestWithTimeoutEndsARequestThatDoesNotAnswer(t *testing.T) {
	release := make(chan struct{})

	testServer, _ := server(t, func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	})

	t.Cleanup(func() { close(release) })

	set := source(t, testServer, remote.WithTimeout(50*time.Millisecond))

	if _, err := set.Get(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got error %v, want %v", err, context.DeadlineExceeded)
	}
}

func signedToken(t *testing.T, id string) (string, []byte) {
	t.Helper()

	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	key := jwk.NewKey(material, jwk.WithID(id))

	document, err := json.Marshal(jwk.NewKeySet(key).Public())
	if err != nil {
		t.Fatalf("cannot marshal the JWK Set: %v", err)
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(
			jwa.ES256(), key, jws.WithProtectedHeader(header.WithKeyID(id)),
		),
	)
	if err != nil {
		t.Fatalf("cannot make the token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot encode the token: %v", err)
	}

	return serialized, document
}

func TestVerifyAcceptsATokenFromAnIssuerThatChangedItsKeys(t *testing.T) {
	_, oldDocument := signedToken(t, "2026-07")
	serialized, newDocument := signedToken(t, "2026-08")

	published := oldDocument

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = writer.Write(published)
	})

	keys := source(t, testServer, remote.WithRefreshInterval(time.Hour), remote.WithMinimumInterval(0))

	if _, err := keys.Get(t.Context()); err != nil {
		t.Fatalf("cannot get the keys: %v", err)
	}

	published = newDocument

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot read the token: %v", err)
	}

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
	)

	if err := token.Verify(t.Context(), keys, config); err != nil {
		t.Fatalf("a token from an issuer that changed its keys did not verify: %v", err)
	}

	if got := requests.Load(); got != 2 {
		t.Errorf("got %d requests, want 2: one for the keys and one for the key that arrived after them", got)
	}
}

func TestVerifyObeysTheMinimumIntervalForUnknownKeys(t *testing.T) {
	_, document := signedToken(t, "2026-07")
	serialized, _ := signedToken(t, "unknown")

	testServer, requests := server(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = writer.Write(document)
	})

	keys := source(t, testServer, remote.WithRefreshInterval(time.Hour), remote.WithMinimumInterval(time.Hour))

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
	)

	for range 10 {
		token, err := jwt.Unmarshal(serialized)
		if err != nil {
			t.Fatalf("cannot read the token: %v", err)
		}

		err = token.Verify(t.Context(), keys, config)

		if !errors.Is(err, jwk.ErrNoSuitableKey) {
			t.Fatalf("got error %v, want ErrNoSuitableKey", err)
		}

		if !errors.Is(err, remote.ErrTooSoon) {
			t.Fatalf("got error %v, want it to name the refusal of the throttle", err)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("got %d requests, want 1: an unknown key id made a request for each token", got)
	}
}
