package remote_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jwk/remote"
)

func examplePublishedKeySet(ids ...string) []byte {
	keys := make([]*jwk.Key, 0, len(ids))

	for _, id := range ids {
		material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		keys = append(keys, jwk.NewKey(
			material,
			jwk.WithPublicKeyUse(jwk.Signature),
			jwk.WithOperations(jwk.Verify),
			jwk.WithAlgorithm(jwa.ES256()),
			jwk.WithID(id),
		))
	}

	document, err := json.Marshal(jwk.NewKeySet(keys...).Public())
	if err != nil {
		panic(err)
	}

	return document
}

func Example() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = writer.Write(examplePublishedKeySet("2026-08"))
	}))
	defer server.Close()

	source, err := remote.NewSource(server.URL, remote.WithHTTPClient(server.Client()))
	if err != nil {
		panic(err)
	}

	set, err := source.Get(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println(len(set.Keys), set.Keys[0].ID(), set.Keys[0].IsPrivate())

	// Output:
	// 1 2026-08 false
}

func ExampleSource() {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	signingKey := jwk.NewKey(material, jwk.WithID("2026-08"))

	document, err := json.Marshal(jwk.NewKeySet(signingKey).Public())
	if err != nil {
		panic(err)
	}

	issuer := httptest.NewTLSServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/jwk-set+json")
			_, _ = writer.Write(document)
		},
	))
	defer issuer.Close()

	keys, err := remote.NewSource(
		issuer.URL,
		remote.WithHTTPClient(issuer.Client()),
		remote.WithRefreshInterval(15*time.Minute),
	)
	if err != nil {
		panic(err)
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithSignature(jwa.ES256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
	)

	if err := received.Verify(context.Background(), keys, config); err != nil {
		panic(err)
	}

	fmt.Println(received.Subject(), received.Verified())

	// Output:
	// alice true
}

func ExampleNewSource() {
	insecure, err := remote.NewSource("http://issuer.example/.well-known/jwks.json")

	source, secureErr := remote.NewSource(
		"https://issuer.example/.well-known/jwks.json",
		remote.WithResponseLimit(1<<20),
		remote.WithTimeout(5*time.Second),
	)
	if secureErr != nil {
		panic(secureErr)
	}

	fmt.Println(insecure == nil, errors.Is(err, remote.ErrInsecureURL), source != nil)

	// Output:
	// true true true
}

func ExampleWithRefreshInterval() {
	requests := new(atomic.Int64)

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		count := requests.Add(1)

		writer.Header().Set("Content-Type", "application/jwk-set+json")

		if count == 1 {
			_, _ = writer.Write(examplePublishedKeySet("2026-08"))

			return
		}

		_, _ = writer.Write(examplePublishedKeySet("2026-08", "2026-09"))
	}))
	defer server.Close()

	now := time.Unix(1000, 0)

	source, err := remote.NewSource(
		server.URL,
		remote.WithHTTPClient(server.Client()),
		remote.WithRefreshInterval(time.Hour),
		remote.WithMinimumInterval(time.Minute),
		remote.WithClock(func() time.Time { return now }),
	)
	if err != nil {
		panic(err)
	}

	first, err := source.Get(context.Background())
	if err != nil {
		panic(err)
	}

	cached, err := source.Get(context.Background())
	if err != nil {
		panic(err)
	}

	_, tooSoon := source.Refresh(context.Background())

	now = now.Add(time.Minute)

	refreshed, err := source.Refresh(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println(len(first.Keys), len(cached.Keys), errors.Is(tooSoon, remote.ErrTooSoon))
	fmt.Println(len(refreshed.Keys), requests.Load())

	// Output:
	// 1 1 true
	// 2 2
}
