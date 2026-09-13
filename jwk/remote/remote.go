// Package remote gets a JWK Set over HTTPS.
//
// [Source] holds the address of a JWK Set and gives the keys at that address.
// It keeps the keys it got and gives them again until they reach the refresh
// interval, thus a recipient that verifies many tokens makes few requests.
//
// # The address comes from the caller
//
// A caller gives the address to [NewSource]. This package reads no address from
// a token: neither the "jku" parameter, nor the "x5u" parameter, nor the "jku"
// member of a "cnf" claim. A token that named its own key set would name the
// party that says which key signed it, and a recipient that got that address
// would let the token select its own key of trust. It would also let a token
// make this process address a host of its selection.
//
// The rest of this module has no networking import at all. This package is
// separate for that reason: a program that does not import it cannot make a
// request, and the property holds for that program by its list of imports.
//
// # What this package limits
//
// The address must be https. A JWK Set on http is a set that any party on the
// path can replace, and the keys in it decide which tokens a recipient accepts.
//
// A response has a maximum size, and the body above that size is not read.
// [WithResponseLimit] gives it.
//
// A refresh has a minimum interval. A token names its key with "kid", and a
// recipient that fetched the set for each name that it does not hold would let
// an unauthenticated token make a request to the issuer for each token that
// arrives. [WithMinimumInterval] gives that interval, and [Source.Refresh]
// gives [ErrTooSoon] inside it.
//
// # Use
//
// A [Source] is a [jwk.Refresher]. A recipient gives it where a key set is
// necessary, and verification gets the keys:
//
//	keys, err := remote.NewSource("https://issuer.example/.well-known/jwks.json")
//	if err != nil {
//		return err
//	}
//
//	err = token.Verify(ctx, keys, config)
//
// Verification gets the keys again one time when the issuer signs with a key
// that this recipient does not hold, and it then makes one more attempt. Thus a
// recipient accepts a token from an issuer that changed its keys. The minimum
// interval applies to that operation, and a refusal from it does not change the
// error of the token.
package remote

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/iscultas/jwt-go/jwk"
)

var (
	// ErrInsecureURL is the error for an address that is not https. See the
	// package documentation.
	ErrInsecureURL = errors.New("remote: the address of a JWK Set must be https")

	// ErrUnexpectedStatus is the error for a response with a status other than
	// 200.
	ErrUnexpectedStatus = errors.New("remote: unexpected status")

	// ErrOversizedKeySet is the error for a response body above the limit that
	// [WithResponseLimit] gives.
	ErrOversizedKeySet = errors.New("remote: the response is too large")

	// ErrMalformedKeySet is the error for a response body that is not a JWK Set.
	ErrMalformedKeySet = errors.New("remote: malformed JWK Set")

	// ErrTooSoon is the error from [Source.Refresh] inside the minimum interval.
	// The keys that the [Source] holds are still available from [Source.Get].
	ErrTooSoon = errors.New("remote: a refresh came before the minimum interval")
)

const (
	defaultInterval = 5 * time.Minute

	defaultMinimumInterval = 30 * time.Second

	defaultResponseLimit = 1 << 20

	defaultTimeout = 30 * time.Second
)

type fetch struct {
	done chan struct{}
	set  *jwk.KeySet
	err  error
}

// Source gets a JWK Set from one address and keeps the keys that it got.
//
// [NewSource] makes one. A Source is safe for use by more than one goroutine at
// the same time, and a program makes one for each address and shares it.
type Source struct {
	url    string
	client *http.Client

	interval time.Duration
	minimum  time.Duration

	limit   int64
	timeout time.Duration
	clock   func() time.Time

	mutex   sync.Mutex
	cached  *jwk.KeySet
	fetched time.Time

	failure  error
	inflight *fetch
}

var _ jwk.Refresher = (*Source)(nil)

// NewSource returns a [Source] for the JWK Set at address.
//
// The address must be https, and NewSource gives [ErrInsecureURL] for each other
// scheme. See the package documentation.
//
// NewSource makes no request. The first request is the first call of
// [Source.Get] or [Source.Refresh], thus a program can make a Source at its start
// and does not need the issuer to answer at that time.
func NewSource(address string, options ...func(*Source)) (*Source, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("remote: cannot read the address: %w", err)
	}

	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: got %q", ErrInsecureURL, parsed.Scheme)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: the address names no host", ErrInsecureURL)
	}

	source := &Source{
		url:      parsed.String(),
		client:   http.DefaultClient,
		interval: defaultInterval,
		minimum:  defaultMinimumInterval,
		limit:    defaultResponseLimit,
		timeout:  defaultTimeout,
	}

	for _, option := range options {
		option(source)
	}

	return source, nil
}

// WithHTTPClient gives the client that makes the requests. The default is
// [http.DefaultClient].
//
// A deployment gives its own client for a proxy, for a set of root certificates
// of its own, or for a timeout that covers each request.
func WithHTTPClient(client *http.Client) func(*Source) {
	return func(source *Source) { source.client = client }
}

// WithRefreshInterval gives the time after which [Source.Get] gets the set
// again. The default is five minutes.
func WithRefreshInterval(interval time.Duration) func(*Source) {
	return func(source *Source) { source.interval = interval }
}

// WithMinimumInterval gives the shortest time between two requests. The default
// is thirty seconds.
//
// It is the throttle on [Source.Refresh], which an unauthenticated token can
// cause. See the package documentation.
func WithMinimumInterval(interval time.Duration) func(*Source) {
	return func(source *Source) { source.minimum = interval }
}

// WithResponseLimit gives the largest response body that this package reads. The
// default is one mebioctet.
func WithResponseLimit(limit int64) func(*Source) {
	return func(source *Source) { source.limit = limit }
}

// WithTimeout gives the time that one request gets, when the context of the
// caller gives no shorter one. The default is thirty seconds, and zero removes
// the limit and leaves the time to the context of the caller and to the client.
func WithTimeout(timeout time.Duration) func(*Source) {
	return func(source *Source) { source.timeout = timeout }
}

// WithClock gives the function that this package reads the current time from. The
// default is [time.Now].
//
// It is for a test that must move the time and make the keys reach an interval.
// A production caller does not give it.
func WithClock(clock func() time.Time) func(*Source) {
	return func(source *Source) { source.clock = clock }
}

func (source *Source) now() time.Time {
	if source.clock == nil {
		return time.Now()
	}

	return source.clock()
}

// Get returns the keys at the address.
//
// It gives the keys that it holds when they are younger than the refresh
// interval, and it gets them again when they are not. Thus a recipient that
// verifies many tokens makes few requests.
//
// No request happens inside the minimum interval of the last one. Get gives the
// keys that it holds in that time. Those keys are at their refresh interval, and
// they are the keys that this Source has. It gives the error of the last request
// when it holds no keys at all.
//
// The result is the [jwk.KeySet] that this package holds and not a copy. A caller
// reads it and does not write to it, because the other callers read the same
// value.
func (source *Source) Get(ctx context.Context) (*jwk.KeySet, error) {
	source.mutex.Lock()

	if source.cached != nil && source.now().Sub(source.fetched) < source.interval {
		cached := source.cached
		source.mutex.Unlock()

		return cached, nil
	}

	source.mutex.Unlock()

	return source.load(ctx, false)
}

// Refresh gets the keys again, for a token that names a key which the keys of
// this Source do not hold.
//
// It gives [ErrTooSoon] when the last request was less than the minimum interval
// ago. A token names its own key, thus a token that names a key of no one would
// otherwise make one request for each token that arrives. [Source.Get] still
// gives the keys that this Source holds.
//
// The error holds the error of the last request when this Source holds no keys.
// Thus a caller reads what the host answered and not only the throttle.
func (source *Source) Refresh(ctx context.Context) (*jwk.KeySet, error) {
	return source.load(ctx, true)
}

func (source *Source) load(ctx context.Context, forced bool) (*jwk.KeySet, error) {
	source.mutex.Lock()

	now := source.now()

	age := now.Sub(source.fetched)

	switch {
	case !forced && source.cached != nil && age < source.interval:
		cached := source.cached
		source.mutex.Unlock()

		return cached, nil

	case !source.fetched.IsZero() && age < source.minimum:
		cached, failure := source.cached, source.failure
		wait := source.minimum - age

		source.mutex.Unlock()

		switch {
		case !forced && cached != nil:
			return cached, nil

		case cached != nil:
			return nil, fmt.Errorf("%w: wait %v", ErrTooSoon, wait)

		case failure != nil:
			return nil, fmt.Errorf("%w: wait %v: %w", ErrTooSoon, wait, failure)

		default:
			return nil, fmt.Errorf("%w: wait %v", ErrTooSoon, wait)
		}
	}

	if current := source.inflight; current != nil {
		source.mutex.Unlock()

		select {
		case <-current.done:
			return current.set, current.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	current := &fetch{done: make(chan struct{})}
	source.inflight = current

	source.mutex.Unlock()

	set, err := source.request(ctx)

	source.mutex.Lock()

	current.set, current.err = set, err

	source.fetched = source.now()
	source.failure = err

	if err == nil {
		source.cached = set
	}

	source.inflight = nil

	source.mutex.Unlock()

	close(current.done)

	return set, err
}

func (source *Source) request(ctx context.Context) (*jwk.KeySet, error) {
	if source.timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, source.timeout)
		defer cancel()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return nil, fmt.Errorf("remote: cannot make the request: %w", err)
	}

	request.Header.Set("Accept", "application/jwk-set+json, application/json;q=0.9")

	response, err := source.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("remote: cannot get the JWK Set: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrUnexpectedStatus, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, source.limit+1))
	if err != nil {
		return nil, fmt.Errorf("remote: cannot read the response: %w", err)
	}

	if int64(len(body)) > source.limit {
		return nil, fmt.Errorf("%w: more than %d octets", ErrOversizedKeySet, source.limit)
	}

	set := new(jwk.KeySet)
	if err := json.Unmarshal(body, set); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedKeySet, err)
	}

	return set, nil
}
