package jwa_test

import (
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

func TestPBES2RejectsAnExcessiveIterationCount(t *testing.T) {
	algorithm := jwa.PBES2HS256A128KW()

	for _, count := range []int{1 << 30, 1 << 40} {
		if _, err := algorithm.DecryptKey(
			nil,
			[]byte("password"),
			jwa.A128GCM(),
			&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16), PBES2Count: count},
		); !errors.Is(err, jwa.ErrExcessiveIterationCount) {
			t.Errorf("p2c of %d: got %v, want ErrExcessiveIterationCount", count, err)
		}
	}

	for _, count := range []int{-1, 0, 1, 999} {
		if _, err := algorithm.DecryptKey(
			nil,
			[]byte("password"),
			jwa.A128GCM(),
			&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16), PBES2Count: count},
		); !errors.Is(err, jwa.ErrInsufficientIterationCount) {
			t.Errorf("p2c of %d: got %v, want ErrInsufficientIterationCount", count, err)
		}
	}

	_, err := algorithm.DecryptKey(
		nil,
		[]byte("password"),
		jwa.A128GCM(),
		&jwa.KeyParameters{PBES2SaltInput: make([]byte, 16), PBES2Count: 1000},
	)
	if errors.Is(err, jwa.ErrInsufficientIterationCount) {
		t.Errorf("p2c of exactly 1000 was refused: %v", err)
	}
}
