// Package jsonerr keeps a JSON decoding error readable through the two
// encoding/json packages.
package jsonerr

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
)

// KeepDuplicateName returns err in a wrapper when err reports a duplicate JSON
// object member name, and err with no change in the other conditions. The
// message stays the same.
//
// The wrapper is necessary because the two decoders give the error of an
// UnmarshalJSON method to a caller differently. The encoding/json/v2 decoder
// gives it with no change, and errors.Is finds [jsontext.ErrDuplicateName] in
// it. The encoding/json decoder makes a *json.SyntaxError of a syntactic error
// that comes from such a method, which holds the message but not the chain.
// It keeps an error that this module wraps itself. Thus a caller reads the same
// error from the two decoders.
func KeepDuplicateName(err error) error {
	if errors.Is(err, jsontext.ErrDuplicateName) {
		return fmt.Errorf("%w", err)
	}

	return err
}
