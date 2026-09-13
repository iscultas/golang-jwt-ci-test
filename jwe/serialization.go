package jwe

import (
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/internal/jsonerr"
	"github.com/iscultas/jwt-go/jwa"
)

const compactParts = 5

func encodeOctets(octets []byte) string {
	return base64url.Encode(octets)
}

func decodeOctets(encoded string) ([]byte, error) {
	if encoded == "" {
		return []byte{}, nil
	}

	return base64url.Decode(encoded)
}

func randomOctets(n int) ([]byte, error) {
	octets := make([]byte, n)

	if _, err := rand.Read(octets); err != nil {
		return nil, err
	}

	return octets, nil
}

// Marshal returns the JWE Compact Serialization.
//
// The compact serialization has a position for one recipient only, and it has no
// position for an unprotected header or for "aad". Marshal gives
// [ErrMalformedMessage] for a message with one of those, and it does not write
// the message without them. To remove them also removes the parameters that are
// necessary to a recipient.
func (message *Message) Marshal() (string, error) {
	switch {
	case len(message.Recipients) == 0:
		return "", fmt.Errorf("%w: no recipients", ErrMalformedMessage)
	case len(message.Recipients) > 1:
		return "", fmt.Errorf(
			"%w: the compact serialization holds one recipient, not %d", ErrMalformedMessage, len(message.Recipients),
		)
	case message.Recipients[0] == nil:
		return "", fmt.Errorf("%w: empty recipient", ErrMalformedMessage)
	case message.Recipients[0].Header != nil && !message.Recipients[0].Header.IsZero():
		return "", fmt.Errorf("%w: the compact serialization has no per-recipient header", ErrMalformedMessage)
	case message.SharedHeader != nil && !message.SharedHeader.IsZero():
		return "", fmt.Errorf("%w: the compact serialization has no shared unprotected header", ErrMalformedMessage)
	case message.AdditionalAuthenticatedData != nil:
		return "", fmt.Errorf("%w: the compact serialization has no aad", ErrMalformedMessage)
	}

	encodedProtectedHeader, err := message.ProtectedHeader.Marshal()
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		encodedProtectedHeader,
		encodeOctets(message.Recipients[0].EncryptedKey),
		encodeOctets(message.InitializationVector),
		encodeOctets(message.Ciphertext),
		encodeOctets(message.AuthenticationTag),
	}, "."), nil
}

// String returns the compact serialization. It panics where [Message.Marshal]
// gives an error. A caller with input that it does not trust must use
// [Message.Marshal].
func (message *Message) String() string {
	encoded, err := message.Marshal()
	if err != nil {
		panic(err)
	}

	return encoded
}

// Unmarshal reads a JWE Compact Serialization and gives the [Message].
//
// Unmarshal gives [ErrMalformedMessage] for input that does not have five parts,
// or for a part that is not correct base64url.
func Unmarshal(encoded string) (*Message, error) {
	if parts := strings.Count(encoded, ".") + 1; parts != compactParts {
		return nil, fmt.Errorf("%w: got %d parts, want %d", ErrMalformedMessage, parts, compactParts)
	}

	encodedProtectedHeader, rest, _ := strings.Cut(encoded, ".")
	encodedEncryptedKey, rest, _ := strings.Cut(rest, ".")
	encodedInitializationVector, rest, _ := strings.Cut(rest, ".")
	encodedCiphertext, encodedAuthenticationTag, _ := strings.Cut(rest, ".")

	protectedHeader := new(header.Header)
	if err := protectedHeader.Unmarshal(encodedProtectedHeader); err != nil {
		return nil, err
	}

	message := &Message{ProtectedHeader: protectedHeader}

	encryptedKey, err := decodeOctets(encodedEncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypted key: %w", ErrMalformedMessage, err)
	}

	if message.InitializationVector, err = decodeOctets(encodedInitializationVector); err != nil {
		return nil, fmt.Errorf("%w: initialization vector: %w", ErrMalformedMessage, err)
	}

	if message.Ciphertext, err = decodeOctets(encodedCiphertext); err != nil {
		return nil, fmt.Errorf("%w: ciphertext: %w", ErrMalformedMessage, err)
	}

	if message.AuthenticationTag, err = decodeOctets(encodedAuthenticationTag); err != nil {
		return nil, fmt.Errorf("%w: authentication tag: %w", ErrMalformedMessage, err)
	}

	message.Recipients = []*Recipient{{EncryptedKey: encryptedKey}}

	return message, nil
}

type rawRecipient struct {
	// Header is kept as octets rather than decoded in place, so that a recipient
	// naming an algorithm this module does not implement can be recorded as one
	// that cannot be served instead of failing the whole document. See
	// decodeRecipient.
	//
	// omitempty, and the encoder is responsible for passing nil rather than "{}"
	// for an empty header, for the reason jws.rawSignature gives: an empty header
	// object must be absent, not written as {}.
	Header jsontext.Value `json:"header,omitempty"`

	EncryptedKey string `json:"encrypted_key,omitempty"`
}

func decodeRecipient(rawRecipient *rawRecipient) (*Recipient, error) {
	encryptedKey, err := decodeOctets(rawRecipient.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypted_key: %w", ErrMalformedMessage, err)
	}

	recipient := &Recipient{EncryptedKey: encryptedKey}

	if len(rawRecipient.Header) == 0 {
		return recipient, nil
	}

	recipientHeader := new(header.Header)
	if err := json.Unmarshal(rawRecipient.Header, recipientHeader); err != nil {
		if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
			return nil, err
		}

		recipient.rawHeader = rawRecipient.Header
		recipient.unsupported = err

		return recipient, nil
	}

	recipient.Header = recipientHeader

	return recipient, nil
}

func encodeRecipientHeader(recipient *Recipient) (jsontext.Value, error) {
	if recipient.unsupported != nil {
		return recipient.rawHeader, nil
	}

	if recipient.Header == nil || recipient.Header.IsZero() {
		return nil, nil
	}

	return json.Marshal(recipient.Header)
}

type rawMessage struct {
	ProtectedHeader string `json:"protected,omitempty"`

	// SharedHeader is decoded strictly, and the per-recipient headers are not. An
	// "alg" value here that this module does not supply applies to each recipient.
	// Thus there is no recipient that can still read the document, and to continue
	// gives nothing.
	SharedHeader *header.Header `json:"unprotected,omitzero"`

	Recipients []*rawRecipient `json:"recipients,omitempty"`

	// Header and EncryptedKey are the recipient that the flattened serialization
	// moves up. Header is octets for the same cause as [rawRecipient.Header].
	Header       jsontext.Value `json:"header,omitempty"`
	EncryptedKey string         `json:"encrypted_key,omitempty"`

	AdditionalAuthenticatedData string `json:"aad,omitempty"`
	InitializationVector        string `json:"iv,omitempty"`
	Ciphertext                  string `json:"ciphertext"`
	AuthenticationTag           string `json:"tag,omitempty"`
}

// MarshalJSON writes the JWE JSON Serialization. It writes the flattened
// serialization for a message with one recipient, and the general serialization
// for a message with more recipients.
//
// MarshalJSON gives [ErrMalformedMessage] for a message with no recipient.
func (message *Message) MarshalJSON() ([]byte, error) {
	if len(message.Recipients) == 0 {
		return nil, fmt.Errorf("%w: no recipients", ErrMalformedMessage)
	}

	encodedProtectedHeader, err := message.ProtectedHeader.Marshal()
	if err != nil {
		return nil, err
	}

	recipients := make([]*rawRecipient, 0, len(message.Recipients))
	for _, recipient := range message.Recipients {
		if recipient == nil {
			return nil, fmt.Errorf("%w: empty recipient", ErrMalformedMessage)
		}

		recipientHeader, err := encodeRecipientHeader(recipient)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, &rawRecipient{
			Header:       recipientHeader,
			EncryptedKey: encodeOctets(recipient.EncryptedKey),
		})
	}

	rawMessage := &rawMessage{
		ProtectedHeader:             encodedProtectedHeader,
		SharedHeader:                message.SharedHeader,
		AdditionalAuthenticatedData: encodeOctets(message.AdditionalAuthenticatedData),
		InitializationVector:        encodeOctets(message.InitializationVector),
		Ciphertext:                  encodeOctets(message.Ciphertext),
		AuthenticationTag:           encodeOctets(message.AuthenticationTag),
	}

	if len(recipients) == 1 {
		rawMessage.Header = recipients[0].Header
		rawMessage.EncryptedKey = recipients[0].EncryptedKey
	} else {
		rawMessage.Recipients = recipients
	}

	return json.Marshal(rawMessage)
}

// UnmarshalJSON reads the general or the flattened JWE JSON Serialization. It
// finds which serialization came in from the members of the object.
//
// UnmarshalJSON keeps a recipient with an "alg" value that this module does not
// supply. See [decodeRecipient]. It gives [ErrMalformedMessage] for an object
// that is not one of the two serializations, and [jsontext.ErrDuplicateName] for
// a member name two times in one of the objects.
func (message *Message) UnmarshalJSON(data []byte) error {
	rawMessage := new(rawMessage)
	if err := json.Unmarshal(data, rawMessage); err != nil {
		return jsonerr.KeepDuplicateName(err)
	}

	if len(rawMessage.Recipients) != 0 && (rawMessage.EncryptedKey != "" || len(rawMessage.Header) != 0) {
		return fmt.Errorf("%w: both a recipients array and a hoisted recipient", ErrMalformedMessage)
	}

	protectedHeader := new(header.Header)
	if rawMessage.ProtectedHeader != "" {
		if err := protectedHeader.Unmarshal(rawMessage.ProtectedHeader); err != nil {
			return err
		}
	}

	decoded := &Message{
		ProtectedHeader: protectedHeader,
		SharedHeader:    rawMessage.SharedHeader,
	}

	for _, part := range []struct {
		name    string
		encoded string
		decoded *[]byte
	}{
		{"iv", rawMessage.InitializationVector, &decoded.InitializationVector},
		{"ciphertext", rawMessage.Ciphertext, &decoded.Ciphertext},
		{"tag", rawMessage.AuthenticationTag, &decoded.AuthenticationTag},
	} {
		octets, err := decodeOctets(part.encoded)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrMalformedMessage, part.name, err)
		}

		*part.decoded = octets
	}

	if rawMessage.AdditionalAuthenticatedData != "" {
		additionalAuthenticatedData, err := decodeOctets(rawMessage.AdditionalAuthenticatedData)
		if err != nil {
			return fmt.Errorf("%w: aad: %w", ErrMalformedMessage, err)
		}

		decoded.AdditionalAuthenticatedData = additionalAuthenticatedData
	}

	rawRecipients := rawMessage.Recipients
	if len(rawRecipients) == 0 {
		rawRecipients = []*rawRecipient{{Header: rawMessage.Header, EncryptedKey: rawMessage.EncryptedKey}}
	}

	decoded.Recipients = make([]*Recipient, 0, len(rawRecipients))
	for _, rawRecipient := range rawRecipients {
		if rawRecipient == nil {
			return fmt.Errorf("%w: empty recipient", ErrMalformedMessage)
		}

		recipient, err := decodeRecipient(rawRecipient)
		if err != nil {
			return err
		}

		decoded.Recipients = append(decoded.Recipients, recipient)
	}

	*message = *decoded

	return nil
}
