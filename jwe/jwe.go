// Package jwe supplies JSON Web Encryption, RFC 7516.
//
// A [Message] is the object that the RFC calls a JWE. It is content that this package
// encrypts with a Content Encryption Key, and a key management algorithm gives
// protection to that key for each recipient. It is the encrypting counterpart of
// the jws package, and it uses the header package with jws. The JOSE header is
// one header, and most of its parameters have the same function in the two
// objects.
//
// This package makes two limits, and it records each of them at the position
// where it applies them. Each limit is one direction of an algorithm. The RSA1_5
// key management algorithm is available on decryption, but this package does not
// write it. Compression with "zip" is the same in the two directions.
package jwe

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
)

// Recipient is one recipient of a [Message]. It holds the JWE Encrypted Key
// with the CEK for that recipient. It also holds the JWE Per-Recipient
// Unprotected Header, which gives the properties of that key.
//
// It is the counterpart of [jws.Signature], for the same cause. A JWE, as a
// JWS does, can go to some parties, and the JSON serialization gives each party a
// different entry.
type Recipient struct {
	// Header is the JWE Per-Recipient Unprotected Header. It occurs in the JSON
	// serialization only.
	Header *header.Header

	// EncryptedKey is the JWE Encrypted Key. It is empty for the two key
	// management modes that make no wrapped key, which are direct encryption and
	// direct key agreement. For those modes the empty value is correct, and it is
	// not a missing value.
	EncryptedKey []byte

	rawHeader []byte

	unsupported error
}

func (recipient *Recipient) members() ([]string, error) {
	if recipient.unsupported != nil {
		return header.MembersIn(recipient.rawHeader)
	}

	return recipient.Header.Members()
}

// Message is a JWE.
//
// A Message holds the headers, the recipients, and the encrypted content.
// [Message.Encrypt] and [Message.Decrypt] operate on it.
//
// The zero Message has no protected header, and [Message.Decrypt] rejects it with
// [ErrMalformedMessage].
type Message struct {
	// ProtectedHeader is the JWE Protected Header. Its encoded octets are the
	// Additional Authenticated Data for the content encryption. Thus the tag
	// protects the integrity of each parameter in it, and no party can change one
	// in transit without an unsuccessful tag check.
	ProtectedHeader *header.Header

	// SharedHeader is the JWE Shared Unprotected Header. It occurs in the JSON
	// serialization only. It is not in the Additional Authenticated Data, thus it
	// has no protection.
	SharedHeader *header.Header

	// Recipients holds one entry for each party that can decrypt the message.
	Recipients []*Recipient

	// InitializationVector, Ciphertext and AuthenticationTag are the JWE
	// Initialization Vector, the JWE Ciphertext and the JWE Authentication Tag.
	InitializationVector []byte
	Ciphertext           []byte
	AuthenticationTag    []byte

	// AdditionalAuthenticatedData is the "aad" member. It is application data that
	// the tag authenticates but that this package does not encrypt. The compact
	// serialization has no position for it.
	AdditionalAuthenticatedData []byte
}

// ErrMalformedMessage is the error for a JWE that this package cannot read as a
// JWE. It is different from a JWE that reads correctly but does not decrypt.
var ErrMalformedMessage = errors.New("jwe: malformed JWE")

// ErrDuplicateHeaderParameter is the error for a parameter name in more than one
// of the three headers of a recipient.
//
// RFC 7516 section 7.2.1 gives the rule: "The Header Parameter names in the three
// locations MUST be disjoint." Section 5.2 gives it again as a decryption step.
//
// The rule makes "the JOSE Header" one object. This package makes the
// three headers one header by union, and a name in two of them has no specified
// value.
//
// A parameter with integrity protection can also occur again in an unprotected
// header. An attacker can then change that value, and the tag does not change.
var ErrDuplicateHeaderParameter = errors.New("jwe: duplicate header parameter")

func checkDisjoint(memberLists ...[]string) error {
	seen := map[string]bool{}

	var duplicates []string

	for _, names := range memberLists {
		for _, name := range names {
			if seen[name] {
				duplicates = append(duplicates, name)
			}

			seen[name] = true
		}
	}

	if len(duplicates) != 0 {
		slices.Sort(duplicates)

		return fmt.Errorf("%w: %s", ErrDuplicateHeaderParameter, strings.Join(slices.Compact(duplicates), ", "))
	}

	return nil
}

func (message *Message) checkHeaders() error {
	sharedMembers, err := message.SharedHeader.Members()
	if err != nil {
		return err
	}

	var (
		protectedMembers     []string
		protectedMembersRead bool
	)

	for _, recipient := range message.Recipients {
		if recipient == nil {
			return fmt.Errorf("%w: empty recipient", ErrMalformedMessage)
		}

		recipientMembers, err := recipient.members()
		if err != nil {
			return err
		}

		if len(sharedMembers) == 0 && len(recipientMembers) == 0 {
			continue
		}

		if !protectedMembersRead {
			protectedMembers, err = message.ProtectedHeader.Members()
			if err != nil {
				return err
			}

			protectedMembersRead = true
		}

		if err := checkDisjoint(protectedMembers, sharedMembers, recipientMembers); err != nil {
			return err
		}
	}

	return nil
}

// ErrCompressedPlaintext is the error when a caller tells this package to
// compress a plaintext before encryption.
//
// To compress before encryption lets the length of the ciphertext give data about
// the plaintext. The CRIME and BREACH family of attacks uses this property.
//
// RFC 7516 gives a SHOULD NOT and not a MUST NOT. This package obeys it in one
// direction only. It decompresses a compressed JWE from a different producer,
// thus interoperability stays. But it does not write one. This is the same
// shape as the rule for "b64" in this module: do not write a value that you
// continue to read.
//
// The asymmetry is correct. A sender keeps all its data when this package
// rejects a value on the producer side. But to reject it on the recipient side keeps a
// message from a recipient with the right to it.
var ErrCompressedPlaintext = errors.New("jwe: refusing to compress before encrypting")

// ErrOversizedPlaintext is the error when a compressed JWE becomes larger than
// [maximumPlaintextSize].
//
// Without a limit, "zip" is a decompression bomb. Some hundred octets of
// ciphertext can hold gigabytes of zeros, and the recipient allocates all of that
// memory before it reads one claim.
var ErrOversizedPlaintext = errors.New("jwe: decompressed plaintext too large")

const maximumPlaintextSize = 1 << 24

func (message *Message) contentEncryption() (jwa.ContentEncrypter, error) {
	if message.ProtectedHeader == nil {
		return nil, fmt.Errorf("%w: no protected header", ErrMalformedMessage)
	}

	if message.ProtectedHeader.EncryptionAlgorithm == nil {
		return nil, fmt.Errorf("%w: the protected header names no enc", ErrMalformedMessage)
	}

	for _, unprotectedHeader := range []*header.Header{message.SharedHeader, unprotectedHeaders(message)} {
		if unprotectedHeader != nil && unprotectedHeader.EncryptionAlgorithm != nil {
			return nil, fmt.Errorf("%w: enc outside the protected header", ErrMalformedMessage)
		}
	}

	return message.ProtectedHeader.EncryptionAlgorithm, nil
}

func unprotectedHeaders(message *Message) *header.Header {
	for _, recipient := range message.Recipients {
		if recipient != nil && recipient.Header != nil && recipient.Header.EncryptionAlgorithm != nil {
			return recipient.Header
		}
	}

	return nil
}

func (message *Message) keyManagement(recipient *Recipient) (jwa.Algorithm, error) {
	if message.ProtectedHeader != nil && message.ProtectedHeader.Algorithm != nil {
		return message.ProtectedHeader.Algorithm, nil
	}

	if message.SharedHeader != nil && message.SharedHeader.Algorithm != nil {
		return message.SharedHeader.Algorithm, nil
	}

	if recipient != nil && recipient.Header != nil && recipient.Header.Algorithm != nil {
		return recipient.Header.Algorithm, nil
	}

	return nil, fmt.Errorf("%w: no alg for this recipient", ErrMalformedMessage)
}

func (message *Message) additionalAuthenticatedData(encodedProtectedHeader string) []byte {
	if message.AdditionalAuthenticatedData == nil {
		return []byte(encodedProtectedHeader)
	}

	var buffer bytes.Buffer
	buffer.WriteString(encodedProtectedHeader)
	buffer.WriteRune('.')
	buffer.WriteString(encodeOctets(message.AdditionalAuthenticatedData))

	return buffer.Bytes()
}

// RecipientKey names one party that this package encrypts a message to. It holds
// the key that gives protection to the Content Encryption Key of that party, and the
// optional JWE Per-Recipient Unprotected Header.
//
// The header holds the parameters that are different for each recipient. Examples
// are a "kid" value that names which key this is, and an "alg" value when the
// protected header gives none. [Message.EncryptTo] writes the parameters that the
// key management algorithm makes, for example "epk" and "p2s". A caller does
// not supply those.
type RecipientKey struct {
	Header *header.Header
	Key    any
}

// Encrypt fills in the message from a plaintext and one recipient key.
//
// The protected header must first name "alg" and "enc". Encrypt writes each
// parameter that the key management algorithm publishes into that header before
// it encodes the header. Thus those parameters are in the Additional
// Authenticated Data.
func (message *Message) Encrypt(plaintext []byte, key any) error {
	return message.EncryptTo(plaintext, RecipientKey{Key: key})
}

// EncryptTo fills in the message from a plaintext and one recipient key or more.
// It encrypts the content one time and does the key management step again for
// each recipient.
//
// A message with more than one recipient cannot use direct encryption or Direct
// Key Agreement. Those modes calculate the CEK and do not select it, thus there
// is no one key for some parties to receive. With "dir", a second recipient
// gets the long-term key of the first recipient. See
// [jwa.ErrDirectKeyManagement].
//
// EncryptTo gives [ErrMalformedMessage] if recipients is empty.
func (message *Message) EncryptTo(plaintext []byte, recipients ...RecipientKey) error {
	if len(recipients) == 0 {
		return fmt.Errorf("%w: no recipients", ErrMalformedMessage)
	}

	encryption, err := message.contentEncryption()
	if err != nil {
		return err
	}

	if message.ProtectedHeader.CompressionAlgorithm != "" {
		return fmt.Errorf("%w: %s", ErrCompressedPlaintext, message.ProtectedHeader.CompressionAlgorithm)
	}

	protectedParameters := message.ProtectedHeader.KeyParameters()

	cek, encrypted, err := message.encryptKeys(encryption, protectedParameters, recipients)
	if err != nil {
		return err
	}

	message.Recipients = encrypted

	if len(recipients) == 1 {
		if err := message.ProtectedHeader.SetKeyParameters(protectedParameters); err != nil {
			return err
		}
	}

	if err := message.checkHeaders(); err != nil {
		return err
	}

	initializationVector, err := randomOctets(encryption.IVSize())
	if err != nil {
		return err
	}

	encodedProtectedHeader, err := message.ProtectedHeader.Marshal()
	if err != nil {
		return err
	}

	message.ProtectedHeader.SetEncoded(encodedProtectedHeader)

	ciphertext, tag, err := encryption.Encrypt(
		plaintext, cek, initializationVector, message.additionalAuthenticatedData(encodedProtectedHeader),
	)
	if err != nil {
		return err
	}

	message.InitializationVector = initializationVector
	message.Ciphertext = ciphertext
	message.AuthenticationTag = tag

	return nil
}

func (message *Message) encryptKeys(
	encryption jwa.ContentEncrypter, protectedParameters *jwa.KeyParameters, recipients []RecipientKey,
) ([]byte, []*Recipient, error) {
	if len(recipients) == 1 {
		recipient := &Recipient{Header: recipients[0].Header}

		algorithm, err := message.keyManagement(recipient)
		if err != nil {
			return nil, nil, err
		}

		keyEncrypter, ok := algorithm.(jwa.KeyEncrypter)
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s cannot manage a key", jwa.ErrUnsupportedAlgorithm, algorithm)
		}

		cek, encryptedKey, err := keyEncrypter.EncryptKey(recipients[0].Key, encryption, protectedParameters)
		if err != nil {
			return nil, nil, err
		}

		recipient.EncryptedKey = encryptedKey

		return cek, []*Recipient{recipient}, nil
	}

	cek, err := jwa.GenerateContentEncryptionKey(encryption)
	if err != nil {
		return nil, nil, err
	}

	encrypted := make([]*Recipient, 0, len(recipients))

	for _, recipientKey := range recipients {
		recipient := &Recipient{Header: recipientKey.Header}

		algorithm, err := message.keyManagement(recipient)
		if err != nil {
			return nil, nil, err
		}

		keyWrapper, ok := algorithm.(jwa.KeyWrapper)
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s", jwa.ErrDirectKeyManagement, algorithm)
		}

		parameters := *protectedParameters

		encryptedKey, err := keyWrapper.WrapKey(cek, recipientKey.Key, encryption, &parameters)
		if err != nil {
			return nil, nil, err
		}

		recipient.EncryptedKey = encryptedKey

		if !parametersEqual(protectedParameters, &parameters) {
			if recipient.Header == nil {
				recipient.Header = new(header.Header)
			}

			if err := recipient.Header.SetKeyParameters(&parameters); err != nil {
				return nil, nil, err
			}
		}

		encrypted = append(encrypted, recipient)
	}

	return cek, encrypted, nil
}

func parametersEqual(a, b *jwa.KeyParameters) bool {
	return a.EphemeralPublicKey == b.EphemeralPublicKey &&
		bytes.Equal(a.AgreementPartyUInfo, b.AgreementPartyUInfo) &&
		bytes.Equal(a.AgreementPartyVInfo, b.AgreementPartyVInfo) &&
		bytes.Equal(a.InitializationVector, b.InitializationVector) &&
		bytes.Equal(a.AuthenticationTag, b.AuthenticationTag) &&
		bytes.Equal(a.PBES2SaltInput, b.PBES2SaltInput) &&
		a.PBES2Count == b.PBES2Count
}

// Decrypt returns the plaintext. It tries each recipient and stops at the first
// recipient that gives the plaintext.
//
// Each failure after this method reads the algorithms gives
// [jwa.ErrDecryptionFailed] and no other error. This is necessary. An attacker
// who can see the difference between "the key did not unwrap" and "the tag did
// not verify" has a decryption oracle. The history of PKCS #1 v1.5 shows the
// value of such an oracle.
func (message *Message) Decrypt(key any) ([]byte, error) {
	encryption, additionalAuthenticatedData, err := message.prepareDecryption()
	if err != nil {
		return nil, err
	}

	var failure error

	for _, recipient := range message.Recipients {
		plaintext, err := message.decryptRecipient(recipient, key, encryption, additionalAuthenticatedData)
		if err != nil {
			failure = err

			continue
		}

		return message.decompress(plaintext)
	}

	return nil, message.decryptionFailure(failure)
}

func (message *Message) prepareDecryption() (jwa.ContentEncrypter, []byte, error) {
	encryption, err := message.contentEncryption()
	if err != nil {
		return nil, nil, err
	}

	if len(message.Recipients) == 0 {
		return nil, nil, fmt.Errorf("%w: no recipients", ErrMalformedMessage)
	}

	if err := message.checkHeaders(); err != nil {
		return nil, nil, err
	}

	encodedProtectedHeader, err := message.ProtectedHeader.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return encryption, message.additionalAuthenticatedData(encodedProtectedHeader), nil
}

func (message *Message) decryptRecipient(
	recipient *Recipient,
	key any,
	encryption jwa.ContentEncrypter,
	additionalAuthenticatedData []byte,
) ([]byte, error) {
	if recipient.unsupported != nil {
		return nil, recipient.unsupported
	}

	algorithm, err := message.keyManagement(recipient)
	if err != nil {
		return nil, err
	}

	keyDecrypter, ok := algorithm.(jwa.KeyDecrypter)
	if !ok {
		return nil, fmt.Errorf("%w: %s cannot manage a key", jwa.ErrUnsupportedAlgorithm, algorithm)
	}

	parameters := message.keyParameters(recipient)

	cek, err := keyDecrypter.DecryptKey(recipient.EncryptedKey, key, encryption, parameters)
	if err != nil {
		return nil, err
	}

	return encryption.Decrypt(
		message.Ciphertext,
		cek,
		message.InitializationVector,
		additionalAuthenticatedData,
		message.AuthenticationTag,
	)
}

func (message *Message) decryptionFailure(failure error) error {
	if len(message.Recipients) == 1 && failure != nil && !errors.Is(failure, jwa.ErrDecryptionFailed) {
		return failure
	}

	return jwa.ErrDecryptionFailed
}

// RecipientOutcome records the result of one recipient entry with a given key.
//
// Step 18 of RFC 7516 section 5.2 makes an implementation give this data with the
// plaintext: "In the JWE JSON Serialization case, also return a result to the
// application indicating for which of the recipients the decryption succeeded and
// failed."
type RecipientOutcome struct {
	// Recipient is the entry of this outcome. It is the same pointer that the
	// message holds, thus a "kid" value in its header names it where such a value
	// is present.
	Recipient *Recipient

	// Succeeded reports whether this entry gave the plaintext.
	//
	// One key opens one entry. Thus with some recipients the usual result is one
	// true value. The other entries fail, and that is the correct result. Those
	// entries go to parties whose keys the caller does not hold.
	Succeeded bool

	// Err is the cause of the failure of the entry. It is nil when the entry did
	// not fail.
	//
	// Err gives only the data that the holder of the message can already find. An
	// "alg" value that is unsupported or missing is in the document for each
	// reader, thus Err names it. Each condition after a key becomes
	// [jwa.ErrDecryptionFailed]. Examples are an unwrap that failed and a tag that
	// did not verify. This is the same rule that [Message.Decrypt] applies. To
	// tell those two conditions apart is the decryption oracle that the section
	// closes.
	Err error
}

// DecryptAll returns the plaintext and reports, for each recipient, whether the
// entry of that recipient gave the plaintext. It is [Message.Decrypt] with the
// second half of step 18 of the decryption procedure. An application uses it
// when it must know which entry it read. Examples are an application with some
// keys, and a recipient of a message that must know which party it is.
//
// The plaintext and the error are the values that [Message.Decrypt] gives.
// DecryptAll gives the outcomes in the two conditions. Thus a message that no
// recipient can open continues to report the cause for each recipient. The
// outcomes are nil only when the message is malformed and this method came to
// no recipient.
//
// DecryptAll tries each recipient and does not stop at the first recipient that
// is correct. This makes one key unwrap necessary for each remaining entry.
// That is the cause of the different method. The data has a value only to a
// caller that made the request.
func (message *Message) DecryptAll(key any) ([]byte, []RecipientOutcome, error) {
	encryption, additionalAuthenticatedData, err := message.prepareDecryption()
	if err != nil {
		return nil, nil, err
	}

	outcomes := make([]RecipientOutcome, 0, len(message.Recipients))

	var plaintext []byte

	var failure error

	for _, recipient := range message.Recipients {
		recipientPlaintext, err := message.decryptRecipient(recipient, key, encryption, additionalAuthenticatedData)

		outcomes = append(outcomes, RecipientOutcome{
			Recipient: recipient,
			Succeeded: err == nil,
			Err:       message.outcomeFailure(err),
		})

		if err != nil {
			failure = err

			continue
		}

		if plaintext == nil {
			plaintext = recipientPlaintext
		}
	}

	if plaintext == nil {
		return nil, outcomes, message.decryptionFailure(failure)
	}

	decompressed, err := message.decompress(plaintext)
	if err != nil {
		return nil, outcomes, err
	}

	return decompressed, outcomes, nil
}

func (message *Message) outcomeFailure(failure error) error {
	if failure == nil {
		return nil
	}

	if errors.Is(failure, jwa.ErrUnsupportedAlgorithm) || errors.Is(failure, ErrMalformedMessage) {
		return failure
	}

	return message.decryptionFailure(failure)
}

func (message *Message) keyParameters(recipient *Recipient) *jwa.KeyParameters {
	parameters := message.ProtectedHeader.KeyParameters()

	if message.SharedHeader != nil {
		mergeKeyParameters(parameters, message.SharedHeader.KeyParameters())
	}

	if recipient.Header != nil {
		mergeKeyParameters(parameters, recipient.Header.KeyParameters())
	}

	return parameters
}

func mergeKeyParameters(base, overlay *jwa.KeyParameters) {
	if overlay.EphemeralPublicKey != nil {
		base.EphemeralPublicKey = overlay.EphemeralPublicKey
	}

	for _, octets := range []struct{ base, overlay *[]byte }{
		{&base.AgreementPartyUInfo, &overlay.AgreementPartyUInfo},
		{&base.AgreementPartyVInfo, &overlay.AgreementPartyVInfo},
		{&base.InitializationVector, &overlay.InitializationVector},
		{&base.AuthenticationTag, &overlay.AuthenticationTag},
		{&base.PBES2SaltInput, &overlay.PBES2SaltInput},
	} {
		if *octets.overlay != nil {
			*octets.base = *octets.overlay
		}
	}

	if overlay.PBES2Count != 0 {
		base.PBES2Count = overlay.PBES2Count
	}
}

func (message *Message) decompress(plaintext []byte) ([]byte, error) {
	compression := message.ProtectedHeader.CompressionAlgorithm
	if compression == "" {
		return plaintext, nil
	}

	if compression != header.Deflate {
		return nil, fmt.Errorf("%w: unsupported zip %q", ErrMalformedMessage, compression)
	}

	reader := flate.NewReader(bytes.NewReader(plaintext))
	defer func() { _ = reader.Close() }()

	decompressed, err := io.ReadAll(io.LimitReader(reader, maximumPlaintextSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMessage, err)
	}

	if len(decompressed) > maximumPlaintextSize {
		return nil, ErrOversizedPlaintext
	}

	return decompressed, nil
}
