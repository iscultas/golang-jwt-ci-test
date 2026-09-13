package rfc7516_test

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
)

const multipleRecipients = `{
  "protected":
   "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  "unprotected":
   {"jku":"https://server.example.com/keys.jwks"},
  "recipients":[
   {"header":
     {"alg":"RSA1_5","kid":"2011-04-29"},
    "encrypted_key":
     "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
   {"header":
     {"alg":"A128KW","kid":"7"},
    "encrypted_key":
     "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
  "iv":
   "AxY8DCtDaGlsbGljb3RoZQ",
  "ciphertext":
   "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
  "tag":
   "Mz-VPPyU4RlcuYv1IwIvzw"
 }`

const multipleRecipientsKey = `{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`

const appendixA2Key = `{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB","d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ","p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM","q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0","dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs","dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU","qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"}`

const appendixA2 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
	"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" +
	"1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" +
	"HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" +
	"NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" +
	"rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" +
	"-B3oWh2TbqmScqXMR4gp_A." +
	"AxY8DCtDaGlsbGljb3RoZQ." +
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
	"9hH0vgRfYgPnAHOd8stkvw"

var unserviceableRecipients = strings.Replace(
	multipleRecipients, `"alg":"RSA1_5"`, `"alg":"ECDH-1PU"`, 1,
)

const multipleRecipientsPlaintext = "Live long and prosper."

func recipientKey(t *testing.T) any {
	t.Helper()

	return parseVectorKey(t, multipleRecipientsKey)
}

func rsaRecipientKey(t *testing.T) any {
	t.Helper()

	return parseVectorKey(t, appendixA2Key)
}

func parseVectorKey(t *testing.T, encoded string) any {
	t.Helper()

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(encoded), key); err != nil {
		t.Fatalf("cannot parse the key: %v", err)
	}

	return key.Material()
}

// TestAppendixA2Decrypts checks this module against the specification's own
// worked RSAES-PKCS1-v1_5 example.
//
// rfc-req: RFC7518-S4_2-R01
// The RFC publishes it for exactly this: "These results can be used to validate
// JWE decryption implementations for these algorithms."
//
// It is the assertion no test this module writes for itself can make. The
// ciphertext was produced by another implementation, so decrypting it shows the
// unwrap agrees with RFC 3447's padding and not merely with jwa's own idea of
// it -- and a round trip through code that both encrypts and decrypts could not
// show that even if this module encrypted, which it does not.
func TestAppendixA2Decrypts(t *testing.T) {
	message, err := jwe.Unmarshal(appendixA2)
	if err != nil {
		t.Fatalf("cannot parse Appendix A.2: %v", err)
	}

	plaintext, err := message.Decrypt(rsaRecipientKey(t))
	if err != nil {
		t.Fatalf("cannot decrypt Appendix A.2: %v", err)
	}

	if string(plaintext) != multipleRecipientsPlaintext {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
	}
}

// TestEitherRecipientOfAppendixA4Opens checks that a multi-recipient document
// opens under each of the keys it is addressed to.
//
// rfc-req: RFC7516-S7_2_1-R14
// MUST — "Therefore, all Header Parameters that specify the treatment of the
// plaintext value MUST be the same for all recipients." The preceding sentence
// carries no keyword and states the same thing of the parts rather than the
// parameters: "All recipients use the same JWE Protected Header, JWE
// Initialization Vector, JWE Ciphertext, and JWE Authentication Tag values."
//
// Appendix A.4 encrypts one plaintext to two parties under two different key
// management algorithms over one protected header, IV, ciphertext and tag, and
// the invariant is that the two arrive at the same CEK. This module's own
// multi-recipient tests assert that too, but against messages it wrote itself,
// where a mutation of the write path is what catches a divergence. Here the
// document was written by somebody else. Until RSA1_5 was implemented only the
// A128KW half of this vector could be exercised.
func TestEitherRecipientOfAppendixA4Opens(t *testing.T) {
	for name, key := range map[string]func(*testing.T) any{
		"RSA1_5": rsaRecipientKey,
		"A128KW": recipientKey,
	} {
		t.Run(name, func(t *testing.T) {
			message := new(jwe.Message)
			if err := json.Unmarshal([]byte(multipleRecipients), message); err != nil {
				t.Fatalf("cannot parse Appendix A.4: %v", err)
			}

			plaintext, err := message.Decrypt(key(t))
			if err != nil {
				t.Fatalf("cannot decrypt Appendix A.4: %v", err)
			}

			if string(plaintext) != multipleRecipientsPlaintext {
				t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
			}
		})
	}
}

// TestARecipientWeCannotServeDoesNotInvalidateTheMessage checks that a JWE
// addressed to several parties decrypts for a party this module can serve, even
// when another recipient names an algorithm it does not implement.
//
// MUST — "If there was no recipient for which all of the decryption steps
// succeeded, then the JWE MUST be considered invalid."
//
// The sentence is a rule about *no* recipient succeeding, and this is the case
// that distinguishes it from a rule about *every* recipient succeeding. Step 12
// records per recipient whether the CEK could be determined and step 13 repeats
// the process for each; a recipient that fails is data for step 18, not an end
// to the procedure.
//
// This module read neither this document nor RFC 7520 §5.13 until the rule was
// implemented: rawRecipient.Header decoded into a header.Header, which refuses
// an unimplemented "alg" outright, so one entry failed the whole document and
// denied the holder of the other key a message they were entitled to. Vectors
// this module did not produce are the only place that shows.
//
// Appendix A.4's own first recipient names RSA1_5, which was that unimplemented
// algorithm when this test was written and is implemented now. The vector
// therefore no longer contains the case, so it is exercised on A.4 with that
// "alg" rewritten to a name no registry holds. See unserviceableRecipients.
//
// rfc-req: RFC7516-S5_2-R04
func TestARecipientWeCannotServeDoesNotInvalidateTheMessage(t *testing.T) {
	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(unserviceableRecipients), message); err != nil {
		t.Fatalf("cannot parse Appendix A.4: %v", err)
	}

	if len(message.Recipients) != 2 {
		t.Fatalf("got %d recipients, want 2", len(message.Recipients))
	}

	plaintext, err := message.Decrypt(recipientKey(t))
	if err != nil {
		t.Fatalf("cannot decrypt Appendix A.4 with the second recipient's key: %v", err)
	}

	if string(plaintext) != multipleRecipientsPlaintext {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
	}
}

// TestAMessageWithNoServiceableRecipientIsInvalid checks the other half of the
// same sentence.
//
// rfc-req: RFC7516-S5_2-R01
// MUST — "in all cases, the encrypted content for at least one recipient MUST
// successfully validate or the JWE will be considered invalid."
//
// Appendix A.4 with the second recipient removed and the first one's "alg"
// rewritten leaves a document with one entry this module cannot serve, which is
// exactly the "no recipient succeeded" case. Tolerating an unserviceable
// recipient must not become tolerating a message made entirely of them, and the
// failure must name the reason rather than collapsing to
// jwa.ErrDecryptionFailed: a single recipient makes it unambiguous whose
// algorithm was refused, and nothing is leaked by saying so -- an attacker
// chooses none of it.
func TestAMessageWithNoServiceableRecipientIsInvalid(t *testing.T) {
	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(unserviceableRecipients), message); err != nil {
		t.Fatalf("cannot parse Appendix A.4: %v", err)
	}

	message.Recipients = message.Recipients[:1]

	_, err := message.Decrypt(recipientKey(t))
	if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestARecipientThatFailsLaterIsAlsoSkipped checks the other two ways a
// recipient can fail to yield a key management algorithm.
//
// MUST — "If there was no recipient for which all of the decryption steps
// succeeded, then the JWE MUST be considered invalid."
//
// A recipient can be unusable without being unparseable. Its "alg" may resolve
// to an algorithm that cannot manage a key at all — jwa keeps one registry for
// JWS and JWE, so "ES256" parses here and is refused at the use site — or it may
// name no "alg" in any of the three headers, which §7.2.1's last-resort rule
// makes malformed for that recipient. Neither says anything about the other
// recipients, so both take the same path as the unimplemented case.
//
// This test exists because a mutation showed it was needed: reverting those two
// branches to abort the loop broke no test in the module. The unimplemented-"alg"
// case is covered by unserviceableRecipients and by RFC 7520 §5.13, but nothing
// reached these two, and consistency that no test can tell from inconsistency is
// not a property the suite has established.
//
// rfc-req: RFC7516-S5_2-R04
func TestARecipientThatFailsLaterIsAlsoSkipped(t *testing.T) {
	message := func(t *testing.T, firstHeader string) *jwe.Message {
		t.Helper()

		decoded := new(jwe.Message)
		if err := json.Unmarshal([]byte(strings.Replace(
			multipleRecipients,
			`{"alg":"RSA1_5","kid":"2011-04-29"}`,
			firstHeader,
			1,
		)), decoded); err != nil {
			t.Fatalf("cannot parse: %v", err)
		}

		if len(decoded.Recipients) != 2 {
			t.Fatalf("got %d recipients, want 2", len(decoded.Recipients))
		}

		return decoded
	}

	for name, firstHeader := range map[string]string{
		"an alg that cannot manage a key": `{"alg":"ES256","kid":"2011-04-29"}`,
		"no alg at all":                   `{"kid":"2011-04-29"}`,
	} {
		t.Run(name, func(t *testing.T) {
			plaintext, err := message(t, firstHeader).Decrypt(recipientKey(t))
			if err != nil {
				t.Fatalf("cannot decrypt with the second recipient's key: %v", err)
			}

			if string(plaintext) != multipleRecipientsPlaintext {
				t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
			}
		})
	}
}

// TestAnUnserviceableRecipientSurvivesARoundTrip checks that re-serializing a
// message does not discard the entry belonging to somebody else.
//
// rfc-req: RFC7516-S7_2_1-R12
// MUST — "Additional members can be present in both the JSON objects defined
// above; if not understood by implementations encountering them, they MUST be
// ignored."
//
// Two things are ignored rather than refused here, and both are asserted: the
// "jku" of the shared unprotected header, which this module never dereferences,
// and the whole first recipient, whose "alg" names an algorithm no registry
// holds. Ignoring is not the same as dropping. An implementation that re-emitted
// this document without the first recipient would have silently revoked one
// party's access, so the octets it arrived as are retained and written back.
func TestAnUnserviceableRecipientSurvivesARoundTrip(t *testing.T) {
	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(unserviceableRecipients), message); err != nil {
		t.Fatalf("cannot parse Appendix A.4: %v", err)
	}

	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("cannot re-encode: %v", err)
	}

	reread := new(jwe.Message)
	if err := json.Unmarshal(encoded, reread); err != nil {
		t.Fatalf("cannot re-read: %v", err)
	}

	if len(reread.Recipients) != 2 {
		t.Fatalf("got %d recipients after a round trip, want 2", len(reread.Recipients))
	}

	var reencoded map[string]any
	if err := json.Unmarshal(encoded, &reencoded); err != nil {
		t.Fatalf("cannot inspect the re-encoding: %v", err)
	}

	recipients, ok := reencoded["recipients"].([]any)
	if !ok || len(recipients) != 2 {
		t.Fatalf("the re-encoding does not carry two recipients: %v", reencoded["recipients"])
	}

	first, ok := recipients[0].(map[string]any)
	if !ok {
		t.Fatalf("the first recipient is not an object: %v", recipients[0])
	}

	firstHeader, ok := first["header"].(map[string]any)
	if !ok {
		t.Fatalf("the first recipient lost its header: %v", first)
	}

	if firstHeader["alg"] != "ECDH-1PU" || firstHeader["kid"] != "2011-04-29" {
		t.Errorf("the first recipient's header changed: %v", firstHeader)
	}

	plaintext, err := reread.Decrypt(recipientKey(t))
	if err != nil {
		t.Fatalf("cannot decrypt after a round trip: %v", err)
	}

	if string(plaintext) != multipleRecipientsPlaintext {
		t.Errorf("plaintext mismatch after a round trip:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
	}
}

// TestAnUnserviceableRecipientIsStillCheckedForDisjointness checks that the one
// header this module cannot parse is not a place to hide a second "enc".
//
// rfc-req: RFC7516-S5_2-R02
// MUST — "When using the JWE JSON Serialization, this restriction includes that
// the same Header Parameter name also MUST NOT occur in distinct JSON object
// values that together comprise the JOSE Header."
//
// This is the security-relevant consequence of retaining an unparsed header
// rather than refusing the document. contentEncryption sweeps the parsed
// headers for a stray "enc"; an unparsed one is invisible to it. What catches
// this case instead is the disjointness check, which reads the member names
// straight out of the retained octets, so a second "enc" collides with the
// protected header's -- which §4.1.2 requires to be present.
func TestAnUnserviceableRecipientIsStillCheckedForDisjointness(t *testing.T) {
	smuggled := `{
      "protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "recipients":[
       {"header":{"alg":"ECDH-1PU","enc":"A128GCM"},"encrypted_key":"UGhI"},
       {"header":{"alg":"A128KW"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
      "iv":"AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":"Mz-VPPyU4RlcuYv1IwIvzw"
     }`

	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(smuggled), message); err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	_, err := message.Decrypt(recipientKey(t))
	if !errors.Is(err, jwe.ErrDuplicateHeaderParameter) {
		t.Errorf("got %v, want ErrDuplicateHeaderParameter", err)
	}
}

// TestAMalformedRecipientHeaderIsStillFatal checks that the tolerance added for
// unimplemented algorithms did not become tolerance of nonsense.
//
// rfc-req: RFC7516-S5_2-R02
// MUST (see above; this is the parse-time half) — a recipient whose header is
// not a valid JSON object is a document that cannot be read, not a recipient
// that failed. Only jwa.ErrUnsupportedAlgorithm is treated as the latter.
func TestAMalformedRecipientHeaderIsStillFatal(t *testing.T) {
	malformed := `{
      "protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "recipients":[
       {"header":{"alg":[]},"encrypted_key":"UGhI"},
       {"header":{"alg":"A128KW"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
      "iv":"AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":"Mz-VPPyU4RlcuYv1IwIvzw"
     }`

	if err := json.Unmarshal([]byte(malformed), new(jwe.Message)); err == nil {
		t.Error("a recipient header with a non-string alg parsed")
	}
}

// TestTheOutcomeOfARecipientWeCouldNotOpenIsOpaque checks the bound RFC 7516
// §11.5 puts on what an outcome may say.
//
// rfc-req: RFC7516-S5_2-R04
// MUST — the same sentence as below, read together with §11.5's "the recipient
// MUST NOT distinguish between format, padding, and length errors of encrypted
// keys."
//
// Appendix A.4 as published is now the case that shows the boundary. Both its
// recipients name algorithms this module implements, so a holder of the A128KW
// key fails the first entry not because the "alg" was refused but because the key
// does not fit it. That failure is on the far side of the key, and it collapses
// to jwa.ErrDecryptionFailed exactly as it does for Decrypt.
//
// The distinction is the whole design of RecipientOutcome.Err: an "alg" written
// in the document may be named, since every reader has it, and nothing past that
// point may be. A per-recipient report is otherwise a fine place to reopen the
// oracle §11.5 exists to close.
func TestTheOutcomeOfARecipientWeCouldNotOpenIsOpaque(t *testing.T) {
	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(multipleRecipients), message); err != nil {
		t.Fatalf("cannot parse Appendix A.4: %v", err)
	}

	plaintext, outcomes, err := message.DecryptAll(recipientKey(t))
	if err != nil {
		t.Fatalf("cannot decrypt Appendix A.4: %v", err)
	}

	if string(plaintext) != multipleRecipientsPlaintext {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
	}

	if len(outcomes) != 2 {
		t.Fatalf("got %d outcomes, want one per recipient", len(outcomes))
	}

	if outcomes[0].Succeeded {
		t.Error("the RSA1_5 recipient reports success under the A128KW key")
	}

	if !errors.Is(outcomes[0].Err, jwa.ErrDecryptionFailed) {
		t.Errorf("got %v, want exactly ErrDecryptionFailed", outcomes[0].Err)
	}

	if errors.Is(outcomes[0].Err, jwa.ErrUnsupportedAlgorithm) {
		t.Error("the outcome names the algorithm for a failure past the key")
	}

	if !outcomes[1].Succeeded {
		t.Error("the A128KW recipient reports failure on a message it opened")
	}
}

// TestTheOutcomeOfEachRecipientIsReported covers the sentence step 18 adds after
// the one above.
//
// MUST — "In the JWE JSON Serialization case, also return a result to the
// application indicating for which of the recipients the decryption succeeded
// and failed."
//
// Appendix A.4 is the case the sentence is written for. It addresses two
// parties, and a holder of the A128KW key learns from Decrypt only that some
// recipient succeeded — not that it was the second, nor why the first did not.
// jwe.Message.DecryptAll answers both, and the "kid" in the entry's own header is
// what lets an application name the key it read.
//
// The first recipient's "alg" is rewritten here, as it is above: an outcome that
// names jwa.ErrUnsupportedAlgorithm is the failure this method exists to report,
// and A.4 as published no longer produces one. What A.4 produces now is the other
// failure, which TestTheOutcomeOfARecipientWeCouldNotOpenIsOpaque covers.
//
// The step 18 result was recorded as an unimplemented gap in this IR until
// DecryptAll existed; the vector was already here, so nothing but the API was
// missing.
//
// rfc-req: RFC7516-S5_2-R04
func TestTheOutcomeOfEachRecipientIsReported(t *testing.T) {
	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(unserviceableRecipients), message); err != nil {
		t.Fatalf("cannot parse Appendix A.4: %v", err)
	}

	plaintext, outcomes, err := message.DecryptAll(recipientKey(t))
	if err != nil {
		t.Fatalf("cannot decrypt Appendix A.4: %v", err)
	}

	if string(plaintext) != multipleRecipientsPlaintext {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, multipleRecipientsPlaintext)
	}

	if len(outcomes) != 2 {
		t.Fatalf("got %d outcomes, want one per recipient", len(outcomes))
	}

	if outcomes[0].Succeeded {
		t.Error("the unserviceable recipient reports success")
	}

	if !errors.Is(outcomes[0].Err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", outcomes[0].Err)
	}

	if !outcomes[1].Succeeded {
		t.Error("the A128KW recipient reports failure on a message it opened")
	}

	if outcomes[1].Err != nil {
		t.Errorf("the recipient that opened reports %v", outcomes[1].Err)
	}

	if outcomes[1].Recipient == nil || outcomes[1].Recipient.Header == nil {
		t.Fatal("the outcome names no recipient")
	}

	if kid := outcomes[1].Recipient.Header.KeyID; kid != "7" {
		t.Errorf(`the entry that opened has kid %q, want "7"`, kid)
	}

	slices.Reverse(message.Recipients)

	_, outcomes, err = message.DecryptAll(recipientKey(t))
	if err != nil {
		t.Fatalf("cannot decrypt the reordered message: %v", err)
	}

	if len(outcomes) != 2 {
		t.Fatalf("got %d outcomes after reordering, want one per recipient", len(outcomes))
	}

	if !outcomes[0].Succeeded {
		t.Error("the A128KW recipient, now first, reports failure")
	}

	if outcomes[1].Succeeded {
		t.Error("the unserviceable recipient, now last, reports success")
	}

	if !errors.Is(outcomes[1].Err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", outcomes[1].Err)
	}
}
