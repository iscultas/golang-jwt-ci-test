package rfc7520_test

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
)

const sharedUnprotectedAlg = `{"recipients":[{"encrypted_key":"jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"}],"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"},"protected":"eyJlbmMiOiJBMTI4R0NNIn0","iv":"WgEJsDS9bkoXQ3nR","ciphertext":"lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf","tag":"fNYLqpUe84KD45lvDiaBAQ"}`

const sharedUnprotectedAlgKey = `{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}`

const severalRecipients = `{"recipients":[{"encrypted_key":"dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zjwj4w6Y5G4XJQsNNIBiqyvUUAOcpL7S7-cFe7Pio7gV_Q06WmCSa-vhW6me4bWrBf7cHwEQJdXihidAYWVajJIaKMXMvFRMV6iDlRr076DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-wqjw0-b-S1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbeYSrRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n5trGuExtp_-dbHcGlihqc_wGgho9fLMK8JOArYLcMDNQ","header":{"alg":"RSA1_5","kid":"frodo.baggins@hobbiton.example"}},{"encrypted_key":"ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHixJuw_elY4gSSId_w","header":{"alg":"ECDH-ES+A256KW","kid":"peregrin.took@tuckborough.example","epk":{"kty":"EC","crv":"P-384","x":"Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2DtMRb25Ma2CX","y":"VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw91fzZ84pbfm"}}},{"encrypted_key":"a7CclAejo_7JSuPB8zeagxXRam8dwCfmkt9-WyTpS1E","header":{"alg":"A256GCMKW","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","tag":"59Nqh1LlYtVIhfD3pgRGvw","iv":"AvpeoPZ9Ncn9mkBn"}}],"unprotected":{"cty":"text/plain"},"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","iv":"VgEIHY20EnzUtZFl2RpB1g","ciphertext":"ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK04SjdxQeSw2L9mu3a_k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM9tBURMFqLByJ8vOYQX0oJW4VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSaP6ga7-siYxStR7_G07Thd1jh-zGT0wxM5g-VRORtq0K6AXpLlwEqRp7pkt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZukLpCbzhzMDLLw2-8I14FQrgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXMY9YQjorZ_P_JYG3ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2ofDQdLChtazE","tag":"BESYyFN7T09KY7i8zKs5_g"}`

var severalRecipientsKeys = map[string]string{
	"RSA1_5":         `{"kty":"RSA","kid":"frodo.baggins@hobbiton.example","use":"enc","n":"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegTHVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5UNwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4cR5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oypBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYAVotGlvMQ","e":"AQAB","d":"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wybQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PNmiuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2vpzj85bQQ","p":"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaEoekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ2VFmU","q":"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_VF099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8d6Et0","dp":"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTHQmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JVRDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsflo0rYU","dq":"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9MbpFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87ACfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14TkXlHE","qi":"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZlXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx2bQ_mM"}`,
	"ECDH-ES+A256KW": `{"kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP","d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}`,
	"A256GCMKW":      `{"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","use":"enc","alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"}`,
}

// RFC 7520 section 5.11 (test vector): "Protecting Specific Header Fields" --
// an example whose "alg" is in the JWE Shared Unprotected Header.
//
// RFC 7516 section 7.2.1 permits a header parameter in any of the three
// locations, and section 5.2 step 4 forms the JOSE Header from their union. This
// module reads "enc" from the protected header alone, since an "enc" an attacker
// can rewrite is the algorithm confusion of RFC 8725 section 3.1, but "alg" from
// any of them: it selects only how a party unwraps a key the tag already binds.
//
// rfc-req: RFC7520-S5_11-R01
func TestASharedUnprotectedAlgIsHonoured(t *testing.T) {
	message := new(jwe.Message)
	if err := json.Unmarshal([]byte(sharedUnprotectedAlg), message); err != nil {
		t.Fatalf("cannot parse section 5.11: %v", err)
	}

	plaintext, err := message.Decrypt(recipientKey(t, jweVector{key: sharedUnprotectedAlgKey}))
	if err != nil {
		t.Fatalf("cannot decrypt section 5.11: %v", err)
	}

	if string(plaintext) != jwePlaintext {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, jwePlaintext)
	}
}

// RFC 7520 section 5.13 (test vector): "Encrypting to Multiple Recipients".
//
// Two properties at once, and the second is the one worth having.
//
// The first is RFC 7516 section 5.2's rule about failure: a recipient whose CEK
// cannot be determined is one that failed (steps 12 and 13), not a document that
// cannot be read, and step 18 invalidates a JWE only when no recipient succeeded.
// Two of the three entries fail on every run here, because one key opens one
// entry. That was the whole of this example's coverage while RSA1_5 was
// unimplemented, when the first entry failed for every key alike.
//
// The second is section 7.2.1's own invariant -- "All recipients use the same
// JWE Protected Header, JWE Initialization Vector, JWE Ciphertext, and JWE
// Authentication Tag values" -- which shows up here as three entirely different
// key management algorithms, an RSA key encryption, an ECDH agreement and an
// AES-GCM key wrap, all arriving at the same CEK and so at the same plaintext.
// This module's own multi-recipient tests assert that too, but against messages
// it wrote itself; this one was written by somebody else.
//
// rfc-req: RFC7520-S5_13-R01
func TestSeveralRecipientsShareOnePlaintext(t *testing.T) {
	for algorithm, key := range severalRecipientsKeys {
		t.Run(algorithm, func(t *testing.T) {
			message := new(jwe.Message)
			if err := json.Unmarshal([]byte(severalRecipients), message); err != nil {
				t.Fatalf("cannot parse section 5.13: %v", err)
			}

			if len(message.Recipients) != 3 {
				t.Fatalf("got %d recipients, want 3", len(message.Recipients))
			}

			plaintext, err := message.Decrypt(recipientKey(t, jweVector{key: key}))
			if err != nil {
				t.Fatalf("cannot decrypt section 5.13: %v", err)
			}

			if string(plaintext) != jwePlaintext {
				t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, jwePlaintext)
			}
		})
	}
}

// TestEachRecipientOfSection5_13IsAccountedFor is the same reading at width
// three, against a document written by somebody else.
//
// rfc-req: RFC7520-S5_13-R01
//
// RFC 7516 §5.2 step 18 asks an implementation to report "for which of the
// recipients the decryption succeeded and failed". With three entries and one key
// the answer has real content: exactly one succeeds and two fail because they are
// addressed to somebody else — which is not an error but the answer.
//
// Running it under each of the three keys in turn is what shows the outcomes
// track the key rather than the message: the entry that succeeds moves.
//
// What the two failing entries may say is bounded by §11.5, and the bound is
// asserted here. A failure on the far side of a key collapses to
// jwa.ErrDecryptionFailed; naming the algorithm at that point would be a per
// recipient decryption oracle. Only an "alg" the document states in plain sight
// may be named, and §5.13 has none this module cannot serve.
func TestEachRecipientOfSection5_13IsAccountedFor(t *testing.T) {
	opener := map[string]int{"RSA1_5": 0, "ECDH-ES+A256KW": 1, "A256GCMKW": 2}

	for algorithm, key := range severalRecipientsKeys {
		t.Run(algorithm, func(t *testing.T) {
			message := new(jwe.Message)
			if err := json.Unmarshal([]byte(severalRecipients), message); err != nil {
				t.Fatalf("cannot parse section 5.13: %v", err)
			}

			plaintext, outcomes, err := message.DecryptAll(recipientKey(t, jweVector{key: key}))
			if err != nil {
				t.Fatalf("cannot decrypt section 5.13: %v", err)
			}

			if string(plaintext) != jwePlaintext {
				t.Errorf("plaintext mismatch:\n got %q\nwant %q", plaintext, jwePlaintext)
			}

			if len(outcomes) != 3 {
				t.Fatalf("got %d outcomes, want one per recipient", len(outcomes))
			}

			for i, outcome := range outcomes {
				if outcome.Succeeded != (i == opener[algorithm]) {
					t.Errorf("outcome %d reports Succeeded=%v", i, outcome.Succeeded)
				}
			}

			for i, outcome := range outcomes {
				if i == opener[algorithm] {
					continue
				}

				if !errors.Is(outcome.Err, jwa.ErrDecryptionFailed) {
					t.Errorf("outcome %d reports %v, want exactly ErrDecryptionFailed", i, outcome.Err)
				}
			}

			opened := outcomes[opener[algorithm]]
			if opened.Recipient == nil || opened.Recipient.Header == nil {
				t.Fatal("the outcome names no recipient")
			}

			if kid := opened.Recipient.Header.KeyID; !strings.Contains(key, `"kid":"`+kid+`"`) {
				t.Errorf("the entry that opened has kid %q, which is not the key's", kid)
			}
		})
	}
}
