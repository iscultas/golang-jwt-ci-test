# Requirement coverage: RFC7520

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 9 | 9 | 100% |

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7520-S3-R01` | MUST | interop | TestPublishedKeysParse (rfc7520/rfc7520_test.go) |
| `RFC7520-S4-R01` | MUST | interop | TestPublishedSignaturesVerify (rfc7520/rfc7520_test.go) |
| `RFC7520-S4-R02` | MUST | interop | TestDeterministicSignaturesAreReproduced (rfc7520/rfc7520_test.go) |
| `RFC7520-S4-R03` | MUST | interop | TestAllExamplesShareTheFigure8Payload (rfc7520/rfc7520_test.go) |
| `RFC7520-S5-R01` | MUST | interop | TestPublishedJWEsDecrypt (rfc7520/jwe_test.go) |
| `RFC7520-S5-R02` | MUST | interop | TestPublishedJWEJSONSerializationsDecrypt (rfc7520/jwe_test.go) |
| `RFC7520-S5-R03` | MUST | interop | TestPublishedJWEKeysParse (rfc7520/jwe_test.go) |
| `RFC7520-S5_11-R01` | MUST | interop | TestASharedUnprotectedAlgIsHonoured (rfc7520/multiple_recipients_test.go) |
| `RFC7520-S5_13-R01` | MUST | interop | TestSeveralRecipientsShareOnePlaintext (rfc7520/multiple_recipients_test.go), TestEachRecipientOfSection5_13IsAccountedFor (rfc7520/multiple_recipients_test.go) |
