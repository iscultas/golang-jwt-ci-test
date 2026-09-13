# Requirement coverage: RFC9278

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 6 | 6 | 100% |

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC9278-S3-R01` | MUST | unit | TestThumbprintURIHasTheRegisteredPrefix (rfc9278/rfc9278_test.go) |
| `RFC9278-S3-R02` | MUST | unit | TestThumbprintURIStructure (rfc9278/rfc9278_test.go), TestURIsNotShapedLikeTheRFCsAreRefused (rfc9278/rfc9278_test.go) |
| `RFC9278-S4-R01` | MUST | unit | TestHashIdentifiersComeFromTheRegistry (rfc9278/rfc9278_test.go) |
| `RFC9278-S4-R02` | MUST | unit | TestURIsNamingUnregisteredHashesAreDetected (rfc9278/rfc9278_test.go) |
| `RFC9278-S5-R01` | MUST | unit | TestSHA256IsMandatoryToImplement (rfc9278/rfc9278_test.go) |
| `RFC9278-S6-R01` | MUST | unit | TestWorkedExampleURIMatchesTheRFC (rfc9278/rfc9278_test.go), TestWorkedExampleURIParsesToTheRFCThumbprint (rfc9278/rfc9278_test.go) |
