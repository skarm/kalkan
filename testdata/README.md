# Historical test fixtures

This directory contains historical assets used by the repository's KalkanCrypt
integration tests, including CMS, XML, ZIP, certificates, and test key stores.
Native tests require an installed SDK; see the checks in the root README.

`p12/` contains 24 PKCS#12 containers named `GOST512_*.p12`. Their public test
password is `Qwerty12`, also used by the existing test helpers. These fixtures
represent test identities and are retained for regression coverage; they are
not production credentials.

An audit of the certificate bags in all 24 containers on 2026-09-05 confirmed:

- Issuer: `ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST) TEST 2022`, country `KZ`.
- Every certificate subject contains `TEST` or `ТЕСТ`.
- Certificate expiration dates (`notAfter`, UTC) range from 2024-11-08 to
  2025-10-30. These certificates are historical and have expired.

The metadata above identifies the test issuer. Follow the
[fixture rules](../.github/CONTRIBUTING.md#test-fixtures) and
[secret-handling rules](../.github/CONTRIBUTING.md#secrets-and-sdk-binaries)
when adding or replacing these public test assets.
