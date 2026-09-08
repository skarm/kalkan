# Native XML and WS-Security fixtures

These signatures were generated with Linux KalkanCrypt SDK 2.0.13 using the
public SDK test key already committed at
`../p12/GOST512_02c7a21f2df78b99cb67323e2e255779bb6ae309.p12`, password `Qwerty12`.
The signer certificate and its issuers are test certificates. No production keys
or credentials are used. The fixtures contain certificates and signatures, not
private keys.

`native-xml.xml` signs the complete document
`<root><value>native XML interoperability</value></root>` with `SignXML`, inclusive
canonicalization and `SkipCertificateTimeCheck`.

`native-wsse.xml` signs a SOAP 1.1 Body with `wsu:Id="body"` and payload
`<value>native WSSE interoperability</value>`, using `SignWSSE`, exclusive
canonicalization and `SkipCertificateTimeCheck`. The native SDK creates the
security header and embeds the X509v3 certificate in a `wsse:KeyIdentifier`.

Both use GOST 34.10/34.11-2015, 512 bit. No TSA is used. Verification explicitly
trusts `../certs/root_test_gost_2022.cer` and
`../certs/nca_gost2022_test.cer`, skips the expired historical certificate dates,
and disables online revocation for these historical fixtures. Separate generated
RSA fixtures exercise current certificate validity and authenticated CRL/OCSP
responses.

`TestJavaXMLNativeFixtures` verifies the signatures through the Java backend and
rejects a changed payload. Linux SDK 2.0.13 also verified Java-generated XML and
WS-Security signatures during the interoperability probe and rejected changed
payloads.
