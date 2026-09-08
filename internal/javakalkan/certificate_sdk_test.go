package javakalkan_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan"
)

func TestJavaCertificateProperties(t *testing.T) {
	requireJavaValidationProvider(t)
	client := openJavaIntegrationClient(t)
	t.Run("GOST SDK identity", func(t *testing.T) {
		encoded, err := os.ReadFile(fixturePath("examples", "test_CERT_GOST.txt"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(encoded)
		if block == nil {
			t.Fatal("missing fixture certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		info, err := client.X509CertificateGetInfo(t.Context(), cert)
		if err != nil {
			t.Fatalf("GOST certificate properties: %v", err)
		}
		if info.IIN != "123456789012" || info.BIN != "123456789021" || info.SubjectCountry != "KZ" ||
			info.SubjectOrganization != `АО "ТЕСТ"` || info.SubjectType != kalkan.CertificateSubjectLegalEntity {
			t.Fatalf("incorrect Kazakhstan identity: %#v", info)
		}
		if !slices.Equal(info.Policies, []string{"1.2.398.3.3.2.1"}) || len(info.Roles) != 0 {
			t.Fatalf("GOST policies = %#v, roles = %#v", info.Policies, info.Roles)
		}
		if !info.ValidFrom.Equal(cert.NotBefore) || !info.ValidUntil.Equal(cert.NotAfter) ||
			info.SignatureAlgorithm != "signatureAlgorithm=GOST 34.311-95 with GOST 34.310-2004(1.2.398.3.10.1.1.1.2)" {
			t.Fatalf("GOST dates or algorithm incorrect: %#v", info)
		}
		key, err := base64.StdEncoding.DecodeString(info.PublicKey)
		if err != nil || !bytes.Equal(key, cert.RawSubjectPublicKeyInfo) {
			t.Fatal("GOST public key metadata does not preserve SubjectPublicKeyInfo")
		}
	})
	t.Run("generated RSA metadata and selected fields", func(t *testing.T) {
		pki := newJavaValidationPKI(t, "http://delta.example")
		var deltaExtension pkix.Extension
		for _, extension := range pki.leaf.cert.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
				deltaExtension = pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: extension.Value}
			}
		}
		if deltaExtension.Value == nil {
			t.Fatal("generated certificate has no CRL distribution point")
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(0x123abc),
			Subject: pkix.Name{
				Country: []string{"KZ"}, CommonName: "Metadata, signer", Organization: []string{"Example organization"},
				SerialNumber: "IIN123456789011", OrganizationalUnit: []string{"BIN123456789022"},
			},
			NotBefore: pki.now.Add(-time.Hour), NotAfter: pki.now.Add(time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 398, 3, 3, 99}},
			SubjectKeyId:       []byte{1, 2, 3, 0xab}, OCSPServer: []string{"https://ocsp.example/status"},
			CRLDistributionPoints: []string{"https://crl.example/full.crl"},
			ExtraExtensions: []pkix.Extension{
				deltaExtension,
				{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: javaValidationASN1(t, []struct{ Policy asn1.ObjectIdentifier }{
					{asn1.ObjectIdentifier{1, 2, 398, 3, 3, 4, 1, 2}},
					{asn1.ObjectIdentifier{1, 2, 398, 3, 3, 4, 1, 2, 3}},
				})},
			},
		}
		identity := javaValidationIssue(t, template, pki.intermediate)
		// The API promises to read Raw DER, not caller-supplied parsed fields.
		input := &x509.Certificate{Raw: identity.cert.Raw, Subject: pkix.Name{CommonName: "spoofed metadata"}}
		info, err := client.X509CertificateGetInfo(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		if info.IIN != "123456789011" || info.BIN != "123456789022" || info.SubjectCountry != "KZ" ||
			info.SubjectOrganization != "Example organization" || info.SubjectSerialNumber != "IIN123456789011" ||
			info.SubjectOrganizationalUnit != "BIN123456789022" || info.SubjectType != kalkan.CertificateSubjectLegalEntity ||
			!slices.Equal(info.Roles, []kalkan.CertificateRole{kalkan.CertificateRoleFinancialSigner}) {
			t.Fatalf("RSA identity and policy mapping = %#v", info)
		}
		if !slices.Equal(info.Policies, []string{"1.2.398.3.3.4.1.2", "1.2.398.3.3.4.1.2.3"}) ||
			!slices.Equal(info.ExtKeyUsages, []string{"1.3.6.1.5.5.7.3.2", "1.2.398.3.3.99"}) ||
			!slices.Equal(info.KeyUsages, []string{"Digital Signature", "Non Repudiation"}) {
			t.Fatalf("RSA policies/usages = %#v / %#v / %#v", info.Policies, info.ExtKeyUsages, info.KeyUsages)
		}
		if !info.ValidFrom.Equal(template.NotBefore) || !info.ValidUntil.Equal(template.NotAfter) ||
			!strings.Contains(info.Subject, "Metadata") || strings.Contains(info.Subject, "spoofed") ||
			!strings.Contains(info.Issuer, "Java integration intermediate") ||
			!strings.HasSuffix(info.SerialNumber, "123ABC") || !strings.HasSuffix(info.SubjKeyID, "010203AB") ||
			info.AuthKeyID == "" || info.SignatureAlgorithm != "signatureAlgorithm=sha256WithRSAEncryption(1.2.840.113549.1.1.11)" {
			t.Fatalf("RSA certificate metadata = %#v", info)
		}
		if info.OCSPURL != "OCSP=https://ocsp.example/status" || info.CRLURL != "crlDistributionPoints=https://crl.example/full.crl" ||
			info.DeltaCRLURL != "freshestCRL=http://delta.example/intermediate.crl" {
			t.Fatalf("certificate URLs = %q / %q / %q", info.OCSPURL, info.CRLURL, info.DeltaCRLURL)
		}
		selected, err := client.X509CertificateGetInfoFields(t.Context(), input, kalkan.CertificateInfoValidUntil|kalkan.CertificateInfoSubjectSerialNumber)
		if err != nil {
			t.Fatal(err)
		}
		if !selected.ValidUntil.Equal(template.NotAfter) || selected.IIN != "123456789011" || selected.Subject != "" ||
			selected.BIN != "" || selected.Policy != "" || selected.PublicKey != "" || selected.OCSPURL != "" || !selected.ValidFrom.IsZero() {
			t.Fatalf("selected properties populated unrequested fields: %#v", selected)
		}
		if _, err := client.X509CertificateGetInfo(t.Context(), &x509.Certificate{Raw: []byte("not DER")}); !errors.Is(err, kalkan.ErrInvalidInput) {
			t.Fatalf("malformed DER error = %v", err)
		}
		if _, err := client.X509CertificateGetInfo(t.Context(), identity.cert); err != nil {
			t.Fatalf("metadata failure poisoned client: %v", err)
		}
	})
}

func TestJavaKeyStoreAndCertificateTimeChecks(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := openJavaIntegrationClient(t, javaIntegrationTrust(t, assets)...)
	ctx := context.Background()
	store := kalkan.KeyStore{Type: kalkan.PKCS12, Path: keyStorePath(t, assets), Password: "incorrect-public-test-password"}
	if err := client.LoadKeyStore(ctx, store); err == nil {
		t.Fatal("LoadKeyStore accepted incorrect password")
	}
	store.Password = fixturePassword
	if err := client.LoadKeyStore(ctx, store); err != nil {
		t.Fatalf("LoadKeyStore with correct password after failure: %v", err)
	}
	request := kalkan.SignCMSRequest{Data: kalkan.Bytes([]byte("certificate time policy")), IncludeCertificate: true}
	if _, err := client.SignCMS(ctx, request); err == nil {
		t.Fatal("SignCMS accepted expired historical fixture with default certificate time checks")
	}
	request.CertificateTimeCheck = kalkan.SkipCertificateTimeCheck
	signed, err := client.SignCMS(ctx, request)
	if err != nil {
		t.Fatalf("SignCMS with explicit historical certificate policy: %v", err)
	}
	verification := kalkan.VerifyCMSRequest{Signature: kalkan.DER(signed.Data), SignerID: 1}
	if _, err := client.VerifyCMS(ctx, verification); err == nil {
		t.Fatal("VerifyCMS accepted expired historical fixture with default certificate time checks")
	}
	verification.CertificateTimeCheck = kalkan.SkipCertificateTimeCheck
	javaIntegrationVerify(t, client, verification, []byte("certificate time policy"))
}

func TestJavaChainFailureIdentifiesCertificatePurpose(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	unrelated := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t,
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Type: kalkan.CertificateCA, Data: unrelated.root.cert.Raw, Format: kalkan.CertificateDER,
		}),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Type: kalkan.CertificateIntermediate, Data: pki.intermediate.cert.Raw, Format: kalkan.CertificateDER,
		}))

	cases := []struct {
		name string
		want string
		call func() error
	}{
		{
			name: "standalone",
			want: "Certificate does not chain to a loaded trusted CA",
			call: func() error {
				_, err := client.ValidateCertificate(t.Context(), kalkan.ValidateCertificateRequest{
					Certificate: kalkan.DER(pki.leaf.cert.Raw), Mode: kalkan.CertificateValidationNone,
				})
				return err
			},
		},
		{
			name: "CMS",
			want: "CMS signer certificate does not chain to a loaded trusted CA",
			call: func() error {
				_, err := client.VerifyCMS(t.Context(), kalkan.VerifyCMSRequest{
					Signature: kalkan.DER(pki.cms(t, []byte("untrusted signer"), "none")), SignerID: 1,
				})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			var providerError *kalkan.JavaError
			if !errors.As(err, &providerError) || providerError.Message != tc.want {
				t.Fatalf("chain failure = %v; want %q", err, tc.want)
			}
		})
	}
	if err := client.LoadTrustedCertificate(t.Context(), kalkan.TrustedCertificate{
		Type: kalkan.CertificateCA, Data: pki.root.cert.Raw, Format: kalkan.CertificateDER,
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name+" with trusted root", func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatalf("validation with the correct root: %v", err)
			}
		})
	}
}
