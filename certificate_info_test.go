package kalkan

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestX509ExportCertificateFromStoreParsesDERCertificate(t *testing.T) {
	der := testCertificateDER(t, "store-cert")
	native := &fakeNative{
		exportCertStoreFunc: func(alias string, format ckalkan.CertFormat) ([]byte, error) {
			if alias != "" {
				t.Fatalf("alias = %q, want default empty alias", alias)
			}
			if format != ckalkan.CertDER {
				t.Fatalf("format = %#x, want CertDER", format)
			}

			return der, nil
		},
	}
	client := &Client{library: native}

	cert, err := client.X509ExportCertificateFromStore(context.Background())
	if err != nil {
		t.Fatalf("X509ExportCertificateFromStore returned error: %v", err)
	}
	if cert.Subject.CommonName != "store-cert" {
		t.Fatalf("certificate CN = %q, want store-cert", cert.Subject.CommonName)
	}
}

func TestParseNativeCertificateFormats(t *testing.T) {
	der := testCertificateDER(t, "native-format")
	pemCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "DER", data: der},
		{name: "NUL-padded DER", data: append(append([]byte(nil), der...), 0, 0, 0)},
		{name: "PEM", data: pemCertificate},
		{name: "NUL-terminated PEM", data: append(append([]byte(nil), pemCertificate...), 0, 'x')},
		{name: "base64 DER", data: []byte(base64.StdEncoding.EncodeToString(der))},
		{name: "empty", data: []byte(" \t\r\n\x00"), wantErr: "certificate output is empty"},
		{name: "empty C string with trailing buffer data", data: []byte{0, 'x'}, wantErr: "certificate output is empty"},
		{
			name:    "PEM trailing data",
			data:    append(append([]byte(nil), pemCertificate...), []byte("trailing")...),
			wantErr: "trailing data",
		},
		{
			name:    "multiple PEM blocks",
			data:    append(append([]byte(nil), pemCertificate...), pemCertificate...),
			wantErr: "trailing data",
		},
		{
			name:    "wrong PEM block type",
			data:    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
			wantErr: "must be CERTIFICATE",
		},
		{
			name:    "invalid DER in PEM",
			data:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
			wantErr: "invalid DER",
		},
		{
			name:    "leading data before PEM",
			data:    append([]byte("leading\n"), pemCertificate...),
			wantErr: "not DER, PEM, or base64 DER",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := parseNativeCertificate(test.data)
			if test.wantErr != "" {
				if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseNativeCertificate error = %v, want ErrInvalidInput containing %q", err, test.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseNativeCertificate returned error: %v", err)
			}
			if cert.Subject.CommonName != "native-format" {
				t.Fatalf("certificate CN = %q, want native-format", cert.Subject.CommonName)
			}
		})
	}
}

func TestCollectSignerCertificatesBoundaries(t *testing.T) {
	der := testCertificateDER(t, "repeated-signer")

	tests := []struct {
		name             string
		certificateCount int
		emptyTerminator  bool
		wantCount        int
		wantCalls        int
		wantErr          string
	}{
		{
			name:            "empty first result",
			emptyTerminator: true,
			wantCalls:       1,
			wantErr:         "signer certificate output is empty",
		},
		{
			name:             "empty terminates non-empty result",
			certificateCount: 1,
			emptyTerminator:  true,
			wantCount:        1,
			wantCalls:        2,
		},
		{
			name:             "exact limit",
			certificateCount: maxExtractedSignerCertificates,
			wantCount:        maxExtractedSignerCertificates,
			wantCalls:        maxExtractedSignerCertificates + 1,
		},
		{
			name:             "over limit",
			certificateCount: maxExtractedSignerCertificates + 1,
			wantCalls:        maxExtractedSignerCertificates + 1,
			wantErr:          "signer certificate count exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			certs, err := collectSignerCertificates(context.Background(), func(signID int) ([]byte, error) {
				calls++
				if signID < test.certificateCount {
					return der, nil
				}
				if test.emptyTerminator {
					return nil, nil
				}

				return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
			})

			if test.wantErr != "" {
				if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("collectSignerCertificates error = %v, want ErrInvalidInput containing %q", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatalf("collectSignerCertificates returned error: %v", err)
			}
			if len(certs) != test.wantCount {
				t.Fatalf("certificate count = %d, want %d", len(certs), test.wantCount)
			}
			if calls != test.wantCalls {
				t.Fatalf("fetch calls = %d, want %d", calls, test.wantCalls)
			}
		})
	}
}

func TestX509CertificateGetInfoBuildsStructuredInfo(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	wantFrom := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)
	wantUntil := time.Date(2025, 1, 3, 16, 5, 6, 0, time.UTC)

	native := &fakeNative{
		certificateGetInfoFunc: func(input []byte, prop ckalkan.CertProp) ([]byte, error) {
			block, _ := pem.Decode(input)
			if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, der) {
				t.Fatalf("certificate info input is not PEM for the supplied certificate")
			}

			value, ok := validCertificateInfoProps()[prop]
			if !ok {
				return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
			}

			return []byte(value), nil
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfo(context.Background(), cert)
	if err != nil {
		t.Fatalf("X509CertificateGetInfo returned error: %v", err)
	}

	if info.Subject != "CN = Native Subject" {
		t.Fatalf("Subject = %q", info.Subject)
	}
	if info.SerialNumber != "certificateSerialNumber=010203" {
		t.Fatalf("SerialNumber = %q", info.SerialNumber)
	}
	if !info.ValidFrom.Equal(wantFrom) {
		t.Fatalf("ValidFrom = %s, want %s", info.ValidFrom, wantFrom)
	}
	if !info.ValidUntil.Equal(wantUntil) {
		t.Fatalf("ValidUntil = %s, want %s", info.ValidUntil, wantUntil)
	}
	if info.Issuer != "CN = Native Issuer" {
		t.Fatalf("Issuer = %q", info.Issuer)
	}
	if info.AlgorithmSignCert != "GOST R 34.10-2015" {
		t.Fatalf("AlgorithmSignCert = %q", info.AlgorithmSignCert)
	}
	if info.OCSPURL != "OCSP=http://ocsp.example.test" {
		t.Fatalf("OCSPURL = %q", info.OCSPURL)
	}
	if !reflect.DeepEqual(info.Policies, []string{"1.2.398.3.3.4", "1.2.398.3.3.5"}) {
		t.Fatalf("Policies = %#v", info.Policies)
	}
	if !reflect.DeepEqual(info.KeyUsages, []string{"digitalSignature", "nonRepudiation"}) {
		t.Fatalf("KeyUsages = %#v", info.KeyUsages)
	}
	if !reflect.DeepEqual(info.ExtKeyUsages, []string{"clientAuth", "emailProtection"}) {
		t.Fatalf("ExtKeyUsages = %#v", info.ExtKeyUsages)
	}
	if info.SubjectSerialNumber != "IIN990106300596" {
		t.Fatalf("SubjectSerialNumber = %q", info.SubjectSerialNumber)
	}
	if info.IIN != "990106300596" {
		t.Fatalf("IIN = %q", info.IIN)
	}
	if info.SubjectOrganization != `LLP "Test"` {
		t.Fatalf("SubjectOrganization = %q", info.SubjectOrganization)
	}
	if info.SubjectOrganizationalUnit != "BIN230540004989" {
		t.Fatalf("SubjectOrganizationalUnit = %q", info.SubjectOrganizationalUnit)
	}
	if info.BIN != "230540004989" {
		t.Fatalf("BIN = %q", info.BIN)
	}
	if info.SubjectType != CertificateSubjectLegalEntity {
		t.Fatalf("SubjectType = %q, want legal entity fallback from BIN", info.SubjectType)
	}
}

func TestX509CertificateGetInfoFieldsReadsCStringPrefix(t *testing.T) {
	der := testCertificateDER(t, "embedded-nul")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	native := &fakeNative{
		certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
			if prop != ckalkan.CertPropSubjectDN {
				t.Errorf("unexpected certificate property %#x", prop)
			}

			return []byte("CN = Native\x00ignored"), nil
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfoFields(context.Background(), cert, CertificateInfoSubject)
	if err != nil {
		t.Fatalf("X509CertificateGetInfoFields returned error: %v", err)
	}
	if info.Subject != "CN = Native" {
		t.Fatalf("Subject = %q, want C-string prefix", info.Subject)
	}
}

func TestX509CertificateGetInfoFieldsSelectsProperties(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	var gotProps []ckalkan.CertProp
	native := &fakeNative{
		certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
			gotProps = append(gotProps, prop)
			switch prop {
			case ckalkan.CertPropSubjectDN:
				return []byte("CN = Native Subject"), nil
			case ckalkan.CertPropCertSN:
				return []byte("certificateSerialNumber=010203"), nil
			default:
				t.Errorf("unexpected certificate property %#x", prop)
				return nil, nil
			}
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfoFields(context.Background(), cert, CertificateInfoSubject|CertificateInfoSerialNumber)
	if err != nil {
		t.Fatalf("X509CertificateGetInfoFields returned error: %v", err)
	}

	if !reflect.DeepEqual(gotProps, []ckalkan.CertProp{ckalkan.CertPropSubjectDN, ckalkan.CertPropCertSN}) {
		t.Fatalf("certificate properties = %#v, want subject and serial only", gotProps)
	}
	if info.Subject != "CN = Native Subject" {
		t.Fatalf("Subject = %q", info.Subject)
	}
	if info.SerialNumber != "certificateSerialNumber=010203" {
		t.Fatalf("SerialNumber = %q", info.SerialNumber)
	}
	if !info.ValidFrom.IsZero() || info.Issuer != "" || len(info.Policies) != 0 || info.IIN != "" || info.BIN != "" {
		t.Fatalf("unrequested fields were populated: %+v", info)
	}
}

func TestX509CertificateGetInfoFieldsKazakhstanSubject(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	var gotProps []ckalkan.CertProp
	native := &fakeNative{
		certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
			gotProps = append(gotProps, prop)
			switch prop {
			case ckalkan.CertPropSubjectSerialNumber:
				return []byte("serialNumber=IIN990106300596"), nil
			case ckalkan.CertPropSubjectOrgName:
				return []byte(`O=LLP "Test"`), nil
			case ckalkan.CertPropSubjectOrgUnitName:
				return []byte("OU=BIN230540004989"), nil
			case ckalkan.CertPropPoliciesID:
				return []byte("certificatePolicies=1.2.398.3.3.4.1.2, 1.2.398.3.3.4.1.2.2, 1.2.398.3.3.4.3.2.1"), nil
			default:
				t.Errorf("unexpected certificate property %#x", prop)
				return nil, nil
			}
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfoFields(
		context.Background(),
		cert,
		CertificateInfoSubjectSerialNumber|
			CertificateInfoSubjectOrganization|
			CertificateInfoSubjectOrganizationalUnit|
			CertificateInfoPolicy,
	)
	if err != nil {
		t.Fatalf("X509CertificateGetInfoFields returned error: %v", err)
	}

	wantProps := []ckalkan.CertProp{
		ckalkan.CertPropPoliciesID,
		ckalkan.CertPropSubjectSerialNumber,
		ckalkan.CertPropSubjectOrgName,
		ckalkan.CertPropSubjectOrgUnitName,
	}
	if !reflect.DeepEqual(gotProps, wantProps) {
		t.Fatalf("certificate properties = %#v, want Kazakhstan subject properties", gotProps)
	}
	if info.SubjectSerialNumber != "IIN990106300596" {
		t.Fatalf("SubjectSerialNumber = %q", info.SubjectSerialNumber)
	}
	if info.IIN != "990106300596" {
		t.Fatalf("IIN = %q", info.IIN)
	}
	if info.SubjectOrganization != `LLP "Test"` {
		t.Fatalf("SubjectOrganization = %q", info.SubjectOrganization)
	}
	if info.SubjectOrganizationalUnit != "BIN230540004989" {
		t.Fatalf("SubjectOrganizationalUnit = %q", info.SubjectOrganizationalUnit)
	}
	if info.BIN != "230540004989" {
		t.Fatalf("BIN = %q", info.BIN)
	}
	if info.SubjectType != CertificateSubjectLegalEntity {
		t.Fatalf("SubjectType = %q, want legal entity policy OID", info.SubjectType)
	}
	if !reflect.DeepEqual(info.Roles, []CertificateRole{CertificateRoleSigner}) {
		t.Fatalf("Roles = %#v", info.Roles)
	}
}

func TestX509CertificateGetInfoFieldsFixtures(t *testing.T) {
	tests := []struct {
		name                    string
		path                    string
		nativeSubjectSerial     string
		nativeSubjectOrg        string
		nativeSubjectOrgUnit    string
		nativePolicy            string
		wantSubjectSerial       string
		wantSubjectOrganization string
		wantSubjectOrgUnit      string
		wantIIN                 string
		wantBIN                 string
		wantSubjectType         CertificateSubjectType
	}{
		{
			name:                    "end_entity",
			path:                    "testdata/examples/test_CERT_GOST.txt",
			nativeSubjectSerial:     "serialNumber=IIN123456789012",
			nativeSubjectOrg:        `O=АО "ТЕСТ"`,
			nativeSubjectOrgUnit:    "OU=BIN123456789021",
			nativePolicy:            "certificatePolicies=1.2.398.3.3.2.1",
			wantSubjectSerial:       "IIN123456789012",
			wantSubjectOrganization: `АО "ТЕСТ"`,
			wantSubjectOrgUnit:      "BIN123456789021",
			wantIIN:                 "123456789012",
			wantBIN:                 "123456789021",
			wantSubjectType:         CertificateSubjectLegalEntity,
		},
		{
			name:            "intermediate_ca",
			path:            "testdata/certs/nca_gost2022_test.cer",
			nativePolicy:    "certificatePolicies=1.2.398.3.3.2",
			wantSubjectType: CertificateSubjectUnknown,
		},
		{
			name:            "root_ca",
			path:            "testdata/certs/root_test_gost_2022.cer",
			nativePolicy:    "certificatePolicies=1.2.398.3.1.2",
			wantSubjectType: CertificateSubjectUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certData, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("read certificate fixture: %v", err)
			}
			cert, err := parseNativeCertificate(certData)
			if err != nil {
				t.Fatalf("parse certificate fixture: %v", err)
			}

			native := &fakeNative{
				certificateGetInfoFunc: func(input []byte, prop ckalkan.CertProp) ([]byte, error) {
					block, _ := pem.Decode(input)
					if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, cert.Raw) {
						t.Fatalf("certificate info input is not PEM for the certificate fixture")
					}

					switch prop {
					case ckalkan.CertPropSubjectCountryName:
						return []byte("C=KZ"), nil
					case ckalkan.CertPropSubjectSerialNumber:
						if tt.nativeSubjectSerial == "" {
							return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
						}

						return []byte(tt.nativeSubjectSerial), nil
					case ckalkan.CertPropSubjectOrgName:
						if tt.nativeSubjectOrg == "" {
							return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
						}

						return []byte(tt.nativeSubjectOrg), nil
					case ckalkan.CertPropSubjectOrgUnitName:
						if tt.nativeSubjectOrgUnit == "" {
							return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
						}

						return []byte(tt.nativeSubjectOrgUnit), nil
					case ckalkan.CertPropPoliciesID:
						return []byte(tt.nativePolicy), nil
					default:
						t.Errorf("unexpected certificate property %#x", prop)
						return nil, nil
					}
				},
			}
			client := &Client{library: native}

			info, err := client.X509CertificateGetInfoFields(
				context.Background(),
				cert,
				CertificateInfoSubjectCountry|
					CertificateInfoSubjectSerialNumber|
					CertificateInfoSubjectOrganization|
					CertificateInfoSubjectOrganizationalUnit|
					CertificateInfoPolicy,
			)
			if err != nil {
				t.Fatalf("X509CertificateGetInfoFields returned error: %v", err)
			}

			if info.SubjectCountry != "KZ" {
				t.Fatalf("SubjectCountry = %q", info.SubjectCountry)
			}
			if info.SubjectSerialNumber != tt.wantSubjectSerial {
				t.Fatalf("SubjectSerialNumber = %q, want %q", info.SubjectSerialNumber, tt.wantSubjectSerial)
			}
			if info.SubjectOrganization != tt.wantSubjectOrganization {
				t.Fatalf("SubjectOrganization = %q, want %q", info.SubjectOrganization, tt.wantSubjectOrganization)
			}
			if info.SubjectOrganizationalUnit != tt.wantSubjectOrgUnit {
				t.Fatalf("SubjectOrganizationalUnit = %q, want %q", info.SubjectOrganizationalUnit, tt.wantSubjectOrgUnit)
			}
			if info.IIN != tt.wantIIN {
				t.Fatalf("IIN = %q, want %q", info.IIN, tt.wantIIN)
			}
			if info.BIN != tt.wantBIN {
				t.Fatalf("BIN = %q, want %q", info.BIN, tt.wantBIN)
			}
			if info.SubjectType != tt.wantSubjectType {
				t.Fatalf("SubjectType = %q, want %q", info.SubjectType, tt.wantSubjectType)
			}
			if len(info.Roles) != 0 {
				t.Fatalf("Roles = %#v, want none for fixture policy %q", info.Roles, info.Policy)
			}
		})
	}
}

func TestCertificateInfoKazakhstanSubject(t *testing.T) {
	tests := []struct {
		name     string
		info     CertificateInfo
		wantIIN  string
		wantBIN  string
		wantType CertificateSubjectType
		wantRole []CertificateRole
	}{
		{
			name: "person_policy",
			info: CertificateInfo{
				SubjectSerialNumber: "serialNumber=IIN123456789011",
				Policies:            []string{string(CertificateSubjectPerson)},
			},
			wantIIN:  "123456789011",
			wantType: CertificateSubjectPerson,
		},
		{
			name: "legal_signer_policy",
			info: CertificateInfo{
				SubjectSerialNumber:       "serialNumber=IIN990106300596",
				SubjectOrganizationalUnit: "OU=BIN230540004989",
				Policies: []string{
					string(CertificateSubjectLegalEntity),
					string(CertificateRoleSigner),
				},
			},
			wantIIN:  "990106300596",
			wantBIN:  "230540004989",
			wantType: CertificateSubjectLegalEntity,
			wantRole: []CertificateRole{CertificateRoleSigner},
		},
		{
			name: "legal_from_bin",
			info: CertificateInfo{
				SubjectOrganizationalUnit: "OU=BIN123456789021",
			},
			wantBIN:  "123456789021",
			wantType: CertificateSubjectLegalEntity,
		},
		{
			name: "person_from_iin",
			info: CertificateInfo{
				SubjectSerialNumber: "serialNumber=IIN123456789011",
			},
			wantIIN:  "123456789011",
			wantType: CertificateSubjectPerson,
		},
		{
			name: "roles_dedup",
			info: CertificateInfo{
				SubjectOrganizationalUnit: "OU=Sales, OU=BIN123456789021",
				Policies: []string{
					string(CertificateRoleFirstHead),
					string(CertificateRoleSigner),
					string(CertificateRoleSigner),
					string(CertificateRoleFinancialSigner),
					string(CertificateRoleHR),
					string(CertificateRoleEmployee),
					string(CertificateRoleLegalEntitySystem),
					string(CertificateRoleLegalEntitySystem) + ".71",
				},
			},
			wantBIN:  "123456789021",
			wantType: CertificateSubjectLegalEntity,
			wantRole: []CertificateRole{
				CertificateRoleFirstHead,
				CertificateRoleSigner,
				CertificateRoleFinancialSigner,
				CertificateRoleHR,
				CertificateRoleEmployee,
				CertificateRoleLegalEntitySystem,
			},
		},
		{
			name: "person_system_role",
			info: CertificateInfo{
				SubjectSerialNumber: "serialNumber=IIN123456789011",
				Policies:            []string{string(CertificateRolePersonSystem)},
			},
			wantIIN:  "123456789011",
			wantType: CertificateSubjectPerson,
			wantRole: []CertificateRole{CertificateRolePersonSystem},
		},
		{
			name: "unknown",
			info: CertificateInfo{
				SubjectSerialNumber:       "serialNumber=SN123456",
				SubjectOrganizationalUnit: "OU=Sales",
				Policies:                  []string{"1.2.398.3.3.4.3.2.1"},
			},
			wantType: CertificateSubjectUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.info

			info.applyKazakhstanSubjectDetails()

			if info.IIN != tt.wantIIN {
				t.Fatalf("IIN = %q, want %q", info.IIN, tt.wantIIN)
			}
			if info.BIN != tt.wantBIN {
				t.Fatalf("BIN = %q, want %q", info.BIN, tt.wantBIN)
			}
			if info.SubjectType != tt.wantType {
				t.Fatalf("SubjectType = %q, want %q", info.SubjectType, tt.wantType)
			}
			if !reflect.DeepEqual(info.Roles, tt.wantRole) {
				t.Fatalf("Roles = %#v, want %#v", info.Roles, tt.wantRole)
			}
		})
	}
}

func TestX509CertificateGetInfoFieldsOptionalSubjectProps(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	native := &fakeNative{
		certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
			switch prop {
			case ckalkan.CertPropPoliciesID:
				return []byte("certificatePolicies=1.2.398.3.3.4.1.1"), nil
			case ckalkan.CertPropSubjectCountryName,
				ckalkan.CertPropSubjectSerialNumber,
				ckalkan.CertPropSubjectOrgName,
				ckalkan.CertPropSubjectOrgUnitName:
				return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
			default:
				t.Errorf("unexpected certificate property %#x", prop)
				return nil, nil
			}
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfoFields(
		context.Background(),
		cert,
		CertificateInfoPolicy|
			CertificateInfoSubjectCountry|
			CertificateInfoSubjectSerialNumber|
			CertificateInfoSubjectOrganization|
			CertificateInfoSubjectOrganizationalUnit,
	)
	if err != nil {
		t.Fatalf("X509CertificateGetInfoFields returned error: %v", err)
	}

	if info.SubjectType != CertificateSubjectPerson {
		t.Fatalf("SubjectType = %q, want person from policy despite optional subject errors", info.SubjectType)
	}
	if info.IIN != "" || info.BIN != "" || info.SubjectCountry != "" || info.SubjectOrganization != "" {
		t.Fatalf("optional subject fields were populated after native errors: %+v", info)
	}
}

func TestX509CertificateGetInfoReturnsRequiredErrors(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	tests := []struct {
		name string
		prop ckalkan.CertProp
	}{
		{name: "subject", prop: ckalkan.CertPropSubjectDN},
		{name: "serial_number", prop: ckalkan.CertPropCertSN},
		{name: "valid_from", prop: ckalkan.CertPropNotBefore},
		{name: "valid_until", prop: ckalkan.CertPropNotAfter},
		{name: "issuer", prop: ckalkan.CertPropIssuerDN},
		{name: "policy", prop: ckalkan.CertPropPoliciesID},
		{name: "key_usage", prop: ckalkan.CertPropKeyUsage},
		{name: "extended_key_usage", prop: ckalkan.CertPropExtKeyUsage},
		{name: "authority_key_id", prop: ckalkan.CertPropAuthKeyID},
		{name: "subject_key_id", prop: ckalkan.CertPropSubjKeyID},
		{name: "signature_algorithm", prop: ckalkan.CertPropSignatureAlg},
		{name: "public_key", prop: ckalkan.CertPropPubKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := validCertificateInfoProps()
			native := &fakeNative{
				certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
					if prop == tt.prop {
						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
					}

					value, ok := props[prop]
					if !ok {
						t.Fatalf("unexpected certificate property %#x", prop)
					}

					return []byte(value), nil
				},
			}
			client := &Client{library: native}

			_, err = client.X509CertificateGetInfo(context.Background(), cert)
			requireKalkanErrorCode(t, err, ckalkan.ErrorGetCertProp)
		})
	}
}

func TestX509CertificateGetInfoIgnoresOptionalErrors(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	tests := []struct {
		name  string
		prop  ckalkan.CertProp
		field func(*CertificateInfo) string
	}{
		{name: "ocsp", prop: ckalkan.CertPropOCSP, field: func(info *CertificateInfo) string {
			return info.OCSPURL
		}},
		{name: "crl", prop: ckalkan.CertPropGetCRL, field: func(info *CertificateInfo) string {
			return info.CRLURL
		}},
		{name: "delta_crl", prop: ckalkan.CertPropGetDeltaCRL, field: func(info *CertificateInfo) string {
			return info.DeltaCRLURL
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := validCertificateInfoProps()
			native := &fakeNative{
				certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
					if prop == tt.prop {
						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
					}

					value, ok := props[prop]
					if !ok {
						t.Fatalf("unexpected certificate property %#x", prop)
					}

					return []byte(value), nil
				},
			}
			client := &Client{library: native}

			info, err := client.X509CertificateGetInfo(context.Background(), cert)
			if err != nil {
				t.Fatalf("X509CertificateGetInfo returned error: %v", err)
			}
			if got := tt.field(info); got != "" {
				t.Fatalf("optional field = %q, want empty", got)
			}
			if info.Subject != "CN = Native Subject" {
				t.Fatalf("Subject = %q", info.Subject)
			}
		})
	}
}

func TestGetCertFromCMSExtractsAllSignerCertificates(t *testing.T) {
	firstDER := testCertificateDER(t, "cms-signer-0")
	secondDER := testCertificateDER(t, "cms-signer-1")
	var signIDs []int

	native := &fakeNative{
		getCertFromCMSFunc: func(cms []byte, signID int, flags ckalkan.Flag) ([]byte, error) {
			if string(cms) != "cms-base64" {
				t.Fatalf("CMS input = %q, want cms-base64", cms)
			}
			wantFlags := ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.OutBase64
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}

			signIDs = append(signIDs, signID)
			switch signID {
			case 0:
				return []byte(base64.StdEncoding.EncodeToString(firstDER)), nil
			case 1:
				return secondDER, nil
			default:
				return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
			}
		},
	}
	client := &Client{library: native}

	certs, err := client.GetCertFromCMS(context.Background(), Base64([]byte("cms-base64")))
	if err != nil {
		t.Fatalf("GetCertFromCMS returned error: %v", err)
	}
	if !reflect.DeepEqual(signIDs, []int{0, 1, 2}) {
		t.Fatalf("signIDs = %#v", signIDs)
	}
	if len(certs) != 2 {
		t.Fatalf("cert count = %d, want 2", len(certs))
	}
	if certs[0].Subject.CommonName != "cms-signer-0" || certs[1].Subject.CommonName != "cms-signer-1" {
		t.Fatalf("cert CNs = %q/%q", certs[0].Subject.CommonName, certs[1].Subject.CommonName)
	}
}

func TestGetCertFromXMLExtractsAllSignerCertificates(t *testing.T) {
	der := testCertificateDER(t, "xml-signer")
	var signIDs []int

	native := &fakeNative{
		getCertFromXMLFunc: func(xml []byte, signID int) ([]byte, error) {
			if string(xml) != "<root/>" {
				t.Fatalf("XML input = %q, want <root/>", xml)
			}

			signIDs = append(signIDs, signID)
			if signID == 0 {
				return []byte(base64.StdEncoding.EncodeToString(der)), nil
			}

			return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
		},
	}
	client := &Client{library: native}

	certs, err := client.GetCertFromXML(context.Background(), Bytes([]byte("<root/>")))
	if err != nil {
		t.Fatalf("GetCertFromXML returned error: %v", err)
	}
	if !reflect.DeepEqual(signIDs, []int{0, 1}) {
		t.Fatalf("signIDs = %#v", signIDs)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "xml-signer" {
		t.Fatalf("certs = %#v", certs)
	}
}

func TestGetCertFromSignedDataReturnsFirstCertNotFoundError(t *testing.T) {
	tests := []struct {
		name    string
		library func(*testing.T) *fakeNative
		call    func(*Client) error
	}{
		{
			name: "CMS",
			library: func(t *testing.T) *fakeNative {
				t.Helper()

				return &fakeNative{
					getCertFromCMSFunc: func(_ []byte, signID int, _ ckalkan.Flag) ([]byte, error) {
						if signID != 0 {
							t.Fatalf("signID = %d, want 0", signID)
						}

						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
					},
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromCMS(context.Background(), Base64([]byte("cms-base64")))
				return err
			},
		},
		{
			name: "XML",
			library: func(t *testing.T) *fakeNative {
				t.Helper()

				return &fakeNative{
					getCertFromXMLFunc: func(_ []byte, signID int) ([]byte, error) {
						if signID != 0 {
							t.Fatalf("signID = %d, want 0", signID)
						}

						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
					},
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromXML(context.Background(), Bytes([]byte("<root/>")))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{library: tt.library(t)}

			err := tt.call(client)
			requireKalkanErrorCode(t, err, ckalkan.ErrorCertNotFound)
		})
	}
}

func TestGetSigAlgFromXMLUsesXMLInput(t *testing.T) {
	native := &fakeNative{
		getSigAlgFromXMLFunc: func(xml []byte) (string, error) {
			if string(xml) != "<signed/>" {
				t.Fatalf("XML input = %q, want <signed/>", xml)
			}

			return "urn:test:signature-algorithm", nil
		},
	}
	client := &Client{library: native}

	algorithm, err := client.GetSigAlgFromXML(context.Background(), Bytes([]byte("<signed/>")))
	if err != nil {
		t.Fatalf("GetSigAlgFromXML returned error: %v", err)
	}
	if algorithm != "urn:test:signature-algorithm" {
		t.Fatalf("algorithm = %q", algorithm)
	}
}

func TestGetTimeFromSigUsesSignatureEncoding(t *testing.T) {
	want := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	native := &fakeNative{
		getTimeFromSigFunc: func(data []byte, flags ckalkan.Flag, sigID int) (time.Time, error) {
			if string(data) != "raw-cms" {
				t.Fatalf("signature input = %q, want raw-cms", data)
			}
			if flags != ckalkan.InDER {
				t.Fatalf("flags = %#x, want InDER", flags)
			}
			if sigID != 0 {
				t.Fatalf("sigID = %d, want 0", sigID)
			}

			return want, nil
		},
	}
	client := &Client{library: native}

	got, err := client.GetTimeFromSig(context.Background(), Bytes([]byte("raw-cms")))
	if err != nil {
		t.Fatalf("GetTimeFromSig returned error: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("time = %s, want %s", got, want)
	}
}

func testCertificateDER(t *testing.T, commonName string) []byte {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123456789),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}

	return der
}

func requireKalkanErrorCode(t *testing.T, err error, want ckalkan.ErrorCode) {
	t.Helper()

	got, ok := ckalkan.ErrorCodeOf(err)
	if err == nil || !ok || got != want {
		t.Fatalf("error = %v, want Kalkan code %v", err, want)
	}
}

func validCertificateInfoProps() map[ckalkan.CertProp]string {
	return map[ckalkan.CertProp]string{
		ckalkan.CertPropSubjectDN:           "CN = Native Subject\x00ignored",
		ckalkan.CertPropCertSN:              "certificateSerialNumber=010203",
		ckalkan.CertPropNotBefore:           "notBefore=02.01.2024 15:04:05 GMT",
		ckalkan.CertPropNotAfter:            "notAfter=03.01.2025 16:05:06 GMT",
		ckalkan.CertPropIssuerDN:            "CN = Native Issuer",
		ckalkan.CertPropPoliciesID:          "certificatePolicies=1.2.398.3.3.4, 1.2.398.3.3.5",
		ckalkan.CertPropKeyUsage:            "keyUsage=digitalSignature, nonRepudiation",
		ckalkan.CertPropExtKeyUsage:         "extendedKeyUsage=clientAuth, emailProtection",
		ckalkan.CertPropAuthKeyID:           "authorityKeyIdentifier=auth-key-id",
		ckalkan.CertPropSubjKeyID:           "subjectKeyIdentifier=subj-key-id",
		ckalkan.CertPropSignatureAlg:        "GOST R 34.10-2015",
		ckalkan.CertPropPubKey:              "PUBLIC-KEY",
		ckalkan.CertPropOCSP:                "OCSP=http://ocsp.example.test",
		ckalkan.CertPropGetCRL:              "crlDistributionPoints=http://crl.example.test/root.crl",
		ckalkan.CertPropGetDeltaCRL:         "freshestCRL=http://crl.example.test/delta.crl",
		ckalkan.CertPropSubjectCountryName:  "C=KZ",
		ckalkan.CertPropSubjectSerialNumber: "serialNumber=IIN990106300596",
		ckalkan.CertPropSubjectOrgName:      `O=LLP "Test"`,
		ckalkan.CertPropSubjectOrgUnitName:  "OU=BIN230540004989",
	}
}
