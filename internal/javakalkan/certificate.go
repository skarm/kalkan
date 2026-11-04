package javakalkan

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

// Certificate properties are metadata, so parsing them does not require a
// signature algorithm implementation. This also handles GOST SPKI and OIDs.
func (c *Operation) X509CertificateGetInfo(encoded []byte, prop ckalkan.CertProp) ([]byte, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}

	if c.closed {
		return nil, ErrWorkerFailed
	}

	if c.failed != nil {
		return nil, c.failed
	}

	if bytes.HasPrefix(bytes.TrimSpace(encoded), []byte("-----BEGIN")) {
		var err error

		encoded, err = decodeSinglePEM(encoded)
		if err != nil {
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate properties: %w", ErrInvalidInput, err)
	}

	value, err := certificateProperty(cert, prop)
	if err != nil {
		return nil, err
	}

	if err := c.checkOutputSize("X509CertificateGetInfo", len(value)); err != nil {
		return nil, err
	}

	return []byte(value), nil
}

func certificateProperty(cert *x509.Certificate, prop ckalkan.CertProp) (string, error) {
	// The order matches the SDK's contiguous issuer/subject property constants.
	attributes := []struct {
		oid, name string
		issuer    bool
	}{
		{"2.5.4.6", "C", true},
		{"2.5.4.8", "ST", true},
		{"2.5.4.7", "L", true},
		{"2.5.4.10", "O", true},
		{"2.5.4.11", "OU", true},
		{"2.5.4.3", "CN", true},
		{"2.5.4.6", "C", false},
		{"2.5.4.8", "ST", false},
		{"2.5.4.7", "L", false},
		{"2.5.4.3", "CN", false},
		{"2.5.4.42", "GN", false},
		{"2.5.4.4", "SN", false},
		{"2.5.4.5", "serialNumber", false},
		{"1.2.840.113549.1.9.1", "emailAddress", false},
		{"2.5.4.10", "O", false},
		{"2.5.4.11", "OU", false},
		{"2.5.4.15", "businessCategory", false},
		{"0.9.2342.19200300.100.1.25", "DC", false},
	}
	if prop >= ckalkan.CertPropIssuerCountryName && prop <= ckalkan.CertPropSubjectDC {
		attr := attributes[int(prop-ckalkan.CertPropIssuerCountryName)]

		raw := cert.RawSubject
		if attr.issuer {
			raw = cert.RawIssuer
		}

		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(raw, &rdn); err != nil {
			return "", err
		}

		var values []string

		for _, set := range rdn {
			for _, value := range set {
				if value.Type.String() == attr.oid {
					values = append(values, attr.name+"="+fmt.Sprint(value.Value))
				}
			}
		}

		return strings.Join(values, "\n"), nil
	}

	switch prop {
	case ckalkan.CertPropNotBefore:
		return "notBefore=" + cert.NotBefore.UTC().Format(time.RFC3339), nil
	case ckalkan.CertPropNotAfter:
		return "notAfter=" + cert.NotAfter.UTC().Format(time.RFC3339), nil
	case ckalkan.CertPropIssuerDN:
		return cert.Issuer.String(), nil
	case ckalkan.CertPropSubjectDN:
		return cert.Subject.String(), nil
	case ckalkan.CertPropCertSN:
		return "certificateSerialNumber=" + strings.ToUpper(cert.SerialNumber.Text(16)), nil
	case ckalkan.CertPropAuthKeyID:
		return "authorityKeyIdentifier=" + strings.ToUpper(hex.EncodeToString(cert.AuthorityKeyId)), nil
	case ckalkan.CertPropSubjKeyID:
		return "subjectKeyIdentifier=" + strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId)), nil
	case ckalkan.CertPropPubKey:
		return base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo), nil
	case ckalkan.CertPropKeyUsage:
		names := []string{"Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Certificate Sign", "CRL Sign", "Encipher Only", "Decipher Only"}

		var usages []string

		for i, name := range names {
			if cert.KeyUsage&(1<<i) != 0 {
				usages = append(usages, name)
			}
		}

		return "keyUsage=" + strings.Join(usages, ", "), nil
	case ckalkan.CertPropExtKeyUsage:
		return certificateOIDExtension(cert, "2.5.29.37", "extendedKeyUsage")
	case ckalkan.CertPropPoliciesID:
		values := make([]string, len(cert.Policies))
		for i, policy := range cert.Policies {
			values[i] = policy.String()
		}

		return "certificatePolicies=" + strings.Join(values, ", "), nil
	case ckalkan.CertPropSignatureAlg:
		var outer struct {
			TBS       asn1.RawValue
			Algorithm pkix.AlgorithmIdentifier
			Signature asn1.BitString
		}
		if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
			return "", err
		}

		oid := outer.Algorithm.Algorithm.String()
		if name := certificateSignatureName(oid); name != "" {
			return "signatureAlgorithm=" + name + "(" + oid + ")", nil
		}

		return oid, nil
	case ckalkan.CertPropOCSP:
		return "OCSP=" + strings.Join(cert.OCSPServer, ", "), nil
	case ckalkan.CertPropGetCRL:
		return "crlDistributionPoints=" + strings.Join(cert.CRLDistributionPoints, ", "), nil
	case ckalkan.CertPropGetDeltaCRL:
		for _, ext := range cert.Extensions {
			if ext.Id.String() == "2.5.29.46" {
				values, err := certificateURIs(ext.Value, 0)
				return "freshestCRL=" + strings.Join(values, ", "), err
			}
		}

		return "", nil
	default:
		return "", fmt.Errorf("%w: unknown certificate property %d", ErrInvalidInput, prop)
	}
}

// Names match OBJ_nid2ln in the native KalkanCrypt 2.0.13 SDK. In particular,
// RSA-PSS identifies the algorithm, not its hash parameters. Keep unknown OIDs
// intact so newer algorithms remain readable without a provider dependency.
func certificateSignatureName(oid string) string {
	switch oid {
	case "1.2.840.113549.1.1.2":
		return "md2WithRSAEncryption"
	case "1.2.840.113549.1.1.4":
		return "md5WithRSAEncryption"
	case "1.2.840.113549.1.1.5":
		return "sha1WithRSAEncryption"
	case "1.2.840.113549.1.1.10":
		return "rsassaPss"
	case "1.2.840.113549.1.1.11":
		return "sha256WithRSAEncryption"
	case "1.2.840.113549.1.1.12":
		return "sha384WithRSAEncryption"
	case "1.2.840.113549.1.1.13":
		return "sha512WithRSAEncryption"
	case "1.2.840.10040.4.3":
		return "dsaWithSHA1"
	case "2.16.840.1.101.3.4.3.2":
		return "dsa_with_SHA256"
	case "1.2.840.10045.4.1":
		return "ecdsa-with-SHA1"
	case "1.2.840.10045.4.3.2":
		return "ecdsa-with-SHA256"
	case "1.2.840.10045.4.3.3":
		return "ecdsa-with-SHA384"
	case "1.2.840.10045.4.3.4":
		return "ecdsa-with-SHA512"
	case "1.3.101.112":
		return "ED25519"
	case "1.2.398.3.10.1.1.1.1":
		return "GOST 34.310-2004"
	case "1.2.398.3.10.1.1.1.2":
		return "GOST 34.311-95 with GOST 34.310-2004"
	case "1.2.398.3.10.1.1.2.1":
		return "GOST R 34.10-2015 with 256 bit modulus"
	case "1.2.398.3.10.1.1.2.2":
		return "GOST R 34.10-2015 with 512 bit modulus"
	case "1.2.398.3.10.1.1.2.3.1":
		return "GOST R 34.10-2015 with GOST R 34.11-2015 (256 bit)"
	case "1.2.398.3.10.1.1.2.3.2":
		return "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)"
	case "1.3.6.1.4.1.6801.1.2.2":
		return "GOST Old 34.311-95 with GOST Old 34.310-2004"
	case "1.2.643.2.2.3":
		return "GOST R 34.11-94 with GOST R 34.10-2001"
	case "1.2.643.2.2.4":
		return "GOST R 34.11-94 with GOST R 34.10-94"
	case "1.2.643.7.1.1.3.2":
		return "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)"
	case "1.2.643.7.1.1.3.3":
		return "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)"
	default:
		return ""
	}
}

func certificateOIDExtension(cert *x509.Certificate, oid, label string) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.String() != oid {
			continue
		}

		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			return "", err
		}

		values := make([]string, len(oids))
		for i, value := range oids {
			values[i] = value.String()
		}

		return label + "=" + strings.Join(values, ", "), nil
	}

	return "", nil
}

func certificateURIs(encoded []byte, depth int) ([]string, error) {
	if depth > 16 {
		return nil, fmt.Errorf("%w: certificate extension nesting", ErrInvalidInput)
	}

	var values []string

	for len(encoded) > 0 {
		var value asn1.RawValue

		rest, err := asn1.Unmarshal(encoded, &value)
		if err != nil {
			return nil, err
		}

		encoded = rest

		if value.Class == asn1.ClassContextSpecific && value.Tag == 6 && !value.IsCompound {
			values = append(values, string(value.Bytes))
		}

		if value.IsCompound {
			nested, err := certificateURIs(value.Bytes, depth+1)
			if err != nil {
				return nil, err
			}

			values = append(values, nested...)
		}
	}

	return values, nil
}
