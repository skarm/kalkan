package kalkan

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
)

// parseOCSPDERCertificate parses legacy certificates with negative serial
// numbers that KalkanCrypt accepts.
// It preserves signed bytes and the actual serial number.
// It relaxes only x509's serial number restriction.
// Signature verification uses the original TBSCertificate.
// The implementation derives from CSP's kalkanSignedCertificate.
func parseOCSPDERCertificate(der []byte) (*x509.Certificate, error) {
	certificate, originalErr := x509.ParseCertificate(der)
	if originalErr == nil {
		return certificate, nil
	}

	var outer, tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 || outer.Tag != asn1.TagSequence || outer.Class != 0 || !outer.IsCompound {
		return nil, originalErr
	}

	trailer, err := asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil || tbs.Tag != asn1.TagSequence || tbs.Class != 0 || !tbs.IsCompound {
		return nil, originalErr
	}

	remaining := tbs.Bytes

	var first asn1.RawValue

	remaining, err = asn1.Unmarshal(remaining, &first)
	if err != nil {
		return nil, originalErr
	}

	var version []byte
	if first.Class == asn1.ClassContextSpecific && first.Tag == 0 {
		version = first.FullBytes

		remaining, err = asn1.Unmarshal(remaining, &first)
		if err != nil {
			return nil, originalErr
		}
	}

	var serial *big.Int
	if rest, err := asn1.Unmarshal(first.FullBytes, &serial); err != nil || len(rest) != 0 || serial.Sign() >= 0 {
		return nil, originalErr
	}

	positiveTBS, err := asn1.Marshal(asn1.RawValue{
		Tag: asn1.TagSequence, IsCompound: true,
		Bytes: bytes.Join([][]byte{version, {asn1.TagInteger, 1, 1}, remaining}, nil),
	})
	if err != nil {
		return nil, originalErr
	}

	positive, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(positiveTBS, trailer...)})
	if err != nil {
		return nil, originalErr
	}

	certificate, err = x509.ParseCertificate(positive)
	if err != nil {
		return nil, originalErr
	}

	certificate.Raw, certificate.RawTBSCertificate, certificate.SerialNumber = der, tbs.FullBytes, serial

	return certificate, nil
}
