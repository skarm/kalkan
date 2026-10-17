package isolated

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/skarm/kalkan"
)

func encodeResult(result any) (wirePayload, error) {
	e := payloadEncoder{}

	switch value := result.(type) {
	case nil:
	case []byte:
		e.bytes(value)
	case *x509.Certificate:
		if value == nil {
			e.bytes(nil)
		} else {
			e.bytes(value.Raw)
		}
	case []*x509.Certificate:
		if e.length(len(value), value != nil) {
			for _, certificate := range value {
				if certificate == nil {
					e.bytes(nil)
				} else {
					e.bytes(certificate.Raw)
				}
			}
		}
	case [][]byte:
		if e.length(len(value), value != nil) {
			for _, data := range value {
				e.bytes(data)
			}
		}
	case string:
		e.text(value)
	case time.Time:
		e.timestamp(value)
	case *kalkan.Digest:
		encodeOptional(&e, value, (*payloadEncoder).digest)
	case *kalkan.CMS:
		encodeOptional(&e, value, (*payloadEncoder).cms)
	case *kalkan.SignedXML:
		encodeOptional(&e, value, (*payloadEncoder).signedXML)
	case *kalkan.Verification:
		encodeOptional(&e, value, (*payloadEncoder).verification)
	case *kalkan.CertificateValidation:
		encodeOptional(&e, value, (*payloadEncoder).validation)
	case *kalkan.SignedZIP:
		encodeOptional(&e, value, (*payloadEncoder).signedZIP)
	case *kalkan.CertificateInfo:
		encodeOptional(&e, value, (*payloadEncoder).certificateInfo)
	default:
		return wirePayload{}, fmt.Errorf("%w: unsupported operation result", ErrProtocol)
	}

	return e.finish()
}

func encodeOptional[Value any](e *payloadEncoder, value *Value, encode func(*payloadEncoder, Value)) {
	e.boolean(value != nil)

	if value != nil {
		encode(e, *value)
	}
}

func decodeOptional[Value any](d *payloadDecoder, decode func(*payloadDecoder) Value) *Value {
	if !d.boolean() {
		return nil
	}

	value := decode(d)

	return &value
}

func decodeResult(operation string, payload wirePayload, out any) error {
	switch operation {
	case opHash:
		return decodePointerResult(payload, out, (*payloadDecoder).digest)
	case opSignHash, opSignCMS:
		return decodePointerResult(payload, out, (*payloadDecoder).cms)
	case opSignXML, opSignWSSE:
		return decodePointerResult(payload, out, (*payloadDecoder).signedXML)
	case opVerifyCMS, opVerifyXML, opVerifyZIP:
		return decodePointerResult(payload, out, (*payloadDecoder).verification)
	case opValidateCertificate:
		return decodePointerResult(payload, out, (*payloadDecoder).validation)
	case opSignZIP:
		return decodePointerResult(payload, out, (*payloadDecoder).signedZIP)
	case opX509CertificateGetInfo, opX509CertificateGetInfoFields:
		return decodePointerResult(payload, out, (*payloadDecoder).certificateInfo)
	case opGetSigAlgFromXML:
		return decodeValueResult(payload, out, (*payloadDecoder).text)
	case opGetTimeFromSig:
		return decodeValueResult(payload, out, (*payloadDecoder).timestamp)
	case opExtractZIPSignerCertificate, opX509ExportCertificateFromStore:
		return decodeValueResult(payload, out, (*payloadDecoder).bytes)
	case opGetCertFromCMS, opGetCertFromXML:
		return decodeValueResult(payload, out, (*payloadDecoder).certificates)
	case opLoadKeyStore, opLoadTrustedCertificate, opSetProxy:
		if !payload.isNull() {
			return malformedResult()
		}

		return nil
	default:
		return fmt.Errorf("%w: unknown isolated operation %q", ErrProtocol, operation)
	}
}

func decodeValueResult[Value any](payload wirePayload, out any, decode func(*payloadDecoder) Value) error {
	target, ok := out.(*Value)
	if !ok || target == nil {
		return malformedResult()
	}

	d := decodePayload(payload)

	value := decode(&d)
	if err := d.finish(); err != nil {
		return err
	}

	*target = value

	return nil
}

func decodePointerResult[Value any](payload wirePayload, out any, decode func(*payloadDecoder) Value) error {
	return decodeValueResult(payload, out, func(d *payloadDecoder) *Value { return decodeOptional(d, decode) })
}

func malformedResult() error {
	return fmt.Errorf("%w: malformed isolated operation result", ErrProtocol)
}

func (d *payloadDecoder) certificates() [][]byte {
	count := d.length(4)
	if count < 0 {
		return nil
	}

	values := make([][]byte, count)
	for i := range values {
		values[i] = d.bytes()
	}

	return values
}

// Preserve the instant and observed zone offset, including values outside
// RFC3339's range. Named location rules and monotonic readings are process-local.
func (e *payloadEncoder) timestamp(value time.Time) {
	e.boolean(!value.IsZero())

	if value.IsZero() {
		return
	}

	name, offset := value.Zone()
	e.int64(value.Unix())
	e.integer(value.Nanosecond())
	e.text(name)
	e.integer(offset)
	e.boolean(value.Location() == time.UTC)
}

func (d *payloadDecoder) timestamp() time.Time {
	if !d.boolean() {
		return time.Time{}
	}

	seconds, nanos := d.int64(), d.integer()

	name, offset, utc := d.text(), d.integer(), d.boolean()
	if nanos < 0 || nanos >= 1_000_000_000 {
		d.err = malformedResult()
		return time.Time{}
	}

	location := time.UTC
	if !utc {
		location = time.FixedZone(name, offset)
	}

	return time.Unix(seconds, int64(nanos)).In(location)
}

func (e *payloadEncoder) digest(v kalkan.Digest) {
	e.integer(int(v.Algorithm))
	e.bytes(v.Data)
}

func (d *payloadDecoder) digest() kalkan.Digest {
	return kalkan.Digest{
		Algorithm: kalkan.HashAlgorithm(d.integer()),
		Data:      d.bytes(),
	}
}

func (e *payloadEncoder) cms(v kalkan.CMS) {
	e.bytes(v.Data)
}

func (d *payloadDecoder) cms() kalkan.CMS {
	return kalkan.CMS{
		Data: d.bytes(),
	}
}

func (e *payloadEncoder) signedXML(v kalkan.SignedXML) {
	e.bytes(v.XML)
}

func (d *payloadDecoder) signedXML() kalkan.SignedXML {
	return kalkan.SignedXML{
		XML: d.bytes(),
	}
}

func (e *payloadEncoder) verification(v kalkan.Verification) {
	e.text(v.Info)
	e.bytes(v.Data)
	e.bytes(v.SignerCert)
}

func (d *payloadDecoder) verification() kalkan.Verification {
	return kalkan.Verification{
		Info:       d.text(),
		Data:       d.bytes(),
		SignerCert: d.bytes(),
	}
}

func (e *payloadEncoder) validation(v kalkan.CertificateValidation) {
	e.text(v.Info)
	e.bytes(v.OCSPResponse)
}

func (d *payloadDecoder) validation() kalkan.CertificateValidation {
	return kalkan.CertificateValidation{
		Info:         d.text(),
		OCSPResponse: d.bytes(),
	}
}

func (e *payloadEncoder) signedZIP(v kalkan.SignedZIP) {
	e.text(v.Path)
}

func (d *payloadDecoder) signedZIP() kalkan.SignedZIP {
	return kalkan.SignedZIP{
		Path: d.text(),
	}
}

func (e *payloadEncoder) certificateInfo(v kalkan.CertificateInfo) {
	e.text(v.Subject)
	e.text(v.SerialNumber)
	e.timestamp(v.ValidFrom)
	e.timestamp(v.ValidUntil)
	e.text(v.Issuer)
	e.text(v.Policy)
	e.text(v.KeyUsage)
	e.text(v.ExtKeyUsage)
	e.text(v.AuthKeyID)
	e.text(v.SubjKeyID)
	e.text(v.SignatureAlgorithm)
	e.text(v.PublicKey)
	e.text(v.OCSPURL)
	e.text(v.CRLURL)
	e.text(v.DeltaCRLURL)
	e.text(v.SubjectCountry)
	e.text(v.SubjectSerialNumber)
	e.text(v.SubjectOrganization)
	e.text(v.SubjectOrganizationalUnit)
	encodeStrings(e, v.Policies)
	encodeStrings(e, v.KeyUsages)
	encodeStrings(e, v.ExtKeyUsages)
	e.text(v.IIN)
	e.text(v.BIN)
	e.text(string(v.SubjectType))
	encodeStrings(e, v.Roles)
}

func (d *payloadDecoder) certificateInfo() kalkan.CertificateInfo {
	return kalkan.CertificateInfo{
		Subject:                   d.text(),
		SerialNumber:              d.text(),
		ValidFrom:                 d.timestamp(),
		ValidUntil:                d.timestamp(),
		Issuer:                    d.text(),
		Policy:                    d.text(),
		KeyUsage:                  d.text(),
		ExtKeyUsage:               d.text(),
		AuthKeyID:                 d.text(),
		SubjKeyID:                 d.text(),
		SignatureAlgorithm:        d.text(),
		PublicKey:                 d.text(),
		OCSPURL:                   d.text(),
		CRLURL:                    d.text(),
		DeltaCRLURL:               d.text(),
		SubjectCountry:            d.text(),
		SubjectSerialNumber:       d.text(),
		SubjectOrganization:       d.text(),
		SubjectOrganizationalUnit: d.text(),
		Policies:                  decodeStrings[string](d),
		KeyUsages:                 decodeStrings[string](d),
		ExtKeyUsages:              decodeStrings[string](d),
		IIN:                       d.text(),
		BIN:                       d.text(),
		SubjectType:               kalkan.CertificateSubjectType(d.text()),
		Roles:                     decodeStrings[kalkan.CertificateRole](d),
	}
}
