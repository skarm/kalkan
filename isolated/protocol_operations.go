package isolated

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/skarm/kalkan"
)

const (
	opOpen                           = "Open"
	opClose                          = "Close"
	opHash                           = "Hash"
	opSignHash                       = "SignHash"
	opSignCMS                        = "SignCMS"
	opVerifyCMS                      = "VerifyCMS"
	opSignXML                        = "SignXML"
	opVerifyXML                      = "VerifyXML"
	opSignWSSE                       = "SignWSSE"
	opValidateCertificate            = "ValidateCertificate"
	opLoadKeyStore                   = "LoadKeyStore"
	opLoadTrustedCertificate         = "LoadTrustedCertificate"
	opSetProxy                       = "SetProxy"
	opSignZIP                        = "SignZIP"
	opVerifyZIP                      = "VerifyZIP"
	opExtractZIPSignerCertificate    = "ExtractZIPSignerCertificate"
	opX509ExportCertificateFromStore = "X509ExportCertificateFromStore"
	opX509CertificateGetInfo         = "X509CertificateGetInfo"
	opX509CertificateGetInfoFields   = "X509CertificateGetInfoFields"
	opGetCertFromCMS                 = "GetCertFromCMS"
	opGetCertFromXML                 = "GetCertFromXML"
	opGetTimeFromSig                 = "GetTimeFromSig"
	opGetSigAlgFromXML               = "GetSigAlgFromXML"
)

// sdkClient is the high-level API implemented by a worker's native client.
// Its methods follow the contracts of the corresponding [kalkan.Client] methods.
type sdkClient interface {
	Hash(context.Context, kalkan.HashRequest) (*kalkan.Digest, error)
	SignHash(context.Context, kalkan.SignHashRequest) (*kalkan.CMS, error)
	SignCMS(context.Context, kalkan.SignCMSRequest) (*kalkan.CMS, error)
	VerifyCMS(context.Context, kalkan.VerifyCMSRequest) (*kalkan.Verification, error)
	SignXML(context.Context, kalkan.SignXMLRequest) (*kalkan.SignedXML, error)
	VerifyXML(context.Context, kalkan.VerifyXMLRequest) (*kalkan.Verification, error)
	SignWSSE(context.Context, kalkan.SignWSSERequest) (*kalkan.SignedXML, error)
	ValidateCertificate(context.Context, kalkan.ValidateCertificateRequest) (*kalkan.CertificateValidation, error)
	LoadKeyStore(context.Context, kalkan.KeyStore) error
	LoadTrustedCertificate(context.Context, kalkan.TrustedCertificate) error
	SetProxy(context.Context, kalkan.Proxy) error
	SignZIP(context.Context, kalkan.SignZIPRequest) (*kalkan.SignedZIP, error)
	VerifyZIP(context.Context, kalkan.VerifyZIPRequest) (*kalkan.Verification, error)
	ExtractZIPSignerCertificate(context.Context, kalkan.ExtractZIPSignerCertificateRequest) ([]byte, error)
	X509ExportCertificateFromStore(context.Context) (*x509.Certificate, error)
	X509CertificateGetInfo(context.Context, *x509.Certificate) (*kalkan.CertificateInfo, error)
	X509CertificateGetInfoFields(context.Context, *x509.Certificate, kalkan.CertificateInfoField) (*kalkan.CertificateInfo, error)
	GetCertFromCMS(context.Context, kalkan.Source) ([]*x509.Certificate, error)
	GetCertFromXML(context.Context, kalkan.Source) ([]*x509.Certificate, error)
	GetTimeFromSig(context.Context, kalkan.Source) (time.Time, error)
	GetSigAlgFromXML(context.Context, kalkan.Source) (string, error)
}

var _ sdkClient = (*kalkan.Client)(nil)

// certificateInfoFieldsRequest carries the two arguments of the corresponding
// client method until encodeRequest replaces the certificate with its raw DER.
type certificateInfoFieldsRequest struct {
	// Certificate supplies the raw DER certificate sent to the worker.
	Certificate *x509.Certificate
	// Fields selects the properties to retrieve using a bitwise OR of field flags.
	Fields kalkan.CertificateInfoField
}

// Request fields have a fixed binary order. No reflected struct serialization
// or intermediate copies of byte inputs are used.
func encodeRequest(operation string, request any, inputLimit int64) (wirePayload, error) {
	e := payloadEncoder{inputLimit: inputLimit}

	switch operation {
	case opHash:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).hashRequest)
	case opSignHash:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).signHashRequest)
	case opSignCMS:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).signCMSRequest)
	case opVerifyCMS:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).verifyCMSRequest)
	case opSignXML:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).signXMLRequest)
	case opVerifyXML:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).verifyXMLRequest)
	case opSignWSSE:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).signWSSERequest)
	case opValidateCertificate:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).validateCertificateRequest)
	case opLoadKeyStore:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).keyStore)
	case opLoadTrustedCertificate:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).trustedCertificate)
	case opSetProxy:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).proxy)
	case opSignZIP:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).signZIPRequest)
	case opVerifyZIP:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).verifyZIPRequest)
	case opExtractZIPSignerCertificate:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).extractZIPSignerCertificateRequest)
	case opGetCertFromCMS, opGetCertFromXML, opGetTimeFromSig, opGetSigAlgFromXML:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).source)
	case opX509CertificateGetInfo:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).certificate)
	case opX509CertificateGetInfoFields:
		return encodeRequestValue(&e, operation, request, (*payloadEncoder).certificateInfoFields)
	case opX509ExportCertificateFromStore:
		if request != nil {
			return wirePayload{}, requestTypeError(operation)
		}
	default:
		return wirePayload{}, fmt.Errorf("%w: unknown isolated operation %q", ErrProtocol, operation)
	}

	return e.finish()
}

func encodeRequestValue[Request any](e *payloadEncoder, operation string, request any, encode func(*payloadEncoder, Request)) (wirePayload, error) {
	value, ok := request.(Request)
	if !ok {
		return wirePayload{}, requestTypeError(operation)
	}

	encode(e, value)

	return e.finish()
}

func requestTypeError(operation string) error {
	return fmt.Errorf("%w: incorrect isolated request type for %s", kalkan.ErrInvalidInput, operation)
}

// The root API owns SDK validation. Fully decode and validate field boundaries
// before calling it, so malformed requests cannot reach native code.
func dispatch(ctx context.Context, client sdkClient, operation string, payload wirePayload) (wirePayload, error) {
	switch operation {
	case opHash:
		return dispatchRequest(ctx, payload, (*payloadDecoder).hashRequest, client.Hash)
	case opSignHash:
		return dispatchRequest(ctx, payload, (*payloadDecoder).signHashRequest, client.SignHash)
	case opSignCMS:
		return dispatchRequest(ctx, payload, (*payloadDecoder).signCMSRequest, client.SignCMS)
	case opVerifyCMS:
		return dispatchRequest(ctx, payload, (*payloadDecoder).verifyCMSRequest, client.VerifyCMS)
	case opSignXML:
		return dispatchRequest(ctx, payload, (*payloadDecoder).signXMLRequest, client.SignXML)
	case opVerifyXML:
		return dispatchRequest(ctx, payload, (*payloadDecoder).verifyXMLRequest, client.VerifyXML)
	case opSignWSSE:
		return dispatchRequest(ctx, payload, (*payloadDecoder).signWSSERequest, client.SignWSSE)
	case opValidateCertificate:
		return dispatchRequest(ctx, payload, (*payloadDecoder).validateCertificateRequest, client.ValidateCertificate)
	case opLoadKeyStore:
		return dispatchVoid(ctx, payload, (*payloadDecoder).keyStore, client.LoadKeyStore)
	case opLoadTrustedCertificate:
		return dispatchVoid(ctx, payload, (*payloadDecoder).trustedCertificate, client.LoadTrustedCertificate)
	case opSetProxy:
		return dispatchVoid(ctx, payload, (*payloadDecoder).proxy, client.SetProxy)
	case opSignZIP:
		return dispatchRequest(ctx, payload, (*payloadDecoder).signZIPRequest, client.SignZIP)
	case opVerifyZIP:
		return dispatchRequest(ctx, payload, (*payloadDecoder).verifyZIPRequest, client.VerifyZIP)
	case opExtractZIPSignerCertificate:
		return dispatchRequest(ctx, payload, (*payloadDecoder).extractZIPSignerCertificateRequest, client.ExtractZIPSignerCertificate)
	case opGetCertFromCMS:
		return dispatchRequest(ctx, payload, (*payloadDecoder).source, client.GetCertFromCMS)
	case opGetCertFromXML:
		return dispatchRequest(ctx, payload, (*payloadDecoder).source, client.GetCertFromXML)
	case opGetTimeFromSig:
		return dispatchRequest(ctx, payload, (*payloadDecoder).source, client.GetTimeFromSig)
	case opGetSigAlgFromXML:
		return dispatchRequest(ctx, payload, (*payloadDecoder).source, client.GetSigAlgFromXML)
	case opX509CertificateGetInfo:
		return dispatchRequest(ctx, payload, (*payloadDecoder).certificate, client.X509CertificateGetInfo)
	case opX509CertificateGetInfoFields:
		return dispatchRequest(ctx, payload, (*payloadDecoder).certificateInfoFields,
			func(ctx context.Context, req certificateInfoFieldsRequest) (*kalkan.CertificateInfo, error) {
				return client.X509CertificateGetInfoFields(ctx, req.Certificate, req.Fields)
			})
	case opX509ExportCertificateFromStore:
		return dispatchRequest(ctx, payload, (*payloadDecoder).empty,
			func(ctx context.Context, _ struct{}) (*x509.Certificate, error) {
				return client.X509ExportCertificateFromStore(ctx)
			})
	default:
		return wirePayload{}, fmt.Errorf("%w: unknown isolated operation %q", ErrProtocol, operation)
	}
}

func dispatchRequest[Request, Result any](ctx context.Context, payload wirePayload, decode func(*payloadDecoder) Request, call func(context.Context, Request) (Result, error)) (wirePayload, error) {
	d := decodePayload(payload)

	request := decode(&d)
	if err := d.finish(); err != nil {
		return wirePayload{}, err
	}

	result, err := call(ctx, request)
	if err != nil {
		return wirePayload{}, err
	}

	return encodeResult(result)
}

func dispatchVoid[Request any](ctx context.Context, payload wirePayload, decode func(*payloadDecoder) Request, call func(context.Context, Request) error) (wirePayload, error) {
	return dispatchRequest(ctx, payload, decode, func(ctx context.Context, request Request) (any, error) {
		return nil, call(ctx, request)
	})
}

func (d *payloadDecoder) empty() struct{} {
	if len(d.blocks) != 0 {
		d.err = fmt.Errorf("%w: unexpected data blocks", ErrProtocol)
	}

	return struct{}{}
}

func (e *payloadEncoder) source(value kalkan.Source) {
	v := value.Describe()
	e.bytes(v.Data)
	e.text(v.Path)
	e.integer(int(v.Encoding))
	e.boolean(v.File)
	e.boolean(v.Set)
}

func (d *payloadDecoder) source() kalkan.Source {
	data, path, encoding := d.bytes(), d.text(), kalkan.Encoding(d.integer())
	file, set := d.boolean(), d.boolean()

	var source kalkan.Source

	if set {
		if file {
			source = kalkan.File(path)
		} else {
			source = kalkan.Bytes(data)
		}
	}

	return source.WithEncoding(encoding)
}

func (e *payloadEncoder) certificate(value *x509.Certificate) {
	e.boolean(value != nil)

	if value != nil {
		e.bytes(value.Raw)
	}
}

func (d *payloadDecoder) certificate() *x509.Certificate {
	if !d.boolean() {
		return nil
	}
	// Only Raw is consumed by root certificate operations, which validate it.
	return &x509.Certificate{Raw: d.bytes()}
}

func (e *payloadEncoder) hashRequest(v kalkan.HashRequest) {
	e.integer(int(v.Algorithm))
	e.source(v.Data)
}

func (d *payloadDecoder) hashRequest() kalkan.HashRequest {
	return kalkan.HashRequest{
		Algorithm: kalkan.HashAlgorithm(d.integer()),
		Data:      d.source(),
	}
}

func (e *payloadEncoder) signHashRequest(v kalkan.SignHashRequest) {
	e.text(v.Alias)
	e.bytes(v.Digest)
	e.integer(int(v.DigestAlgorithm))
	e.boolean(v.Timestamp)
	e.boolean(v.IncludeCertificate)
	e.integer(int(v.OutputFormat))
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) signHashRequest() kalkan.SignHashRequest {
	return kalkan.SignHashRequest{
		Alias:                d.text(),
		Digest:               d.bytes(),
		DigestAlgorithm:      kalkan.HashAlgorithm(d.integer()),
		Timestamp:            d.boolean(),
		IncludeCertificate:   d.boolean(),
		OutputFormat:         kalkan.CMSOutputFormat(d.integer()),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) signCMSRequest(v kalkan.SignCMSRequest) {
	e.text(v.Alias)
	e.source(v.Data)
	e.boolean(v.Detached)
	e.boolean(v.Timestamp)
	e.boolean(v.IncludeCertificate)
	e.integer(int(v.OutputFormat))
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) signCMSRequest() kalkan.SignCMSRequest {
	return kalkan.SignCMSRequest{
		Alias:                d.text(),
		Data:                 d.source(),
		Detached:             d.boolean(),
		Timestamp:            d.boolean(),
		IncludeCertificate:   d.boolean(),
		OutputFormat:         kalkan.CMSOutputFormat(d.integer()),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) verifyCMSRequest(v kalkan.VerifyCMSRequest) {
	e.text(v.Alias)
	e.source(v.Signature)
	e.source(v.Data)
	e.boolean(v.Detached)
	e.integer(int(v.Encoding))
	e.integer(v.SignerID)
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) verifyCMSRequest() kalkan.VerifyCMSRequest {
	return kalkan.VerifyCMSRequest{
		Alias:                d.text(),
		Signature:            d.source(),
		Data:                 d.source(),
		Detached:             d.boolean(),
		Encoding:             kalkan.Encoding(d.integer()),
		SignerID:             d.integer(),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) signXMLRequest(v kalkan.SignXMLRequest) {
	e.text(v.Alias)
	e.source(v.XML)
	e.text(v.SignNodeID)
	e.text(v.ParentSignNode)
	e.text(v.ParentNamespace)
	e.integer(int(v.Canonicalization))
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) signXMLRequest() kalkan.SignXMLRequest {
	return kalkan.SignXMLRequest{
		Alias:                d.text(),
		XML:                  d.source(),
		SignNodeID:           d.text(),
		ParentSignNode:       d.text(),
		ParentNamespace:      d.text(),
		Canonicalization:     kalkan.XMLCanonicalization(d.integer()),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) verifyXMLRequest(v kalkan.VerifyXMLRequest) {
	e.text(v.Alias)
	e.source(v.XML)
	e.text(v.ExpectedBodyID)
	e.integer(int(v.Canonicalization))
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) verifyXMLRequest() kalkan.VerifyXMLRequest {
	return kalkan.VerifyXMLRequest{
		Alias:                d.text(),
		XML:                  d.source(),
		ExpectedBodyID:       d.text(),
		Canonicalization:     kalkan.XMLCanonicalization(d.integer()),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) signWSSERequest(v kalkan.SignWSSERequest) {
	e.text(v.Alias)
	e.source(v.XML)
	e.text(v.BodyID)
	e.boolean(v.WrapSOAP)
	e.integer(int(v.Canonicalization))
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) signWSSERequest() kalkan.SignWSSERequest {
	return kalkan.SignWSSERequest{
		Alias:                d.text(),
		XML:                  d.source(),
		BodyID:               d.text(),
		WrapSOAP:             d.boolean(),
		Canonicalization:     kalkan.XMLCanonicalization(d.integer()),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) validateCertificateRequest(v kalkan.ValidateCertificateRequest) {
	e.source(v.Certificate)
	e.integer(int(v.Mode))
	e.text(v.RevocationSource)
	e.timestamp(v.CheckTime)
	e.boolean(v.ReturnOCSPResponse)
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) validateCertificateRequest() kalkan.ValidateCertificateRequest {
	return kalkan.ValidateCertificateRequest{
		Certificate:          d.source(),
		Mode:                 kalkan.CertificateValidationMode(d.integer()),
		RevocationSource:     d.text(),
		CheckTime:            d.timestamp(),
		ReturnOCSPResponse:   d.boolean(),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) keyStore(v kalkan.KeyStore) {
	e.integer(int(v.Type))
	e.text(v.Path)
	e.text(v.Password)
	e.text(v.Alias)
}

func (d *payloadDecoder) keyStore() kalkan.KeyStore {
	return kalkan.KeyStore{
		Type:     kalkan.KeyStoreType(d.integer()),
		Path:     d.text(),
		Password: d.text(),
		Alias:    d.text(),
	}
}

func (e *payloadEncoder) trustedCertificate(v kalkan.TrustedCertificate) {
	e.bytes(v.Data)
	e.text(v.Path)
	e.integer(int(v.Type))
	e.integer(int(v.Format))
}

func (d *payloadDecoder) trustedCertificate() kalkan.TrustedCertificate {
	return kalkan.TrustedCertificate{
		Data:   d.bytes(),
		Path:   d.text(),
		Type:   kalkan.CertificateType(d.integer()),
		Format: kalkan.CertificateFormat(d.integer()),
	}
}

func (e *payloadEncoder) proxy(v kalkan.Proxy) {
	e.boolean(v.Enabled)
	e.text(v.Address)
	e.text(v.Port)
	e.text(v.User)
	e.text(v.Password)
}

func (d *payloadDecoder) proxy() kalkan.Proxy {
	return kalkan.Proxy{
		Enabled:  d.boolean(),
		Address:  d.text(),
		Port:     d.text(),
		User:     d.text(),
		Password: d.text(),
	}
}

func (e *payloadEncoder) signZIPRequest(v kalkan.SignZIPRequest) {
	e.text(v.Alias)
	e.text(v.InputPath)
	e.text(v.OutputPath)
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) signZIPRequest() kalkan.SignZIPRequest {
	return kalkan.SignZIPRequest{
		Alias:                d.text(),
		InputPath:            d.text(),
		OutputPath:           d.text(),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) verifyZIPRequest(v kalkan.VerifyZIPRequest) {
	e.text(v.Path)
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) verifyZIPRequest() kalkan.VerifyZIPRequest {
	return kalkan.VerifyZIPRequest{
		Path:                 d.text(),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) extractZIPSignerCertificateRequest(v kalkan.ExtractZIPSignerCertificateRequest) {
	e.text(v.Path)
	e.integer(v.SignerID)
	e.integer(int(v.CertificateTimeCheck))
}

func (d *payloadDecoder) extractZIPSignerCertificateRequest() kalkan.ExtractZIPSignerCertificateRequest {
	return kalkan.ExtractZIPSignerCertificateRequest{
		Path:                 d.text(),
		SignerID:             d.integer(),
		CertificateTimeCheck: kalkan.CertificateTimeCheck(d.integer()),
	}
}

func (e *payloadEncoder) certificateInfoFields(v certificateInfoFieldsRequest) {
	e.certificate(v.Certificate)
	e.uint64(uint64(v.Fields))
}

func (d *payloadDecoder) certificateInfoFields() certificateInfoFieldsRequest {
	return certificateInfoFieldsRequest{
		Certificate: d.certificate(),
		Fields:      kalkan.CertificateInfoField(d.uint64()),
	}
}
