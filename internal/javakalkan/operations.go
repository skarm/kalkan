package javakalkan

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func encodeFlag(flags ckalkan.Flag, bit ckalkan.Flag) []byte {
	if flags&bit != 0 {
		return []byte("1")
	}

	return []byte("0")
}

func unsupported(operation string) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, operation)
}

func (c *Operation) SetTSAURL(endpoint string) error {
	_, err := c.call("SetTSAURL", 12, 0, []byte(endpoint))
	return err
}

func (c *Operation) SetProxy(req ckalkan.ProxyRequest) error {
	return c.configureProxy(req)
}

func (c *Operation) HashData(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
	input, err := c.inputBytes(data, flags)
	if err != nil {
		return nil, err
	}

	fields, err := c.call("Hash", 1, 1, []byte(algorithm), input)
	if err != nil {
		return nil, err
	}

	return c.outputBytes("Hash", fields[0], 0)
}

func (c *Operation) LoadKeyStore(storage ckalkan.Store, password, container, alias string) error {
	if storage != ckalkan.StorePKCS12 {
		return unsupported("key store type")
	}

	_, err := c.call("LoadKeyStore", 2, 0, []byte(container), []byte(password), []byte(alias))

	return err
}

func (c *Operation) SignData(req ckalkan.SignDataRequest) ([]byte, error) {
	data, err := c.inputBytes(req.Data, req.Flags)
	if err != nil {
		return nil, err
	}

	fields, err := c.call("SignCMS", 3, 1, []byte(req.Alias), data,
		encodeFlag(req.Flags, ckalkan.DetachedData), encodeFlag(req.Flags, ckalkan.WithCert), encodeFlag(req.Flags, ckalkan.NoCheckCertTime),
		encodeFlag(req.Flags, ckalkan.WithTimestamp), req.Signature)
	if err != nil {
		return nil, err
	}

	return c.outputBytes("SignCMS", fields[0], req.Flags)
}

func (c *Operation) SignHash(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
	fields, err := c.call("SignHash", 5, 1, []byte(alias), hash, encodeFlag(flags, ckalkan.WithCert), encodeFlag(flags, ckalkan.NoCheckCertTime), encodeFlag(flags, ckalkan.WithTimestamp))
	if err != nil {
		return nil, err
	}

	return c.outputBytes("SignHash", fields[0], flags)
}

func (c *Operation) VerifyData(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
	var result ckalkan.VerifyDataResult

	signature, err := c.inputBytes(req.Signature, req.Flags)
	if err != nil {
		return result, err
	}

	data := req.Data
	if req.Flags&ckalkan.In2Base64 != 0 {
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return result, fmt.Errorf("%w: detached data base64: %w", ErrInvalidInput, err)
		}
	}

	fields, err := c.call("VerifyCMS", 4, 3, signature, data, encodeFlag(req.Flags, ckalkan.DetachedData),
		[]byte(strconv.Itoa(req.CertID)), encodeFlag(req.Flags, ckalkan.NoCheckCertTime), []byte(req.Alias))
	if err != nil {
		return result, err
	}

	for _, field := range fields {
		if err := c.checkOutputSize("VerifyCMS", len(field)); err != nil {
			return result, err
		}
	}

	result.Data, result.Cert, result.VerifyInfo = fields[0], fields[1], string(fields[2])
	// Only in-memory attached CMS returns the extracted payload.
	if req.Flags&(ckalkan.DetachedData|ckalkan.InFile) != 0 {
		result.Data = nil
	}

	return result, nil
}

func (c *Operation) GetCertFromCMS(data []byte, signID int, flags ckalkan.Flag) ([]byte, error) {
	der, err := c.inputBytes(data, flags&^ckalkan.InFile)
	if err != nil {
		return nil, err
	}

	fields, err := c.call("GetCertFromCMS", 6, 1, der, []byte(strconv.Itoa(signID)))
	if err != nil {
		return nil, err
	}
	// Certificates are returned as DER; an empty result ends enumeration.
	if err := c.checkOutputSize("GetCertFromCMS", len(fields[0])); err != nil {
		return nil, err
	}

	return fields[0], nil
}

func (c *Operation) GetTimeFromSig(data []byte, flags ckalkan.Flag, signerID int) (time.Time, error) {
	der, err := c.inputBytes(data, flags)
	if err != nil {
		return time.Time{}, err
	}

	fields, err := c.call("GetTimeFromSig", 13, 1, der, []byte(strconv.Itoa(signerID)))
	if err != nil {
		return time.Time{}, err
	}

	millis, err := strconv.ParseInt(string(fields[0]), 10, 64)
	if err != nil {
		return time.Time{}, c.fail(fmt.Errorf("invalid timestamp response: %w", err))
	}

	return time.UnixMilli(millis).UTC(), nil
}

func (c *Operation) X509LoadCertificateFromFile(path string, role ckalkan.CertType) error {
	data, err := c.readFile(path)
	if err != nil {
		return err
	}

	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		data, err = decodeSinglePEM(data)
		if err != nil {
			return err
		}
	}

	_, err = c.call("LoadTrustedCertificate", 7, 0, data, []byte(strconv.Itoa(int(role))))

	return err
}

func (c *Operation) X509LoadCertificateFromBuffer(data []byte, format ckalkan.CertFormat) error {
	der, err := decodeCertificate(data, format)
	if err != nil {
		return err
	}

	_, err = c.call("LoadTrustedCertificate", 7, 0, der, []byte("0"))

	return err
}

func (c *Operation) X509ExportCertificateFromStore(alias string, format ckalkan.CertFormat) ([]byte, error) {
	fields, err := c.call("ExportCertificate", 8, 1, []byte(alias))
	if err != nil {
		return nil, err
	}

	var out []byte

	switch format {
	case ckalkan.CertDER:
		out = fields[0]
	case ckalkan.CertPEM:
		out = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fields[0]})
	case ckalkan.CertB64:
		if err := c.checkOutputSize("ExportCertificate", base64.StdEncoding.EncodedLen(len(fields[0]))); err != nil {
			return nil, err
		}

		out = base64.StdEncoding.AppendEncode(nil, fields[0])
	default:
		return nil, fmt.Errorf("%w: certificate output format", ErrInvalidInput)
	}

	if err := c.checkOutputSize("ExportCertificate", len(out)); err != nil {
		return nil, err
	}

	return out, nil
}

func (c *Operation) X509ValidateCertificate(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
	var result ckalkan.ValidateCertificateResult
	if req.CheckTimeUnix != 0 && req.ValidationType == ckalkan.UseOCSP {
		return result, unsupported("historical OCSP validation requires archived evidence")
	}

	mode := "none"

	switch req.ValidationType {
	case ckalkan.UseOCSP:
		mode = "ocsp"
	case ckalkan.UseCRL:
		mode = "crl"
	case ckalkan.UseNothing:
	default:
		return result, fmt.Errorf("%w: certificate validation mode", ErrInvalidInput)
	}

	source, local, err := c.revocationSource(mode, req.ValidationPath)
	if err != nil {
		return result, err
	}

	cert := req.Certificate
	if bytes.HasPrefix(bytes.TrimSpace(cert), []byte("-----BEGIN")) {
		cert, err = decodeSinglePEM(cert)
		if err != nil {
			return result, err
		}
	}

	fields, err := c.call("ValidateCertificate", 11, 2, cert, []byte(mode), []byte(source), local,
		encodeFlag(req.Flags, ckalkan.NoCheckCertTime), []byte(strconv.FormatInt(req.CheckTimeUnix, 10)), encodeFlag(req.Flags, ckalkan.GetOCSPResponse))
	if err != nil {
		return result, err
	}

	for _, field := range fields {
		if err := c.checkOutputSize("ValidateCertificate", len(field)); err != nil {
			return result, err
		}
	}

	result.Info, result.OCSPResponse = string(fields[0]), fields[1]

	return result, nil
}

func decodeCertificate(data []byte, format ckalkan.CertFormat) ([]byte, error) {
	switch format {
	case ckalkan.CertDER:
		return data, nil
	case ckalkan.CertPEM:
		return decodeSinglePEM(data)
	case ckalkan.CertB64:
		der, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("%w: certificate base64: %w", ErrInvalidInput, err)
		}

		return der, nil
	default:
		return nil, fmt.Errorf("%w: certificate input format", ErrInvalidInput)
	}
}

func (c *Operation) inputBytes(data []byte, flags ckalkan.Flag) ([]byte, error) {
	var err error
	if flags&ckalkan.InFile != 0 {
		data, err = c.readFile(string(data))
		if err != nil {
			return nil, err
		}
	}

	if flags&ckalkan.InBase64 != 0 {
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("%w: input base64: %w", ErrInvalidInput, err)
		}
	} else if flags&ckalkan.InPEM != 0 {
		data, err = decodeSinglePEM(data)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

func decodeSinglePEM(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)

	block, rest := pem.Decode(data)
	// Require one complete PEM block because pem.Decode can skip malformed blocks.
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) || bytes.Contains(data, []byte("\n-----BEGIN ")) || block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: expected a single PEM block", ErrInvalidInput)
	}

	return block.Bytes, nil
}

func (c *Operation) outputBytes(operation string, data []byte, flags ckalkan.Flag) ([]byte, error) {
	if flags&ckalkan.OutBase64 != 0 {
		if err := c.checkOutputSize(operation, base64.StdEncoding.EncodedLen(len(data))); err != nil {
			return nil, err
		}

		data = base64.StdEncoding.AppendEncode(nil, data)
	} else if flags&ckalkan.OutPEM != 0 {
		data = pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: data})
	}

	if err := c.checkOutputSize(operation, len(data)); err != nil {
		return nil, err
	}

	return data, nil
}

func (c *Operation) checkOutputSize(operation string, size int) error {
	limit := c.cfg.MaxOutputSize
	if limit < 0 || size < 0 {
		return fmt.Errorf("%w: invalid output size", ErrInvalidInput)
	}

	if size > limit {
		return &ckalkan.OutputBufferLimitError{Operation: operation, Requested: uint64(size), Limit: uint64(limit)}
	}

	return nil
}
