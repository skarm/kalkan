package isolated

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
)

type recordingClient struct {
	t         *testing.T
	operation string
	request   any
	context   context.Context
	result    any
	err       error
	calls     int
}

func record[Result any](client *recordingClient, ctx context.Context, operation string, request any) (Result, error) {
	client.t.Helper()
	client.operation, client.request, client.context = operation, request, ctx
	client.calls++
	var zero Result
	if client.result == nil {
		return zero, client.err
	}
	result, ok := client.result.(Result)
	if !ok {
		client.t.Fatalf("fake result has incorrect type for %s", operation)
	}
	return result, client.err
}

func (c *recordingClient) Hash(ctx context.Context, req kalkan.HashRequest) (*kalkan.Digest, error) {
	return record[*kalkan.Digest](c, ctx, "Hash", req)
}

func (c *recordingClient) SignHash(ctx context.Context, req kalkan.SignHashRequest) (*kalkan.CMS, error) {
	return record[*kalkan.CMS](c, ctx, "SignHash", req)
}

func (c *recordingClient) SignCMS(ctx context.Context, req kalkan.SignCMSRequest) (*kalkan.CMS, error) {
	return record[*kalkan.CMS](c, ctx, "SignCMS", req)
}

func (c *recordingClient) VerifyCMS(ctx context.Context, req kalkan.VerifyCMSRequest) (*kalkan.Verification, error) {
	return record[*kalkan.Verification](c, ctx, "VerifyCMS", req)
}

func (c *recordingClient) SignXML(ctx context.Context, req kalkan.SignXMLRequest) (*kalkan.SignedXML, error) {
	return record[*kalkan.SignedXML](c, ctx, "SignXML", req)
}

func (c *recordingClient) VerifyXML(ctx context.Context, req kalkan.VerifyXMLRequest) (*kalkan.Verification, error) {
	return record[*kalkan.Verification](c, ctx, "VerifyXML", req)
}

func (c *recordingClient) SignWSSE(ctx context.Context, req kalkan.SignWSSERequest) (*kalkan.SignedXML, error) {
	return record[*kalkan.SignedXML](c, ctx, "SignWSSE", req)
}

func (c *recordingClient) ValidateCertificate(ctx context.Context, req kalkan.ValidateCertificateRequest) (*kalkan.CertificateValidation, error) {
	return record[*kalkan.CertificateValidation](c, ctx, "ValidateCertificate", req)
}

func (c *recordingClient) LoadKeyStore(ctx context.Context, req kalkan.KeyStore) error {
	_, err := record[any](c, ctx, "LoadKeyStore", req)
	return err
}

func (c *recordingClient) LoadTrustedCertificate(ctx context.Context, req kalkan.TrustedCertificate) error {
	_, err := record[any](c, ctx, "LoadTrustedCertificate", req)
	return err
}

func (c *recordingClient) SetProxy(ctx context.Context, req kalkan.Proxy) error {
	_, err := record[any](c, ctx, "SetProxy", req)
	return err
}

func (c *recordingClient) SignZIP(ctx context.Context, req kalkan.SignZIPRequest) (*kalkan.SignedZIP, error) {
	return record[*kalkan.SignedZIP](c, ctx, "SignZIP", req)
}

func (c *recordingClient) VerifyZIP(ctx context.Context, req kalkan.VerifyZIPRequest) (*kalkan.Verification, error) {
	return record[*kalkan.Verification](c, ctx, "VerifyZIP", req)
}

func (c *recordingClient) ExtractZIPSignerCertificate(ctx context.Context, req kalkan.ExtractZIPSignerCertificateRequest) ([]byte, error) {
	return record[[]byte](c, ctx, "ExtractZIPSignerCertificate", req)
}

func (c *recordingClient) X509ExportCertificateFromStore(ctx context.Context) (*x509.Certificate, error) {
	return record[*x509.Certificate](c, ctx, "X509ExportCertificateFromStore", nil)
}

func (c *recordingClient) X509CertificateGetInfo(ctx context.Context, req *x509.Certificate) (*kalkan.CertificateInfo, error) {
	return record[*kalkan.CertificateInfo](c, ctx, "X509CertificateGetInfo", req)
}

func (c *recordingClient) X509CertificateGetInfoFields(ctx context.Context, req *x509.Certificate, fields kalkan.CertificateInfoField) (*kalkan.CertificateInfo, error) {
	return record[*kalkan.CertificateInfo](c, ctx, "X509CertificateGetInfoFields", certificateInfoFieldsRequest{Certificate: req, Fields: fields})
}

func (c *recordingClient) GetCertFromCMS(ctx context.Context, req kalkan.Source) ([]*x509.Certificate, error) {
	return record[[]*x509.Certificate](c, ctx, "GetCertFromCMS", req)
}

func (c *recordingClient) GetCertFromXML(ctx context.Context, req kalkan.Source) ([]*x509.Certificate, error) {
	return record[[]*x509.Certificate](c, ctx, "GetCertFromXML", req)
}

func (c *recordingClient) GetTimeFromSig(ctx context.Context, req kalkan.Source) (time.Time, error) {
	return record[time.Time](c, ctx, "GetTimeFromSig", req)
}

func (c *recordingClient) GetSigAlgFromXML(ctx context.Context, req kalkan.Source) (string, error) {
	return record[string](c, ctx, "GetSigAlgFromXML", req)
}

func TestOperationsPreserveRequestsAndResponses(t *testing.T) {
	ctx := t.Context()
	instant := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	certificate := &x509.Certificate{Raw: []byte("certificate DER")}
	verification := &kalkan.Verification{Info: "verified", Data: []byte{1, 0, 2}, SignerCert: []byte("certificate")}
	for _, tc := range []struct {
		operation string
		request   any
		result    any
		wire      any
	}{
		{"Hash", kalkan.HashRequest{Algorithm: kalkan.GOST2015_512, Data: kalkan.File("document.bin").WithEncoding(kalkan.EncodingAuto)}, &kalkan.Digest{Algorithm: kalkan.GOST2015_512, Data: []byte{1, 2}}, &kalkan.Digest{Algorithm: kalkan.GOST2015_512, Data: []byte{1, 2}}},
		{"SignHash", kalkan.SignHashRequest{Alias: "alias", Digest: []byte{3, 0, 4}, DigestAlgorithm: kalkan.GOST2015_256, Timestamp: true, IncludeCertificate: true, OutputFormat: kalkan.CMSOutputPEM, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, &kalkan.CMS{Data: []byte("CMS")}, &kalkan.CMS{Data: []byte("CMS")}},
		{"SignCMS", kalkan.SignCMSRequest{Alias: "alias", Data: kalkan.Base64([]byte("AQID")), ExistingSignature: kalkan.DER([]byte{0, 1, 255}), Detached: true, Timestamp: true, IncludeCertificate: true, OutputFormat: kalkan.CMSOutputBase64, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, &kalkan.CMS{Data: []byte("CMS")}, &kalkan.CMS{Data: []byte("CMS")}},
		{"VerifyCMS", kalkan.VerifyCMSRequest{Alias: "alias", Signature: kalkan.File("signed.cms").WithEncoding(kalkan.EncodingPEM), Data: kalkan.Bytes(nil), Detached: true, Encoding: kalkan.EncodingDER, SignerID: 7, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, verification, verification},
		{"SignXML", kalkan.SignXMLRequest{Alias: "alias", XML: kalkan.Bytes([]byte("<root/>")), SignNodeID: "node", ParentSignNode: "root", ParentNamespace: "urn:root", Canonicalization: kalkan.XMLCanonicalizationExclusiveWithComments, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, &kalkan.SignedXML{XML: []byte("<signed/>")}, &kalkan.SignedXML{XML: []byte("<signed/>")}},
		{"VerifyXML", kalkan.VerifyXMLRequest{Alias: "alias", XML: kalkan.Bytes([]byte("<signed/>")), ExpectedBodyID: "body", Canonicalization: kalkan.XMLCanonicalizationInclusive11, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, verification, verification},
		{"SignWSSE", kalkan.SignWSSERequest{Alias: "alias", XML: kalkan.Bytes([]byte("<payload/>")), BodyID: "body", WrapSOAP: true, Canonicalization: kalkan.XMLCanonicalizationExclusive, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, &kalkan.SignedXML{XML: []byte("<soap/>")}, &kalkan.SignedXML{XML: []byte("<soap/>")}},
		{"ValidateCertificate", kalkan.ValidateCertificateRequest{Certificate: kalkan.DER([]byte{1, 0, 255}), Mode: kalkan.CertificateValidationOCSP, RevocationSource: "https://ocsp.example", CheckTime: instant, ReturnOCSPResponse: true, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, &kalkan.CertificateValidation{Info: "valid", OCSPResponse: []byte("OCSP")}, &kalkan.CertificateValidation{Info: "valid", OCSPResponse: []byte("OCSP")}},
		{"LoadKeyStore", kalkan.KeyStore{Type: kalkan.PKCS12, Path: "fixture.p12", Password: "synthetic password", Alias: "alias"}, nil, nil},
		{"LoadTrustedCertificate", kalkan.TrustedCertificate{Data: []byte("DER"), Path: "root.cer", Type: kalkan.CertificateIntermediate, Format: kalkan.CertificateBase64}, nil, nil},
		{"SetProxy", kalkan.Proxy{Enabled: true, Address: "proxy.example", Port: "8080", User: "user", Password: "synthetic password"}, nil, nil},
		{"SignZIP", kalkan.SignZIPRequest{Alias: "alias", InputPath: "in.txt", OutputPath: "out.zip", CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, &kalkan.SignedZIP{Path: "out.zip"}, &kalkan.SignedZIP{Path: "out.zip"}},
		{"VerifyZIP", kalkan.VerifyZIPRequest{Path: "signed.zip", CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, verification, verification},
		{"ExtractZIPSignerCertificate", kalkan.ExtractZIPSignerCertificateRequest{Path: "signed.zip", SignerID: 5, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}, []byte("DER"), []byte("DER")},
		{"X509ExportCertificateFromStore", nil, certificate, certificate.Raw},
		{"X509CertificateGetInfo", certificate, &kalkan.CertificateInfo{Subject: "subject", ValidFrom: instant}, &kalkan.CertificateInfo{Subject: "subject", ValidFrom: instant}},
		{"X509CertificateGetInfoFields", certificateInfoFieldsRequest{Certificate: certificate, Fields: kalkan.CertificateInfoIssuer | kalkan.CertificateInfoSerialNumber}, &kalkan.CertificateInfo{Issuer: "issuer", SerialNumber: "serial"}, &kalkan.CertificateInfo{Issuer: "issuer", SerialNumber: "serial"}},
		{"GetCertFromCMS", kalkan.PEM([]byte("CMS")), []*x509.Certificate{certificate, nil, certificate}, [][]byte{certificate.Raw, nil, certificate.Raw}},
		{"GetCertFromXML", kalkan.Bytes([]byte("<root/>")), []*x509.Certificate{certificate}, [][]byte{certificate.Raw}},
		{"GetTimeFromSig", kalkan.File("signed.cms").WithEncoding(kalkan.EncodingBase64), instant, instant},
		{"GetSigAlgFromXML", kalkan.Bytes([]byte("<root/>")), "urn:signature", "urn:signature"},
	} {
		for _, opaque := range []bool{false, true} {
			test := tc
			name := tc.operation
			if opaque {
				name += "/opaque strings"
				test.request = opaqueValue(test.request)
				test.result = opaqueValue(test.result)
				test.wire = opaqueValue(test.wire)
			}
			t.Run(name, func(t *testing.T) {
				tc := test
				payload, err := encodeRequest(tc.operation, tc.request, 0)
				if err != nil {
					t.Fatal(err)
				}
				payload = roundTripPayload(t, payload)
				client := &recordingClient{t: t, result: tc.result}
				response, err := dispatch(ctx, client, tc.operation, payload)
				if err != nil {
					t.Fatal(err)
				}
				if client.calls != 1 || client.operation != tc.operation || client.context != ctx {
					t.Fatalf("dispatch = %s with %d calls and matching context %t", client.operation, client.calls, client.context == ctx)
				}
				if !reflect.DeepEqual(client.request, tc.request) {
					t.Fatalf("%s request changed during transport", tc.operation)
				}
				var destination any
				if tc.wire == nil {
					var decoded any
					destination = &decoded
				} else {
					destination = reflect.New(reflect.TypeOf(tc.wire)).Interface()
				}
				if err := decodeResult(tc.operation, roundTripPayload(t, response), destination); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(reflect.ValueOf(destination).Elem().Interface(), tc.wire) {
					t.Fatalf("%s result changed during transport", tc.operation)
				}
			})
		}
	}
}

func TestBinarySourcePreservesPresenceAndEncoding(t *testing.T) {
	for _, source := range []kalkan.Source{
		{},
		(kalkan.Source{}).WithEncoding(kalkan.EncodingPEM),
		kalkan.Bytes(nil), kalkan.Bytes([]byte{}), kalkan.Bytes([]byte{0, 128, 255}),
		kalkan.DER([]byte{0, 128, 255}), kalkan.PEM([]byte("PEM")), kalkan.Base64([]byte("AA==")),
		kalkan.File(""), kalkan.File("document").WithEncoding(kalkan.EncodingRaw),
		kalkan.File("document").WithEncoding(kalkan.Encoding(99)),
	} {
		request := kalkan.HashRequest{Data: source}
		payload, err := encodeRequest("Hash", request, 0)
		if err != nil {
			t.Fatal(err)
		}
		client := &recordingClient{t: t}
		if _, err := dispatch(context.Background(), client, "Hash", payload); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(client.request, request) {
			t.Fatalf("source presence or encoding changed: %#v", source.Describe())
		}
	}
}

func TestCertificateInfoTransportsOnlyRawAndPreservesNil(t *testing.T) {
	for _, certificate := range []*x509.Certificate{nil, {}, {Raw: []byte("invalid DER"), DNSNames: []string{"ignored.example"}}} {
		payload, err := encodeRequest("X509CertificateGetInfo", certificate, 0)
		if err != nil {
			t.Fatal(err)
		}
		client := &recordingClient{t: t}
		if _, err := dispatch(context.Background(), client, "X509CertificateGetInfo", payload); err != nil {
			t.Fatal(err)
		}
		var want *x509.Certificate
		if certificate != nil {
			want = &x509.Certificate{Raw: certificate.Raw}
		}
		if !reflect.DeepEqual(client.request, want) {
			t.Fatal("certificate nil state or raw DER changed before native validation")
		}
	}
}

func TestDispatchRejectsMalformedRequestsAndPreservesOperationErrors(t *testing.T) {
	valid, err := encodeRequest("Hash", kalkan.HashRequest{Data: kalkan.Bytes([]byte("data"))}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(valid.metadata); length++ {
		client := &recordingClient{t: t}
		payload := wirePayload{metadata: valid.metadata[:length], blocks: valid.blocks}
		if _, err := dispatch(context.Background(), client, "Hash", payload); !errors.Is(err, ErrProtocol) || client.calls != 0 {
			t.Fatalf("truncated at %d: error = %v, calls = %d", length, err, client.calls)
		}
	}
	for _, tc := range []struct {
		operation string
		payload   wirePayload
	}{
		{"Unknown", nullPayload()},
		{"Hash", wirePayload{metadata: valid.metadata}}, // Reference to a missing block.
		{"Hash", wirePayload{metadata: append(bytes.Clone(valid.metadata), 0), blocks: valid.blocks}},
		{"SetProxy", wirePayload{metadata: []byte{255}}}, // Invalid boolean.
		{"X509ExportCertificateFromStore", wirePayload{metadata: []byte{0}}},
	} {
		client := &recordingClient{t: t}
		if _, err := dispatch(context.Background(), client, tc.operation, tc.payload); !errors.Is(err, ErrProtocol) || client.calls != 0 {
			t.Fatalf("invalid request: error = %v, calls = %d", err, client.calls)
		}
	}
	if _, err := encodeRequest("Hash", "wrong type", 0); !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("incorrect request type error = %v, want ErrInvalidInput", err)
	}
	failure := &ckalkan.KalkanError{Code: ckalkan.ErrorSignInvalid, Message: "synthetic native error"}
	client := &recordingClient{t: t, err: failure}
	payload, err := encodeRequest("Hash", kalkan.HashRequest{Data: kalkan.Bytes([]byte("payload"))}, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatch(context.Background(), client, "Hash", payload)
	if !errors.Is(err, failure) || len(result.metadata) != 0 || client.calls != 1 {
		t.Fatalf("operation failure changed: result = %+v, error = %v, calls = %d", result, err, client.calls)
	}
}

func TestDispatchRejectsInconsistentSourceDescriptors(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		path string
		file bool
		set  bool
	}{
		{"file with bytes", []byte("ignored"), "input.xml", true, true},
		{"file with empty bytes", []byte{}, "input.xml", true, true},
		{"bytes with path", []byte("<root/>"), "ignored.xml", false, true},
		{"absent bytes", []byte("ignored"), "", false, false},
		{"absent empty bytes", []byte{}, "", false, false},
		{"absent path", nil, "ignored.xml", false, false},
		{"absent file", nil, "", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := payloadEncoder{}
			e.bytes(test.data)
			e.text(test.path)
			e.integer(int(kalkan.EncodingRaw))
			e.boolean(test.file)
			e.boolean(test.set)
			payload, err := e.finish()
			if err != nil {
				t.Fatal(err)
			}
			client := &recordingClient{t: t}
			_, err = dispatch(t.Context(), client, opGetCertFromXML, roundTripPayload(t, payload))
			if !errors.Is(err, ErrProtocol) || client.calls != 0 {
				t.Fatalf("inconsistent source: error=%v, SDK calls=%d", err, client.calls)
			}
		})
	}
}

func TestDecodeResultRejectsMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		operation string
		out       any
	}{
		{"Hash", new(*kalkan.Digest)},
		{"VerifyCMS", new(*kalkan.Verification)},
		{"ValidateCertificate", new(*kalkan.CertificateValidation)},
		{"SignZIP", new(*kalkan.SignedZIP)},
		{"X509CertificateGetInfo", new(*kalkan.CertificateInfo)},
		{"X509CertificateGetInfoFields", new(*kalkan.CertificateInfo)},
		{"GetTimeFromSig", new(time.Time)},
		{"GetSigAlgFromXML", new(string)},
		{"GetCertFromCMS", new([][]byte)},
		{"LoadKeyStore", new(any)},
		{"Unknown", new(any)},
		{"SignZIP", new(string)},
	} {
		if err := decodeResult(tc.operation, wirePayload{metadata: []byte{255}}, tc.out); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%s malformed response error = %v, want ErrProtocol", tc.operation, err)
		}
	}
	e := payloadEncoder{}
	e.timestamp(time.Unix(1, 2).UTC())
	payload, err := e.finish()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(payload.metadata[9:17], 1_000_000_000)
	if err := decodeResult("GetTimeFromSig", payload, new(time.Time)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("out-of-range nanoseconds: %v", err)
	}
	payload, err = encodeResult(&kalkan.Digest{Data: []byte("digest")})
	if err != nil {
		t.Fatal(err)
	}
	payload.blocks = nil
	if err := decodeResult("Hash", payload, new(*kalkan.Digest)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing result block: %v", err)
	}
}

func TestDecodeResultPreservesNilAndEmptyValues(t *testing.T) {
	for _, tc := range []struct {
		operation string
		out       any
	}{
		{"Hash", new(*kalkan.Digest)},
		{"VerifyCMS", new(*kalkan.Verification)},
		{"ValidateCertificate", new(*kalkan.CertificateValidation)},
		{"SignZIP", new(*kalkan.SignedZIP)},
		{"X509CertificateGetInfo", new(*kalkan.CertificateInfo)},
		{"GetCertFromCMS", new([][]byte)},
		{"X509ExportCertificateFromStore", new([]byte)},
	} {
		payload, err := encodeResult(reflect.Zero(reflect.TypeOf(tc.out).Elem()).Interface())
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeResult(tc.operation, payload, tc.out); err != nil {
			t.Fatalf("%s nil result: %v", tc.operation, err)
		}
		if !reflect.ValueOf(tc.out).Elem().IsNil() {
			t.Fatalf("%s nil result became non-nil", tc.operation)
		}
	}
	var algorithm string
	emptyString, err := encodeResult("")
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeResult("GetSigAlgFromXML", emptyString, &algorithm); err != nil || algorithm != "" {
		t.Fatalf("empty algorithm = %q, error = %v", algorithm, err)
	}
	var certificates [][]byte
	emptyCertificates, err := encodeResult([][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeResult("GetCertFromCMS", emptyCertificates, &certificates); err != nil || certificates == nil || len(certificates) != 0 {
		t.Fatalf("empty certificate list = %#v, error = %v", certificates, err)
	}
}

func TestBinaryTimePreservesNativeTimestampSemantics(t *testing.T) {
	for _, instant := range []time.Time{
		{},
		time.Unix(0, 123456789).UTC(),
		time.Date(2024, 1, 2, 3, 4, 5, 987654321, time.FixedZone("seconds", 1)),
		time.Date(10000, 1, 2, 3, 4, 5, 123456789, time.FixedZone("future\xff", -61)),
		time.Date(2024, 1, 2, 3, 4, 5, 456789123, time.FixedZone("large offset", 3_000_000)),
	} {
		request := kalkan.ValidateCertificateRequest{Certificate: kalkan.DER([]byte("DER")), CheckTime: instant}
		payload, err := encodeRequest("ValidateCertificate", request, 0)
		if err != nil {
			t.Fatalf("encode CheckTime: %v", err)
		}
		client := &recordingClient{t: t}
		if _, err := dispatch(context.Background(), client, "ValidateCertificate", payload); err != nil {
			t.Fatal(err)
		}
		received, ok := client.request.(kalkan.ValidateCertificateRequest)
		if !ok {
			t.Fatal("wrong validation request type")
		}
		requireSameTime(t, received.CheckTime, instant)

		for _, operation := range []string{"GetTimeFromSig", "X509CertificateGetInfo", "X509CertificateGetInfoFields"} {
			var request, result, out any
			var timestamp time.Time
			var info *kalkan.CertificateInfo
			switch operation {
			case "GetTimeFromSig":
				request, result, out = kalkan.DER([]byte("CMS")), instant, &timestamp
			case "X509CertificateGetInfo":
				request = (*x509.Certificate)(nil)
				result, out = &kalkan.CertificateInfo{ValidFrom: instant, ValidUntil: instant}, &info
			case "X509CertificateGetInfoFields":
				request = certificateInfoFieldsRequest{Fields: kalkan.CertificateInfoValidFrom | kalkan.CertificateInfoValidUntil}
				result, out = &kalkan.CertificateInfo{ValidFrom: instant, ValidUntil: instant}, &info
			}
			payload, err := encodeRequest(operation, request, 0)
			if err != nil {
				t.Fatal(err)
			}
			client := &recordingClient{t: t, result: result}
			response, err := dispatch(context.Background(), client, operation, payload)
			if err != nil {
				t.Fatalf("encode %s timestamp: %v", operation, err)
			}
			if err := decodeResult(operation, response, out); err != nil {
				t.Fatal(err)
			}
			if info != nil {
				requireSameTime(t, info.ValidFrom, instant)
				requireSameTime(t, info.ValidUntil, instant)
			} else {
				requireSameTime(t, timestamp, instant)
			}
		}
	}
}

func requireSameTime(t *testing.T, actual, expected time.Time) {
	t.Helper()
	if !actual.Equal(expected) || actual.Unix() != expected.Unix() || actual.Nanosecond() != expected.Nanosecond() || actual.IsZero() != expected.IsZero() {
		t.Fatalf("timestamp changed: got %v, want %v", actual, expected)
	}
	actualZone, actualOffset := actual.Zone()
	expectedZone, expectedOffset := expected.Zone()
	if actualZone != expectedZone || actualOffset != expectedOffset {
		t.Fatalf("timestamp zone changed: got %q/%d, want %q/%d", actualZone, actualOffset, expectedZone, expectedOffset)
	}
}

// opaqueValue changes every public string slot, including currently empty
// fields, so new request/result string fields cannot silently bypass the codec.
func opaqueValue(input any) any {
	if input == nil {
		return nil
	}
	return opaqueReflect(reflect.ValueOf(input)).Interface()
}

func opaqueReflect(input reflect.Value) reflect.Value {
	const suffix = "\xff\x80"
	if input.CanInterface() {
		switch value := input.Interface().(type) {
		case kalkan.Source:
			description := value.Describe()
			if description.File {
				return reflect.ValueOf(kalkan.File(description.Path + suffix).WithEncoding(description.Encoding))
			}
			return input
		case *x509.Certificate:
			if value == nil {
				return input
			}
			return reflect.ValueOf(&x509.Certificate{Raw: value.Raw})
		}
	}
	output := reflect.New(input.Type()).Elem()
	output.Set(input)
	switch input.Kind() {
	case reflect.String:
		output.SetString(input.String() + suffix)
	case reflect.Pointer:
		if !input.IsNil() {
			output = reflect.New(input.Type().Elem())
			output.Elem().Set(opaqueReflect(input.Elem()))
		}
	case reflect.Struct:
		for i := 0; i < input.NumField(); i++ {
			if input.Type().Field(i).PkgPath == "" {
				output.Field(i).Set(opaqueReflect(input.Field(i)))
			}
		}
	case reflect.Slice:
		if input.Type().Elem().Kind() == reflect.String {
			output = reflect.MakeSlice(input.Type(), max(input.Len(), 1), max(input.Len(), 1))
			for i := 0; i < output.Len(); i++ {
				if i < input.Len() {
					output.Index(i).Set(opaqueReflect(input.Index(i)))
				} else {
					output.Index(i).SetString(suffix)
				}
			}
		}
	}
	return output
}

func TestBinaryRequestIntegersPreserveTheirFullRange(t *testing.T) {
	for _, test := range []struct {
		operation string
		request   any
	}{
		{"Hash", kalkan.HashRequest{Algorithm: kalkan.HashAlgorithm(math.MinInt)}},
		{"ExtractZIPSignerCertificate", kalkan.ExtractZIPSignerCertificateRequest{SignerID: math.MaxInt}},
		{"X509CertificateGetInfoFields", certificateInfoFieldsRequest{Fields: kalkan.CertificateInfoField(^uint64(0))}},
	} {
		payload, err := encodeRequest(test.operation, test.request, 0)
		if err != nil {
			t.Fatal(err)
		}
		client := &recordingClient{t: t}
		if _, err := dispatch(t.Context(), client, test.operation, roundTripPayload(t, payload)); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(client.request, test.request) {
			t.Fatalf("%s integer changed before SDK validation", test.operation)
		}
	}
}
