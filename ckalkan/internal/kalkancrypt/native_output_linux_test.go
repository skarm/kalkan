//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

const (
	kcrBufferTooSmall         = 0x08f00005
	largeNativeOutputCapacity = 1 << 20
)

func TestNativeSingleOutputBufferBoundaries(t *testing.T) {
	ctx := openContext(t)
	assets := loadFixtureAssets(t)
	loadCertificates(t, ctx, assets)
	loadPKCS12Fixture(t, ctx)

	data := []byte("kalkancrypt output-buffer boundary test")
	digest := make([]byte, 64)
	for i := range digest {
		digest[i] = byte(i)
	}

	certificateResult, err := ctx.X509ExportCertificateFromStore("", certPEM, largeNativeOutputCapacity)
	certificate := requireBufferOK(t, "X509ExportCertificateFromStore setup", certificateResult, err)
	xml := readExample(t, assets, "test_xml")
	signedXMLResult, err := ctx.SignXML(kalkancrypt.SignXMLCall{
		Flags:    xmlInclC14N | noCheckCertTime,
		XML:      xml,
		Capacity: largeNativeOutputCapacity,
	})
	signedXML := requireBufferOK(t, "SignXML setup", signedXMLResult, err)
	wsse := readExample(t, assets, "test_wsse")
	zipPath := copyZIPFixture(t, zipFixtures(t, assets)[0])
	dataPath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatalf("write native boundary input %q: %v", dataPath, err)
	}

	tests := []struct {
		name string
		call func(int) (kalkancrypt.BufferResult, error)
	}{
		{name: "HashData", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.HashData(kalkancrypt.HashDataCall{
				Algorithm: "sha256", Data: []byte("abc"), Capacity: capacity,
			})
		}},
		{name: "X509ExportCertificateFromStore", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.X509ExportCertificateFromStore("", certPEM, capacity)
		}},
		{name: "X509CertificateGetInfo", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.X509CertificateGetInfo(certificate, certPropSubjectCommonName, capacity)
		}},
		{name: "SignHash", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.SignHash(kalkancrypt.SignHashCall{
				Flags:    signCMS | outBase64 | noCheckCertTime,
				Hash:     digest,
				Capacity: capacity,
			})
		}},
		{name: "SignData", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.SignData(kalkancrypt.SignDataCall{
				Flags:    signCMS | outBase64 | noCheckCertTime,
				Data:     data,
				Capacity: capacity,
			})
		}},
		{name: "SignData/InFile", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.SignData(kalkancrypt.SignDataCall{
				Flags:    signCMS | inFile | outBase64 | noCheckCertTime,
				Data:     []byte(dataPath),
				Capacity: capacity,
			})
		}},
		{name: "SignXML", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.SignXML(kalkancrypt.SignXMLCall{
				Flags: xmlInclC14N | noCheckCertTime, XML: xml, Capacity: capacity,
			})
		}},
		{name: "SignWSSE", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.SignWSSE(kalkancrypt.SignWSSECall{
				Flags: uint64(xmlInclC14N | noCheckCertTime), XML: wsse, SignNodeID: "TheBody", Capacity: capacity,
			})
		}},
		{name: "GetCertFromXML", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.GetCertFromXML(signedXML, 0, capacity)
		}},
		{name: "GetSigAlgFromXML", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.GetSigAlgFromXML(signedXML, capacity)
		}},
		{name: "ZipConVerify", call: func(capacity int) (kalkancrypt.BufferResult, error) {
			return ctx.ZipConVerify(zipPath, noCheckCertTime, capacity)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertNativeSingleOutputBuffer(t, test.call)
		})
	}
}

func assertNativeSingleOutputBuffer(t *testing.T, call func(int) (kalkancrypt.BufferResult, error)) {
	t.Helper()

	baseline, err := call(largeNativeOutputCapacity)
	if err != nil {
		t.Fatalf("baseline returned Go error: %v", err)
	}
	if baseline.Code != kcrOK {
		t.Fatalf("baseline code=%#x, want %#x", baseline.Code, kcrOK)
	}
	if baseline.OutLen <= 1 || baseline.OutLen != len(baseline.Data) || cap(baseline.Data) != len(baseline.Data) {
		t.Fatalf("baseline OutLen=%d dataLen=%d dataCap=%d, want equal lengths/capacity greater than 1",
			baseline.OutLen, len(baseline.Data), cap(baseline.Data))
	}

	required := baseline.OutLen
	// Signing outputs are not guaranteed to be byte-for-byte deterministic
	// between calls. Equal OutLen, len, and cap are the buffer invariants here.
	for _, capacity := range []int{required, required + 1, required * 2} {
		result, err := call(capacity)
		if err != nil {
			t.Fatalf("capacity %d returned Go error: %v", capacity, err)
		}
		if result.Code != kcrOK || result.OutLen != required || len(result.Data) != required || cap(result.Data) != required {
			t.Fatalf("capacity %d returned code=%#x OutLen=%d dataLen=%d dataCap=%d; want code=%#x and length/capacity=%d",
				capacity, result.Code, result.OutLen, len(result.Data), cap(result.Data), kcrOK, required)
		}
	}

	shortCapacities := []int{1}
	if required-1 != 1 {
		shortCapacities = append(shortCapacities, required-1)
	}
	for _, capacity := range shortCapacities {
		short, err := call(capacity)
		if err != nil {
			t.Fatalf("capacity %d returned Go error: %v", capacity, err)
		}
		switch short.Code {
		case kcrBufferTooSmall:
			// The status itself is a sufficient retry signal; some SDK methods
			// additionally replace OutLen with the required size.
		case kcrOK:
			if short.OutLen <= capacity {
				t.Fatalf("capacity %d returned KCR_OK with OutLen=%d, no retry signal", capacity, short.OutLen)
			}
		default:
			t.Fatalf("capacity %d returned unexpected code=%#x OutLen=%d", capacity, short.Code, short.OutLen)
		}
		if len(short.Data) > capacity || cap(short.Data) != len(short.Data) {
			t.Fatalf("capacity %d returned data len/cap=%d/%d", capacity, len(short.Data), cap(short.Data))
		}
	}
}

func TestNativeLastErrorOutputBufferBoundaries(t *testing.T) {
	ctx := openContext(t)
	call := func(capacity int) (kalkancrypt.BufferResult, error) {
		ctx.LoadKeyStore(kcstPKCS12, "bad-password", "/tmp/ckalkan-no-such-key.p12", "")
		return ctx.LastErrorString(capacity)
	}

	short, err := call(1)
	if err != nil {
		t.Fatalf("short call returned Go error: %v", err)
	}
	if short.Code != kcrBufferTooSmall || short.OutLen <= 1 {
		t.Fatalf("short call = code:%#x OutLen:%d, want KCR_BUFFER_TOO_SMALL and required length", short.Code, short.OutLen)
	}

	large, err := call(largeNativeOutputCapacity)
	if err != nil {
		t.Fatalf("large call returned Go error: %v", err)
	}
	if large.Code == kcrBufferTooSmall || large.OutLen <= 1 || large.OutLen != len(large.Data) || cap(large.Data) != len(large.Data) {
		t.Fatalf("large call = code:%#x OutLen:%d dataLen:%d dataCap:%d", large.Code, large.OutLen, len(large.Data), cap(large.Data))
	}
}

func TestNativeVerifyDataAttachedOutputBufferBoundary(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	data := []byte("kalkancrypt VerifyData output-buffer boundary test")
	signatureResult, err := ctx.SignData(kalkancrypt.SignDataCall{
		Flags:    signCMS | outBase64 | noCheckCertTime,
		Data:     data,
		Capacity: largeNativeOutputCapacity,
	})
	signature := requireBufferOK(t, "SignData setup", signatureResult, err)
	call := func(dataCapacity, infoCapacity int) kalkancrypt.VerifyResult {
		t.Helper()
		result, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
			Flags:        signCMS | inBase64 | noCheckCertTime,
			Data:         data,
			Signature:    signature,
			DataCapacity: dataCapacity,
			InfoCapacity: infoCapacity,
			CertCapacity: largeNativeOutputCapacity,
		})
		if err != nil {
			t.Fatalf("VerifyData returned Go error: %v", err)
		}
		return result
	}

	baseline := call(largeNativeOutputCapacity, largeNativeOutputCapacity)
	if baseline.Code != kcrOK || baseline.DataLen <= 1 || baseline.InfoLen <= 1 {
		t.Fatalf("baseline = code:%#x dataLen:%d infoLen:%d", baseline.Code, baseline.DataLen, baseline.InfoLen)
	}
	if !bytes.Equal(baseline.Data, data) {
		t.Fatalf("baseline data = %q, want %q", baseline.Data, data)
	}

	for _, test := range []struct {
		name     string
		capacity int
		wantLen  int
	}{
		{name: "one byte short", capacity: baseline.DataLen - 1, wantLen: baseline.DataLen - 1},
		{name: "exact", capacity: baseline.DataLen, wantLen: baseline.DataLen},
		{name: "one byte spare", capacity: baseline.DataLen + 1, wantLen: baseline.DataLen},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := call(test.capacity, largeNativeOutputCapacity)
			if result.Code != kcrOK || result.DataLen != test.wantLen || len(result.Data) != test.wantLen {
				t.Fatalf("capacity %d result = code:%#x DataLen:%d dataLen:%d; want code:%#x and length:%d",
					test.capacity, result.Code, result.DataLen, len(result.Data), kcrOK, test.wantLen)
			}
			if !bytes.Equal(result.Data, data[:test.wantLen]) {
				t.Fatalf("capacity %d data = %q, want prefix %q", test.capacity, result.Data, data[:test.wantLen])
			}
		})
	}

	infoShort := call(largeNativeOutputCapacity, baseline.InfoLen-1)
	if infoShort.Code != kcrBufferTooSmall && infoShort.InfoLen <= baseline.InfoLen-1 {
		t.Fatalf("undersized info result = code:%#x InfoLen:%d, no retry signal", infoShort.Code, infoShort.InfoLen)
	}
}

func TestNativeUVerifyDataAttachedFileOutputBufferBoundary(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	data := []byte("kalkancrypt UVerifyData output-buffer boundary test")
	signatureResult, err := ctx.SignData(kalkancrypt.SignDataCall{
		Flags:    signCMS | outBase64 | noCheckCertTime,
		Data:     data,
		Capacity: largeNativeOutputCapacity,
	})
	signature := requireBufferOK(t, "SignData setup", signatureResult, err)
	signaturePath := filepath.Join(t.TempDir(), "attached.cms")
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatalf("write attached CMS: %v", err)
	}

	call := func(dataCapacity, infoCapacity int) kalkancrypt.VerifyResult {
		t.Helper()
		result, err := ctx.UVerifyData(kalkancrypt.VerifyDataCall{
			Flags:        noCheckCertTime,
			Data:         data,
			Signature:    []byte(signaturePath),
			DataCapacity: dataCapacity,
			InfoCapacity: infoCapacity,
			CertCapacity: largeNativeOutputCapacity,
		})
		if err != nil {
			t.Fatalf("UVerifyData returned Go error: %v", err)
		}

		return result
	}

	baseline := call(largeNativeOutputCapacity, largeNativeOutputCapacity)
	if baseline.Code != kcrOK || !bytes.Equal(baseline.Data, data) || baseline.InfoLen <= 1 {
		t.Fatalf("baseline = code:%#x DataLen:%d InfoLen:%d data:%q",
			baseline.Code, baseline.DataLen, baseline.InfoLen, baseline.Data)
	}

	for _, test := range []struct {
		name     string
		capacity int
		wantLen  int
	}{
		{name: "one byte short", capacity: baseline.DataLen - 1, wantLen: baseline.DataLen - 1},
		{name: "exact", capacity: baseline.DataLen, wantLen: baseline.DataLen},
		{name: "one byte spare", capacity: baseline.DataLen + 1, wantLen: baseline.DataLen},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := call(test.capacity, largeNativeOutputCapacity)
			if result.Code != kcrOK || result.DataLen != test.wantLen || len(result.Data) != test.wantLen {
				t.Fatalf("capacity %d result = code:%#x DataLen:%d dataLen:%d; want code:%#x and length:%d",
					test.capacity, result.Code, result.DataLen, len(result.Data), kcrOK, test.wantLen)
			}
			if !bytes.Equal(result.Data, data[:test.wantLen]) {
				t.Fatalf("capacity %d data = %q, want prefix %q", test.capacity, result.Data, data[:test.wantLen])
			}
		})
	}

	infoShort := call(largeNativeOutputCapacity, baseline.InfoLen-1)
	if infoShort.Code != kcrBufferTooSmall && infoShort.InfoLen <= baseline.InfoLen-1 {
		t.Fatalf("undersized info result = code:%#x InfoLen:%d, no retry signal", infoShort.Code, infoShort.InfoLen)
	}
}

func TestNativeVerifyDataLeavesUnusedDataBufferUntouched(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)
	data := []byte("kalkancrypt detached output-buffer boundary test")

	for _, variant := range []struct {
		name        string
		signFlags   int
		verifyFlags int
	}{
		{
			name:        "detached CMS",
			signFlags:   signCMS | outBase64 | detachedData | noCheckCertTime,
			verifyFlags: signCMS | inBase64 | detachedData | noCheckCertTime,
		},
		{
			name:        "draft signature",
			signFlags:   signDraft | outBase64 | noCheckCertTime,
			verifyFlags: signDraft | inBase64 | noCheckCertTime,
		},
	} {
		t.Run(variant.name, func(t *testing.T) {
			signatureResult, err := ctx.SignData(kalkancrypt.SignDataCall{
				Flags:    variant.signFlags,
				Data:     data,
				Capacity: largeNativeOutputCapacity,
			})
			signature := requireBufferOK(t, "SignData setup", signatureResult, err)

			for _, capacity := range []int{1, len(data), len(data) + 1} {
				result, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
					Flags:        variant.verifyFlags,
					Data:         data,
					Signature:    signature,
					DataCapacity: capacity,
					InfoCapacity: largeNativeOutputCapacity,
					CertCapacity: largeNativeOutputCapacity,
				})
				if err != nil {
					t.Fatalf("capacity %d returned Go error: %v", capacity, err)
				}
				if result.Code != kcrOK || result.DataLen != capacity || len(result.Data) != capacity {
					t.Fatalf("capacity %d result = code:%#x DataLen:%d dataLen:%d; want code:%#x and supplied capacity",
						capacity, result.Code, result.DataLen, len(result.Data), kcrOK)
				}
				if !bytes.Equal(result.Data, make([]byte, capacity)) {
					t.Fatalf("capacity %d data buffer was unexpectedly populated: %x", capacity, result.Data)
				}
			}
		})
	}
}

func TestNativeVerifyDataClearsDataOutputForSignatureFile(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	data := []byte("kalkancrypt VerifyData InFile output-buffer test")
	signatureResult, err := ctx.SignData(kalkancrypt.SignDataCall{
		Flags:    signCMS | outBase64 | noCheckCertTime,
		Data:     data,
		Capacity: largeNativeOutputCapacity,
	})
	signature := requireBufferOK(t, "SignData setup", signatureResult, err)
	signaturePath := filepath.Join(t.TempDir(), "attached.cms")
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatalf("write attached CMS: %v", err)
	}

	for _, capacity := range []int{1, len(data), len(data) + 1} {
		result, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
			Flags:        signCMS | inBase64 | inFile | noCheckCertTime,
			Data:         data,
			Signature:    []byte(signaturePath),
			DataCapacity: capacity,
			InfoCapacity: largeNativeOutputCapacity,
			CertCapacity: largeNativeOutputCapacity,
		})
		if err != nil {
			t.Fatalf("capacity %d returned Go error: %v", capacity, err)
		}
		if result.Code != kcrOK || result.DataLen != 0 || len(result.Data) != 0 {
			t.Fatalf("capacity %d result = code:%#x DataLen:%d dataLen:%d; want code:%#x and empty data output",
				capacity, result.Code, result.DataLen, len(result.Data), kcrOK)
		}
		if !bytes.Contains(result.Info, []byte("Verify - OK")) {
			t.Fatalf("capacity %d info = %q, want Verify - OK", capacity, result.Info)
		}
	}
}
