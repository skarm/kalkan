package ckalkan

import (
	"fmt"
	"os"
)

const (
	// signatureOutputOverhead is deliberately conservative. It covers the
	// signature value, certificate material, XML/CMS structure, and typical TSA
	// data. It is only an initial estimate; native reported lengths and retries
	// remain authoritative.
	signatureOutputOverhead = 64 << 10
	pemEnvelopeOverhead     = 256
	pemLineWidth            = 64
)

func (c config) estimatedOutputInitialCapacity(requested, estimated, fallback int) int {
	if requested > 0 {
		return requested
	}

	return max(c.outputInitialCapacity(fallback), estimated)
}

func estimateSignDataOutput(req SignDataRequest) (int, error) {
	// KC_IN_FILE applies to the primary data input. The existing signature is
	// still the secondary in-memory input and must never be interpreted as a
	// file path merely because Data is a file.
	signatureSize := int64(len(req.Signature))
	if req.Flags&In2Base64 != 0 {
		signatureSize = decodedBase64UpperBound(signatureSize)
	}

	contentSize := signatureSize

	if req.Flags&SignCMS != 0 && req.Flags&DetachedData == 0 {
		dataSize := estimateInputSize(req.Data, req.Flags&InFile != 0)
		if req.Flags&InBase64 != 0 {
			dataSize = decodedBase64UpperBound(dataSize)
		}

		contentSize = max(contentSize, dataSize)
	}

	estimated := saturatingEstimateAdd(contentSize, signatureOutputOverhead)
	estimated = estimateEncodedOutputSize(estimated, req.Flags)

	return checkedOutputEstimate("SignData", estimated)
}

func estimateSignedXMLOutput(xml []byte, operation string) (int, error) {
	// KalkanCrypt SignXML and SignWSSE parse the input argument itself as
	// XML even when KC_IN_FILE is set, so only in-memory XML is a supported input.
	estimated := saturatingEstimateAdd(int64(len(xml)), signatureOutputOverhead)

	return checkedOutputEstimate(operation, estimated)
}

func estimateInputSize(value []byte, file bool) int64 {
	if !file {
		return int64(len(value))
	}

	info, err := os.Stat(string(value))
	if err == nil && !info.IsDir() && info.Size() >= 0 {
		return info.Size()
	}

	// Preserve native error behavior when the path does not exist. The path
	// length is still a better fallback than pretending there is a known file.
	return int64(len(value))
}

func decodedBase64UpperBound(encoded int64) int64 {
	if encoded <= 0 {
		return 0
	}

	return saturatingEstimateMultiply(ceilPositiveQuotient(encoded, 4), 3)
}

func estimateEncodedOutputSize(raw int64, flags Flag) int64 {
	if flags&OutPEM != 0 {
		encoded := base64EncodedEstimate(raw)
		lineBreaks := saturatingEstimateMultiply(ceilPositiveQuotient(encoded, pemLineWidth), 2)

		return saturatingEstimateAdd(saturatingEstimateAdd(encoded, lineBreaks), pemEnvelopeOverhead)
	}

	if flags&OutBase64 != 0 {
		return base64EncodedEstimate(raw)
	}

	return raw
}

func base64EncodedEstimate(raw int64) int64 {
	if raw <= 0 {
		return 0
	}

	// Keep the arithmetic in int64. base64.Encoding.EncodedLen accepts int and
	// can overflow before the result is checked on 32-bit builds.
	return saturatingEstimateMultiply(ceilPositiveQuotient(raw, 3), 4)
}

func ceilPositiveQuotient(value, divisor int64) int64 {
	quotient := value / divisor
	if value%divisor != 0 {
		quotient++
	}

	return quotient
}

func saturatingEstimateAdd(left, right int64) int64 {
	limit := int64(maxNativeOutputBufferSize) + 1
	if left >= limit || right >= limit || left > limit-right {
		return limit
	}

	return left + right
}

func saturatingEstimateMultiply(value, multiplier int64) int64 {
	limit := int64(maxNativeOutputBufferSize) + 1

	if value <= 0 || multiplier <= 0 {
		return 0
	}

	if value >= limit || value > limit/multiplier {
		return limit
	}

	return value * multiplier
}

func checkedOutputEstimate(operation string, estimated int64) (int, error) {
	if estimated > int64(maxNativeOutputBufferSize) {
		return 0, &KalkanError{
			Code:    ErrorBufferTooSmall,
			Message: fmt.Sprintf("estimated %s output exceeds native C int buffer limit %d", operation, maxNativeOutputBufferSize),
		}
	}

	return int(estimated), nil
}
