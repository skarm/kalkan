package ckalkan_test

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestConstantsMatchKalkanCryptHeaderValues(t *testing.T) {
	checks := map[string]bool{
		"StorePKCS12":                ckalkan.StorePKCS12 == 0x00000001,
		"CertB64":                    ckalkan.CertB64 == 0x00000104,
		"UseOCSP":                    ckalkan.UseOCSP == 0x00000404,
		"XMLExclC14N":                ckalkan.XMLExclC14N == 0x01000010,
		"CertPropPubKey":             ckalkan.CertPropPubKey == 0x0000081d,
		"CertPropOCSP":               ckalkan.CertPropOCSP == 0x0000081f,
		"CertPropGetCRL":             ckalkan.CertPropGetCRL == 0x00000820,
		"CertPropGetDeltaCRL":        ckalkan.CertPropGetDeltaCRL == 0x00000821,
		"WithTimestamp":              ckalkan.WithTimestamp == 0x00000100,
		"GetOCSPResponse":            ckalkan.GetOCSPResponse == 0x00080000,
		"HashGOST2015_256Flag":       ckalkan.HashGOST2015_256 == 0x00100000,
		"HashGOST2015_512Flag":       ckalkan.HashGOST2015_512 == 0x00200000,
		"SHA256String":               ckalkan.SHA256 == "sha256",
		"GOST95String":               ckalkan.GOST95 == "Gost34311_95",
		"GOST2015_256String":         ckalkan.GOST2015_256 == "GostR3411_2015_256",
		"GOST2015_512String":         ckalkan.GOST2015_512 == "GostR3411_2015_512",
		"ErrorParam":                 ckalkan.ErrorParam == 0x08f00300,
		"ErrorVerifyTSHash":          ckalkan.ErrorVerifyTSHash == 0x08f00054,
		"ErrorXADEST":                ckalkan.ErrorXADESTFailed == 0x08f00055,
		"ErrorOCSPMalformedRequest":  ckalkan.ErrorOCSPRespStatMalformedRequest == 0x08f00056,
		"ErrorOCSPInternalError":     ckalkan.ErrorOCSPRespStatInternalError == 0x08f00057,
		"ErrorOCSPTryLater":          ckalkan.ErrorOCSPRespStatTryLater == 0x08f00058,
		"ErrorOCSPSigRequired":       ckalkan.ErrorOCSPRespStatSigRequired == 0x08f00059,
		"ErrorOCSPUnauthorized":      ckalkan.ErrorOCSPRespStatUnauthorized == 0x08f0005a,
		"ErrorVerifyIssuerSerialV2":  ckalkan.ErrorVerifyIssuerSerialV2 == 0x08f0005b,
		"ErrorOCSPCheckCertFromResp": ckalkan.ErrorOCSPCheckCertFromResp == 0x08f0005c,
		"ErrorCRLExpired":            ckalkan.ErrorCRLExpired == 0x08f0005d,
	}
	for name, ok := range checks {
		if !ok {
			t.Fatalf("constant %s has unexpected value", name)
		}
	}
}
