package ckalkan

// ErrorCode is a KalkanCrypt runtime/status code (KCR_*).
type ErrorCode uint64

const (
	// ErrorOK reports a successful KalkanCrypt operation.
	ErrorOK ErrorCode = 0x00000000
	// ErrorInit reports a KalkanCrypt initialization failure.
	ErrorInit ErrorCode = 0x08f00001
	// ErrorReadPKCS12 reports a failure while reading a PKCS#12 file.
	ErrorReadPKCS12 ErrorCode = 0x08f00002
	// ErrorOpenPKCS12 reports a failure while opening a PKCS#12 file.
	ErrorOpenPKCS12 ErrorCode = 0x08f00003
	// ErrorInvalidPropID reports an invalid certificate property identifier.
	ErrorInvalidPropID ErrorCode = 0x08f00004
	// ErrorBufferTooSmall reports that the provided output buffer is too small.
	ErrorBufferTooSmall ErrorCode = 0x08f00005
	// ErrorCertParse reports a certificate parsing failure.
	ErrorCertParse ErrorCode = 0x08f00006
	// ErrorInvalidFlag reports an invalid KalkanCrypt flag.
	ErrorInvalidFlag ErrorCode = 0x08f00007
	// ErrorOpenFile reports a failure while opening a file.
	ErrorOpenFile ErrorCode = 0x08f00008
	// ErrorInvalidPassword reports an invalid password.
	ErrorInvalidPassword ErrorCode = 0x08f00009
	// ErrorCertWrongDate reports an invalid certificate date.
	ErrorCertWrongDate ErrorCode = 0x08f0000a
	// ErrorCertExpired reports an expired certificate.
	ErrorCertExpired ErrorCode = 0x08f0000b
	// ErrorIsNotCACert reports that a certificate is not a CA certificate.
	ErrorIsNotCACert ErrorCode = 0x08f0000c
	// ErrorMemory reports a native memory allocation failure.
	ErrorMemory ErrorCode = 0x08f0000d
	// ErrorCheckChain reports a certificate chain validation failure.
	ErrorCheckChain ErrorCode = 0x08f0000e
	// ErrorCACertKeyUsage reports an invalid CA certificate key usage.
	ErrorCACertKeyUsage ErrorCode = 0x08f0000f
	// ErrorValidType reports an invalid certificate validation type.
	ErrorValidType ErrorCode = 0x08f00010
	// ErrorBadCRLFormat reports an invalid CRL format.
	ErrorBadCRLFormat ErrorCode = 0x08f00011
	// ErrorLoadCRL reports a CRL loading failure.
	ErrorLoadCRL ErrorCode = 0x08f00012
	// ErrorLoadCRLs reports a failure while loading CRLs.
	ErrorLoadCRLs ErrorCode = 0x08f00013
	// ErrorUnknownAlg reports an unknown algorithm.
	ErrorUnknownAlg ErrorCode = 0x08f00015
	// ErrorKeyNotFound reports that the private key was not found.
	ErrorKeyNotFound ErrorCode = 0x08f00016
	// ErrorSignInit reports a signature initialization failure.
	ErrorSignInit ErrorCode = 0x08f00017
	// ErrorSign reports a signing failure.
	ErrorSign ErrorCode = 0x08f00018
	// ErrorEncode reports an encoding failure.
	ErrorEncode ErrorCode = 0x08f00019
	// ErrorInvalidFlags reports invalid KalkanCrypt flags.
	ErrorInvalidFlags ErrorCode = 0x08f0001a
	// ErrorCertNotFound reports that a certificate was not found.
	ErrorCertNotFound ErrorCode = 0x08f0001b
	// ErrorVerifySign reports a signature verification failure.
	ErrorVerifySign ErrorCode = 0x08f0001c
	// ErrorBase64Decode reports a Base64 decoding failure.
	ErrorBase64Decode ErrorCode = 0x08f0001d
	// ErrorUnknownCMSFormat reports an unknown CMS format.
	ErrorUnknownCMSFormat ErrorCode = 0x08f0001e
	// ErrorGetHash reports a hash retrieval failure.
	ErrorGetHash ErrorCode = 0x08f0001f
	// ErrorCACertNotFound reports that a CA certificate was not found.
	ErrorCACertNotFound ErrorCode = 0x08f00020
	// ErrorXMLSecInit reports an xmlsec initialization failure.
	ErrorXMLSecInit ErrorCode = 0x08f00021
	// ErrorLoadTrustedCerts reports a trusted-certificate loading failure.
	ErrorLoadTrustedCerts ErrorCode = 0x08f00022
	// ErrorSignInvalid reports an invalid signature.
	ErrorSignInvalid ErrorCode = 0x08f00023
	// ErrorNoSignFound reports that no signature was found.
	ErrorNoSignFound ErrorCode = 0x08f00024
	// ErrorDecode reports a decoding failure.
	ErrorDecode ErrorCode = 0x08f00025
	// ErrorXMLParse reports an XML parsing failure.
	ErrorXMLParse ErrorCode = 0x08f00026
	// ErrorXMLAddID reports a failure while adding an XML ID.
	ErrorXMLAddID ErrorCode = 0x08f00027
	// ErrorXMLInternal reports an internal XML processing failure.
	ErrorXMLInternal ErrorCode = 0x08f00028
	// ErrorXMLSetSign reports a failure while setting an XML signature.
	ErrorXMLSetSign ErrorCode = 0x08f00029
	// ErrorOpenSSL reports an OpenSSL failure.
	ErrorOpenSSL ErrorCode = 0x08f0002a
	// ErrorEngineInit reports an engine initialization failure.
	ErrorEngineInit ErrorCode = 0x08f0002b
	// ErrorNoTokenFound reports that no token was found.
	ErrorNoTokenFound ErrorCode = 0x08f0002c
	// ErrorOCSPAddCert reports a failure while adding a certificate to an OCSP request.
	ErrorOCSPAddCert ErrorCode = 0x08f0002d
	// ErrorOCSPParseURL reports an OCSP URL parsing failure.
	ErrorOCSPParseURL ErrorCode = 0x08f0002e
	// ErrorOCSPAddHost reports a failure while adding an OCSP host.
	ErrorOCSPAddHost ErrorCode = 0x08f0002f
	// ErrorOCSPReq reports an OCSP request creation failure.
	ErrorOCSPReq ErrorCode = 0x08f00030
	// ErrorOCSPConnection reports an OCSP connection failure.
	ErrorOCSPConnection ErrorCode = 0x08f00031
	// ErrorVerifyNoData reports that there is no data to verify.
	ErrorVerifyNoData ErrorCode = 0x08f00032
	// ErrorIDAttrNotFound reports that an XML ID attribute was not found.
	ErrorIDAttrNotFound ErrorCode = 0x08f00033
	// ErrorIDRange reports an invalid XML ID range or index.
	ErrorIDRange ErrorCode = 0x08f00034
	// ErrorXMLKeyDup reports a duplicate XML key.
	ErrorXMLKeyDup ErrorCode = 0x08f00035
	// ErrorXMLKeyCreate reports an XML key creation failure.
	ErrorXMLKeyCreate ErrorCode = 0x08f00036
	// ErrorReaderNotFound reports that a reader was not found.
	ErrorReaderNotFound ErrorCode = 0x08f00037
	// ErrorGetCertProp reports a certificate property retrieval failure.
	ErrorGetCertProp ErrorCode = 0x08f00038
	// ErrorSignFormat reports an unknown signature format.
	ErrorSignFormat ErrorCode = 0x08f00039
	// ErrorInDataFormat reports an unknown input data format.
	ErrorInDataFormat ErrorCode = 0x08f0003a
	// ErrorOutDataFormat reports an unknown output data format.
	ErrorOutDataFormat ErrorCode = 0x08f0003b
	// ErrorVerifyInit reports a verification initialization failure.
	ErrorVerifyInit ErrorCode = 0x08f0003c
	// ErrorVerify reports a verification failure.
	ErrorVerify ErrorCode = 0x08f0003d
	// ErrorHash reports a hashing failure.
	ErrorHash ErrorCode = 0x08f0003e
	// ErrorSignHash reports a hash-signing failure.
	ErrorSignHash ErrorCode = 0x08f0003f
	// ErrorCACertsNotFound reports that CA certificates were not found.
	ErrorCACertsNotFound ErrorCode = 0x08f00040
	// ErrorCertTimeInvalid reports an invalid certificate validity time.
	ErrorCertTimeInvalid ErrorCode = 0x08f00042
	// ErrorConvert reports a conversion failure.
	ErrorConvert ErrorCode = 0x08f00043
	// ErrorTSACreateQuery reports a TSA query creation failure.
	ErrorTSACreateQuery ErrorCode = 0x08f00044
	// ErrorCreateObj reports an ASN.1 object creation failure.
	ErrorCreateObj ErrorCode = 0x08f00045
	// ErrorCreateNonce reports a nonce creation failure.
	ErrorCreateNonce ErrorCode = 0x08f00046
	// ErrorHTTP reports an HTTP failure.
	ErrorHTTP ErrorCode = 0x08f00047
	// ErrorCADESBESFailed reports a CAdES-BES processing failure.
	ErrorCADESBESFailed ErrorCode = 0x08f00048
	// ErrorCADESTFailed reports a CAdES-T processing failure.
	ErrorCADESTFailed ErrorCode = 0x08f00049
	// ErrorNoTSAToken reports that a TSA token is absent.
	ErrorNoTSAToken ErrorCode = 0x08f0004a
	// ErrorInvalidDigestLen reports an invalid digest length.
	ErrorInvalidDigestLen ErrorCode = 0x08f0004b
	// ErrorGenRand reports a random-data generation failure.
	ErrorGenRand ErrorCode = 0x08f0004c
	// ErrorSoapNS reports a SOAP namespace failure.
	ErrorSoapNS ErrorCode = 0x08f0004d
	// ErrorGetPubKey reports a public-key retrieval failure.
	ErrorGetPubKey ErrorCode = 0x08f0004e
	// ErrorGetCertInfo reports a certificate information retrieval failure.
	ErrorGetCertInfo ErrorCode = 0x08f0004f
	// ErrorFileRead reports a file read failure.
	ErrorFileRead ErrorCode = 0x08f00050
	// ErrorCheck reports a check failure or hash mismatch.
	ErrorCheck ErrorCode = 0x08f00051
	// ErrorZipExtract reports a ZIP extraction failure.
	ErrorZipExtract ErrorCode = 0x08f00052
	// ErrorNoManifestFile reports that a MANIFEST file was not found.
	ErrorNoManifestFile ErrorCode = 0x08f00053
	// ErrorVerifyTSHash reports a timestamp-token hash verification failure.
	ErrorVerifyTSHash ErrorCode = 0x08f00054
	// ErrorXADESTFailed reports an XAdES-T verification failure.
	ErrorXADESTFailed ErrorCode = 0x08f00055
	// ErrorOCSPRespStatMalformedRequest reports an OCSP malformedRequest status.
	ErrorOCSPRespStatMalformedRequest ErrorCode = 0x08f00056
	// ErrorOCSPRespStatInternalError reports an OCSP internalError status.
	ErrorOCSPRespStatInternalError ErrorCode = 0x08f00057
	// ErrorOCSPRespStatTryLater reports an OCSP tryLater status.
	ErrorOCSPRespStatTryLater ErrorCode = 0x08f00058
	// ErrorOCSPRespStatSigRequired reports an OCSP sigRequired status.
	ErrorOCSPRespStatSigRequired ErrorCode = 0x08f00059
	// ErrorOCSPRespStatUnauthorized reports an OCSP unauthorized status.
	ErrorOCSPRespStatUnauthorized ErrorCode = 0x08f0005a
	// ErrorVerifyIssuerSerialV2 reports an IssuerSerialV2 verification failure.
	ErrorVerifyIssuerSerialV2 ErrorCode = 0x08f0005b
	// ErrorOCSPCheckCertFromResp reports a certificate-check failure in an OCSP response.
	ErrorOCSPCheckCertFromResp ErrorCode = 0x08f0005c
	// ErrorCRLExpired reports an expired certificate revocation list.
	ErrorCRLExpired ErrorCode = 0x08f0005d
	// ErrorLibraryNotInitialized reports that the native library is not initialized.
	ErrorLibraryNotInitialized ErrorCode = 0x08f00101
	// ErrorEngineLoad reports an engine loading failure.
	ErrorEngineLoad ErrorCode = 0x08f00200
	// ErrorParam reports invalid parameters.
	ErrorParam ErrorCode = 0x08f00300
	// ErrorCertStatusOK reports a valid certificate status.
	ErrorCertStatusOK ErrorCode = 0x08f00400
	// ErrorCertStatusRevoked reports a revoked certificate status.
	ErrorCertStatusRevoked ErrorCode = 0x08f00401
	// ErrorCertStatusUnknown reports an unknown certificate status.
	ErrorCertStatusUnknown ErrorCode = 0x08f00402
)
