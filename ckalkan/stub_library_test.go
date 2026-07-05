//go:build linux && cgo

package ckalkan_test

const stubSource = `
#include <string.h>
#include <time.h>
#include "KalkanCrypt.h"

static unsigned long copy_out(const char *s, unsigned char *out, int *outLen) {
    int n = (int)strlen(s);
    if (*outLen < n) {
        *outLen = n;
        return KCR_BUFFER_TOO_SMALL;
    }
    memcpy(out, s, (size_t)n);
    *outLen = n;
    return KCR_OK;
}

static unsigned long copy_out_char(const char *s, char *out, int *outLen) {
    return copy_out(s, (unsigned char*)out, outLen);
}

static unsigned long stub_init(void) { return KCR_OK; }
static unsigned long stub_get_tokens(unsigned long storage, char *tokens, unsigned long *tk_count) { (void)storage; strcpy(tokens, "token-a;token-b"); *tk_count = 2; return KCR_OK; }
static unsigned long stub_get_certificates_list(char *certificates, unsigned long *cert_count) { strcpy(certificates, "cert-a"); *cert_count = 1; return KCR_OK; }
static unsigned long stub_load_key_store(int storage, char *password, int passLen, char *container, int containerLen, char *alias) { (void)storage; (void)password; (void)passLen; (void)container; (void)containerLen; (void)alias; return KCR_OK; }
static unsigned long stub_x509_load_file(char *certPath, int certType) { (void)certPath; (void)certType; return KCR_OK; }
static unsigned long stub_x509_load_buffer(unsigned char *inCert, int certLength, int flag) { (void)inCert; (void)certLength; (void)flag; return KCR_OK; }
static unsigned long stub_x509_export(char *alias, int flag, char *outCert, int *outCertLength) { (void)alias; (void)flag; return copy_out_char("CERT", outCert, outCertLength); }
static unsigned long stub_x509_info(char *inCert, int inCertLength, int propId, unsigned char *outData, int *outDataLength) { (void)inCert; (void)inCertLength; (void)propId; return copy_out("INFO", outData, outDataLength); }
static unsigned long stub_x509_validate(char *inCert, int inCertLength, int validType, char *validPath, long long checkTime, char *outInfo, int *outInfoLength, int flag, char *getOCSPResponse, int *getOCSPResponseLength) { (void)inCert; (void)inCertLength; (void)validType; (void)validPath; (void)checkTime; (void)flag; unsigned long rc = copy_out_char("VALID", outInfo, outInfoLength); if (rc != KCR_OK) return rc; return copy_out_char("OCSP", getOCSPResponse, getOCSPResponseLength); }
static unsigned long stub_hash(char *algorithm, int flags, char *inData, int inDataLength, unsigned char *outData, int *outDataLength) { (void)algorithm; (void)flags; (void)inData; (void)inDataLength; return copy_out("HASH", outData, outDataLength); }
static unsigned long stub_sign_hash(char *alias, int flags, char *inHash, int inHashLength, unsigned char *outSign, int *outSignLength) { (void)alias; (void)flags; (void)inHash; (void)inHashLength; return copy_out("SIGNHASH", outSign, outSignLength); }
static unsigned long stub_sign_data(char *alias, int flags, char *inData, int inDataLength, unsigned char *inSign, int inSignLen, unsigned char *outSign, int *outSignLength) { (void)alias; (void)flags; (void)inData; (void)inDataLength; (void)inSign; (void)inSignLen; return copy_out("SIGNDATA", outSign, outSignLength); }
static unsigned long stub_sign_xml(char *alias, int flags, char *inData, int inDataLength, unsigned char *outSign, int *outSignLength, char *signNodeId, char *parentSignNode, char *parentNameSpace) { (void)alias; (void)flags; (void)inData; (void)inDataLength; (void)signNodeId; (void)parentSignNode; (void)parentNameSpace; return copy_out("<signed/>", outSign, outSignLength); }
static unsigned long stub_verify_data(char *alias, int flags, char *inData, int inDataLength, unsigned char *inoutSign, int inoutSignLength, char *outData, int *outDataLen, char *outVerifyInfo, int *outVerifyInfoLen, int inCertID, char *outCert, int *outCertLength) { (void)alias; (void)flags; (void)inData; (void)inDataLength; (void)inoutSign; (void)inoutSignLength; (void)inCertID; unsigned long rc = copy_out_char("DATA", outData, outDataLen); if (rc != KCR_OK) return rc; rc = copy_out_char("VERIFY", outVerifyInfo, outVerifyInfoLen); if (rc != KCR_OK) return rc; return copy_out_char("CERT", outCert, outCertLength); }
static unsigned long stub_verify_xml(char *alias, int flags, char *inData, int inDataLength, char *outVerifyInfo, int *outVerifyInfoLen) { (void)alias; (void)flags; (void)inData; (void)inDataLength; return copy_out_char("XMLVERIFY", outVerifyInfo, outVerifyInfoLen); }
static unsigned long stub_cert_from_xml(const char* inXML, int inXMLLength, int inSignID, char *outCert, int *outCertLength) { (void)inXML; (void)inXMLLength; (void)inSignID; return copy_out_char("XMLCERT", outCert, outCertLength); }
static unsigned long stub_sig_alg(const char* xml_in, int xml_in_size, char *retSigAlg, int *retLen) { (void)xml_in; (void)xml_in_size; return copy_out_char("ALG", retSigAlg, retLen); }
static unsigned long stub_last_error(void) { return KCR_OK; }
static unsigned long stub_last_error_string(char *errorString, int *bufSize) { return copy_out_char("OK", errorString, bufSize); }
static void stub_void(void) { }
static void stub_tsa(char *tsaurl) { (void)tsaurl; }
static unsigned long stub_time(char *inData, int inDataLength, int flags, int inSigId, time_t *outDateTime) { (void)inData; (void)inDataLength; (void)flags; (void)inSigId; *outDateTime = (time_t)12345; return KCR_OK; }
static unsigned long stub_proxy(int flags, char *inProxyAddr, char *inProxyPort, char *inUser, char *inPass) { (void)flags; (void)inProxyAddr; (void)inProxyPort; (void)inUser; (void)inPass; return KCR_OK; }
static unsigned long stub_cert_from_cms(char *inCMS, int inCMSLen, int inSignId, int flags, char *outCert, int *outCertLength) { (void)inCMS; (void)inCMSLen; (void)inSignId; (void)flags; return copy_out_char("CMSCERT", outCert, outCertLength); }
static unsigned long stub_wsse(char *alias, unsigned long flags, char *inData, int inDataLength, unsigned char *outSign, int *outSignLength, char *signNodeId) { (void)alias; (void)flags; (void)inData; (void)inDataLength; (void)signNodeId; return copy_out("<wsse/>", outSign, outSignLength); }
static unsigned long stub_zip_verify(char *inZipFile, int flags, char *outVerifyInfo, int *outVerifyInfoLen) { (void)inZipFile; (void)flags; return copy_out_char("ZIPVERIFY", outVerifyInfo, outVerifyInfoLen); }
static unsigned long stub_zip_sign(char *alias, const char *filePath, const char *name, const char *outDir, int flags) { (void)alias; (void)filePath; (void)name; (void)outDir; (void)flags; return KCR_OK; }
static unsigned long stub_cert_from_zip(char* inZipFile, int flags, int inSignID, char *outCert, int *outCertLength) { (void)inZipFile; (void)flags; (void)inSignID; return copy_out_char("ZIPCERT", outCert, outCertLength); }
static unsigned long stub_uverify_data(char *alias, int flags, char *inData, int inDataLength, unsigned char *inOutSign, int inOutSignLength, char *outData, int *outDataLen, char *outVerifyInfo, int *outVerifyInfoLen, int inCertID, char *outCert, int *outCertLength) { (void)alias; (void)flags; (void)inData; (void)inDataLength; (void)inOutSign; (void)inOutSignLength; (void)inCertID; unsigned long rc = copy_out_char("UDATA", outData, outDataLen); if (rc != KCR_OK) return rc; rc = copy_out_char("UVERIFY", outVerifyInfo, outVerifyInfoLen); if (rc != KCR_OK) return rc; return copy_out_char("UCERT", outCert, outCertLength); }

static stKCFunctionsType funcs = {
    .KC_Init = stub_init,
    .KC_GetTokens = stub_get_tokens,
    .KC_GetCertificatesList = stub_get_certificates_list,
    .KC_LoadKeyStore = stub_load_key_store,
    .X509LoadCertificateFromFile = stub_x509_load_file,
    .X509LoadCertificateFromBuffer = stub_x509_load_buffer,
    .X509ExportCertificateFromStore = stub_x509_export,
    .X509CertificateGetInfo = stub_x509_info,
    .X509ValidateCertificate = stub_x509_validate,
    .HashData = stub_hash,
    .SignHash = stub_sign_hash,
    .SignData = stub_sign_data,
    .SignXML = stub_sign_xml,
    .VerifyData = stub_verify_data,
    .VerifyXML = stub_verify_xml,
    .KC_getCertFromXML = stub_cert_from_xml,
    .KC_getSigAlgFromXML = stub_sig_alg,
    .KC_GetLastError = stub_last_error,
    .KC_GetLastErrorString = stub_last_error_string,
    .KC_XMLFinalize = stub_void,
    .KC_Finalize = stub_void,
    .KC_TSASetUrl = stub_tsa,
    .KC_GetTimeFromSig = stub_time,
    .KC_SetProxy = stub_proxy,
    .KC_GetCertFromCMS = stub_cert_from_cms,
    .SignWSSE = stub_wsse,
    .ZipConVerify = stub_zip_verify,
    .ZipConSign = stub_zip_sign,
    .KC_getCertFromZipFile = stub_cert_from_zip,
    .UVerifyData = stub_uverify_data,
    .KC_InitDebug = stub_void,
};

int KC_GetFunctionList(stKCFunctionsType **KCfunc) {
    *KCfunc = &funcs;
    return 0;
}
`
