package ckalkan

const (
	unknownEnglishErrorLabel = "unknown error code"
	unknownRussianErrorLabel = "неизвестный код ошибки"
)

type localizedErrorLabel struct {
	english string
	russian string
}

//nolint:gochecknoglobals
var localizedErrorLabels = map[ErrorCode]localizedErrorLabel{
	ErrorOK:                           {english: "no error", russian: "нет ошибки"},
	ErrorInit:                         {english: "initialization error", russian: "ошибка инициализации"},
	ErrorReadPKCS12:                   {english: "cannot read PKCS#12 file", russian: "невозможно прочитать файл PKCS#12"},
	ErrorOpenPKCS12:                   {english: "cannot open PKCS#12 file", russian: "невозможно открыть файл PKCS#12"},
	ErrorInvalidPropID:                {english: "invalid certificate property identifier", russian: "недопустимый идентификатор свойства сертификата"},
	ErrorBufferTooSmall:               {english: "buffer is too small", russian: "буфер слишком мал"},
	ErrorCertParse:                    {english: "certificate parse error", russian: "ошибка разбора сертификата"},
	ErrorInvalidFlag:                  {english: "invalid flag", russian: "недопустимый флаг"},
	ErrorOpenFile:                     {english: "cannot open file", russian: "невозможно открыть файл"},
	ErrorInvalidPassword:              {english: "invalid password", russian: "неправильный пароль"},
	ErrorCertWrongDate:                {english: "invalid certificate date", russian: "некорректная дата сертификата"},
	ErrorCertExpired:                  {english: "certificate expired", russian: "сертификат истек"},
	ErrorIsNotCACert:                  {english: "certificate is not a CA certificate", russian: "сертификат не является сертификатом УЦ"},
	ErrorMemory:                       {english: "memory allocation error", russian: "ошибка выделения памяти"},
	ErrorCheckChain:                   {english: "certificate chain validation error", russian: "ошибка построения/проверки цепочки сертификатов"},
	ErrorCACertKeyUsage:               {english: "invalid CA certificate key usage", russian: "некорректное использование ключа сертификата УЦ"},
	ErrorValidType:                    {english: "invalid validation type", russian: "недопустимый тип валидации"},
	ErrorBadCRLFormat:                 {english: "invalid CRL format", russian: "некорректный формат CRL"},
	ErrorLoadCRL:                      {english: "cannot load CRL", russian: "невозможно загрузить CRL"},
	ErrorLoadCRLs:                     {english: "cannot load CRLs", russian: "невозможно загрузить CRL-ы"},
	ErrorUnknownAlg:                   {english: "unknown algorithm", russian: "неизвестный алгоритм"},
	ErrorKeyNotFound:                  {english: "private key not found", russian: "приватный ключ не найден"},
	ErrorSignInit:                     {english: "signature initialization error", russian: "ошибка инициализации подписи"},
	ErrorSign:                         {english: "signature error", russian: "ошибка подписи"},
	ErrorEncode:                       {english: "encoding error", russian: "ошибка кодирования"},
	ErrorInvalidFlags:                 {english: "invalid flags", russian: "недопустимые флаги"},
	ErrorCertNotFound:                 {english: "certificate not found", russian: "сертификат не найден"},
	ErrorVerifySign:                   {english: "signature verification error", russian: "ошибка проверки подписи"},
	ErrorBase64Decode:                 {english: "Base64 decode error", russian: "ошибка декодирования Base64"},
	ErrorUnknownCMSFormat:             {english: "unknown CMS format", russian: "неизвестный формат CMS"},
	ErrorGetHash:                      {english: "hash retrieval error", russian: "ошибка получения хэша"},
	ErrorCACertNotFound:               {english: "CA certificate not found", russian: "сертификат УЦ не найден"},
	ErrorXMLSecInit:                   {english: "xmlsec initialization error", russian: "ошибка инициализации xmlsec"},
	ErrorLoadTrustedCerts:             {english: "trusted certificates loading error", russian: "ошибка загрузки доверенных сертификатов"},
	ErrorSignInvalid:                  {english: "invalid signature", russian: "недопустимая подпись"},
	ErrorNoSignFound:                  {english: "signature not found", russian: "подпись не найдена"},
	ErrorDecode:                       {english: "decode error", russian: "ошибка декодирования"},
	ErrorXMLParse:                     {english: "XML parse error", russian: "ошибка разбора XML"},
	ErrorXMLAddID:                     {english: "XML ID add error", russian: "ошибка добавления XML ID"},
	ErrorXMLInternal:                  {english: "internal XML error", russian: "внутренняя ошибка XML"},
	ErrorXMLSetSign:                   {english: "XML signature setup error", russian: "ошибка установки XML-подписи"},
	ErrorOpenSSL:                      {english: "OpenSSL error", russian: "ошибка OpenSSL"},
	ErrorEngineInit:                   {english: "engine initialization error", russian: "ошибка инициализации engine"},
	ErrorNoTokenFound:                 {english: "token not found", russian: "токен не найден"},
	ErrorOCSPAddCert:                  {english: "OCSP request certificate add error", russian: "ошибка добавления сертификата в OCSP-запрос"},
	ErrorOCSPParseURL:                 {english: "OCSP URL parse error", russian: "ошибка разбора OCSP URL"},
	ErrorOCSPAddHost:                  {english: "OCSP host add error", russian: "ошибка добавления OCSP host"},
	ErrorOCSPReq:                      {english: "OCSP request creation error", russian: "ошибка формирования OCSP-запроса"},
	ErrorOCSPConnection:               {english: "OCSP connection error", russian: "ошибка соединения с OCSP"},
	ErrorVerifyNoData:                 {english: "no data to verify", russian: "нет данных для проверки"},
	ErrorIDAttrNotFound:               {english: "ID attribute not found", russian: "атрибут ID не найден"},
	ErrorIDRange:                      {english: "invalid ID range or index", russian: "некорректный диапазон/номер ID"},
	ErrorXMLKeyDup:                    {english: "duplicate XML key", russian: "дублирование XML-ключа"},
	ErrorXMLKeyCreate:                 {english: "XML key creation error", russian: "ошибка создания XML-ключа"},
	ErrorReaderNotFound:               {english: "reader not found", russian: "ридер не найден"},
	ErrorGetCertProp:                  {english: "certificate property retrieval error", russian: "ошибка получения свойства сертификата"},
	ErrorSignFormat:                   {english: "unknown signature format", russian: "неизвестный формат подписи"},
	ErrorInDataFormat:                 {english: "unknown input data format", russian: "неизвестный формат входных данных"},
	ErrorOutDataFormat:                {english: "unknown output data format", russian: "неизвестный формат выходных данных"},
	ErrorVerifyInit:                   {english: "verification initialization error", russian: "ошибка инициализации проверки"},
	ErrorVerify:                       {english: "verification error", russian: "ошибка проверки"},
	ErrorHash:                         {english: "hashing error", russian: "ошибка хэширования"},
	ErrorSignHash:                     {english: "hash signing error", russian: "ошибка подписи хэша"},
	ErrorCACertsNotFound:              {english: "CA certificates not found", russian: "сертификаты УЦ не найдены"},
	ErrorCertTimeInvalid:              {english: "certificate validity time is invalid", russian: "срок действия сертификата недействителен"},
	ErrorConvert:                      {english: "conversion error", russian: "ошибка преобразования"},
	ErrorTSACreateQuery:               {english: "TSA query creation error", russian: "ошибка создания TSA-запроса"},
	ErrorCreateObj:                    {english: "ASN.1 object creation error", russian: "ошибка создания объекта ASN.1"},
	ErrorCreateNonce:                  {english: "nonce creation error", russian: "ошибка создания nonce"},
	ErrorHTTP:                         {english: "HTTP error", russian: "ошибка HTTP"},
	ErrorCADESBESFailed:               {english: "CAdES-BES processing error", russian: "ошибка CAdES-BES"},
	ErrorCADESTFailed:                 {english: "CAdES-T processing error", russian: "ошибка CAdES-T"},
	ErrorNoTSAToken:                   {english: "TSA token is absent", russian: "TSA-токен отсутствует"},
	ErrorInvalidDigestLen:             {english: "invalid digest length", russian: "некорректная длина дайджеста"},
	ErrorGenRand:                      {english: "random data generation error", russian: "ошибка генерации случайных данных"},
	ErrorSoapNS:                       {english: "SOAP namespace error", russian: "ошибка SOAP namespace"},
	ErrorGetPubKey:                    {english: "public key retrieval error", russian: "ошибка получения публичного ключа"},
	ErrorGetCertInfo:                  {english: "certificate information retrieval error", russian: "ошибка получения информации о сертификате"},
	ErrorFileRead:                     {english: "file read error", russian: "ошибка чтения файла"},
	ErrorCheck:                        {english: "check failed or hash mismatch", russian: "ошибка проверки/несовпадение хэша"},
	ErrorZipExtract:                   {english: "ZIP extraction error", russian: "ошибка извлечения ZIP"},
	ErrorNoManifestFile:               {english: "MANIFEST file not found", russian: "файл MANIFEST не найден"},
	ErrorVerifyTSHash:                 {english: "TSA token hash verification error", russian: "ошибка проверки хэша TSA-токена"},
	ErrorXADESTFailed:                 {english: "XAdES-T verification error", russian: "ошибка проверки XAdES-T"},
	ErrorOCSPRespStatMalformedRequest: {english: "OCSP: malformed request", russian: "OCSP: неправильный запрос"},
	ErrorOCSPRespStatInternalError:    {english: "OCSP: internal error", russian: "OCSP: внутренняя ошибка"},
	ErrorOCSPRespStatTryLater:         {english: "OCSP: try later", russian: "OCSP: попробуйте позже"},
	ErrorOCSPRespStatSigRequired:      {english: "OCSP: signature required", russian: "OCSP: требуется подпись запроса"},
	ErrorOCSPRespStatUnauthorized:     {english: "OCSP: unauthorized request", russian: "OCSP: запрос не авторизован"},
	ErrorVerifyIssuerSerialV2:         {english: "IssuerSerialV2 verification error", russian: "ошибка проверки IssuerSerialV2"},
	ErrorOCSPCheckCertFromResp:        {english: "certificate check from OCSP response failed", russian: "ошибка проверки сертификата из OCSP-ответа"},
	ErrorCRLExpired:                   {english: "CRL expired", russian: "CRL истек"},
	ErrorLibraryNotInitialized:        {english: "library is not initialized", russian: "библиотека не инициализирована"},
	ErrorEngineLoad:                   {english: "engine loading error", russian: "ошибка загрузки engine"},
	ErrorParam:                        {english: "invalid parameters", russian: "некорректные параметры"},
	ErrorCertStatusOK:                 {english: "certificate status: valid", russian: "статус сертификата: действителен"},
	ErrorCertStatusRevoked:            {english: "certificate status: revoked", russian: "статус сертификата: отозван"},
	ErrorCertStatusUnknown:            {english: "certificate status: unknown", russian: "статус сертификата: неизвестен"},
}

func errorLabelForLanguage(code ErrorCode, language ErrorLanguage) string {
	label, known := localizedErrorLabels[code]
	if language == ErrorLanguageRussian {
		if known {
			return label.russian
		}

		return unknownRussianErrorLabel
	}

	if known {
		return label.english
	}

	return unknownEnglishErrorLabel
}
