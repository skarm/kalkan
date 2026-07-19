# KalkanCrypt для Go

[English version](README.md)

[![CI](https://github.com/skarm/kalkan/actions/workflows/ci.yml/badge.svg)](https://github.com/skarm/kalkan/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/skarm/kalkan.svg)](https://pkg.go.dev/github.com/skarm/kalkan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Go-обёртка над KalkanCrypt. Корневой пакет предоставляет типизированный API поверх низкоуровневого `ckalkan`.

## Совместимость

- Go 1.26+
- `linux/amd64` с `CGO_ENABLED=1`
- `windows/amd64`

Нативные тесты CI выполняются с `libkalkancryptwr-64.so.2.0.13`.

`windows/386`, Linux с `CGO_ENABLED=0` и другие платформы компилируются с заглушкой драйвера и возвращают `ErrUnavailable`.

SDK доступен на [портале разработчиков НУЦ РК](https://pki.gov.kz/ru/developers/). `WithLibraryPath` принимает абсолютный путь к x64 `.so` или DLL.

## Установка

```sh
go get github.com/skarm/kalkan@latest
```

## Пакеты

- [`github.com/skarm/kalkan`](https://pkg.go.dev/github.com/skarm/kalkan): типизированный API для CMS, XML, WS-Security, хеширования, ZIP, сертификатов, OCSP/TSA, прокси и логирования
- [`github.com/skarm/kalkan/ckalkan`](https://pkg.go.dev/github.com/skarm/kalkan/ckalkan): ABI-уровень с нативными флагами, кодировками и настройками буферов

Используйте `ckalkan`, если нужной операции нет в корневом пакете. Также используйте его для собственного высокоуровневого слоя над KalkanCrypt: со своими типами запросов, валидацией, политикой буферов, логированием или преобразованием ошибок.

`ckalkan` близок к нативному API. Вызывающий код отвечает за нативные флаги, кодировки, размеры буферов и обработку статус-кодов; он также должен учитывать жизненный цикл клиента, ограничения ABI и необходимость изоляции процесса.

### Выходные буферы `ckalkan`

Параметры буферов `ckalkan` разделены по двум формам ABI:

- `WithListBufferSize` задаёт начальную аллокацию для `KC_GetTokens` и `KC_GetCertificatesList`; значение по умолчанию равно 1 MiB. В протестированном Linux SDK 2.0.13 эти функции не получают ёмкость буфера в байтах, а `tk_count` и `cert_count` являются выходными счётчиками элементов. Опция управляет размером аллокации, но не ограничивает нативную запись.
- `WithBufferSize` задаёт общую начальную ёмкость для вызовов с выходным буфером, которым передаётся его размер. Поля ёмкости в запросе имеют приоритет над этой опцией. Без неё используются начальные размеры 128 байт для хешей, 4 KiB для метаданных, 8 KiB для сертификатов и 64 KiB для подписей и остальных выходных буферов. Для прикреплённого CMS учитываются размер входных данных в памяти или файла и консервативный запас на подпись; также учитывается расширение Base64 и PEM. Для подписанного XML/WSSE учитываются размер XML в памяти и тот же запас (`KC_IN_FILE` этими двумя вызовами SDK не поддерживается). Перед вызовом ёмкость записывается в выходной параметр длины. При `KCR_BUFFER_TOO_SMALL` обёртка увеличивает буфер и повторяет вызов.
- Каждый выходной буфер по умолчанию имеет жёсткий лимит 64 MiB (`ckalkan.DefaultMaxOutputBufferSize`). `WithMaxBufferSize(0)` восстанавливает безопасное значение по умолчанию; положительное значение осознанно задаёт меньший или больший лимит вплоть до максимума нативного C `int` — 2^31-1 байт. Отрицательное значение приводит к ошибке `ErrInvalidOutputBufferSize` из `New`. Если нативный код сообщает размер выше действующего лимита, обёртка до повторного вызова и аллокации чрезмерной ёмкости возвращает типизированную `OutputBufferLimitError` с названием операции, запрошенным размером и применённым лимитом.

В Linux для `ZipConVerify` нужна защитная аллокация 64 KiB: SDK 2.0.13 может записать данные за пределами меньшей переданной ёмкости. Если явный жёсткий лимит меньше этого безопасного минимума, вызов завершается ошибкой до входа в нативную библиотеку.

Положительные значения `WithBufferSize` и `WithListBufferSize` нормализуются до значения не менее 64 KiB. Положительное значение `WithMaxBufferSize` соблюдается точно до максимума ABI C `int`. Меньший жёсткий лимит может не позволить операции использовать обычную начальную ёмкость; значение 64 MiB по умолчанию является границей безопасности и доступности, а не указанием, что операция обычно должна использовать столько памяти.

Лимит аллокации также ограничивает повторный рост обёртки для `KC_GetTokens` и `KC_GetCertificatesList`, но не устраняет их отдельный ABI-риск: эти две функции не получают ёмкость в байтах, поэтому опция не способна ограничить даже первую нативную запись.

Формально успешный результат списка, который занял всю аллокацию без завершающего NUL, считается потенциально усечённым и повторяется с увеличенной аллокацией.

## Использование клиента

```go
import (
	"context"
	"errors"
	"os"

	"github.com/skarm/kalkan"
)

func hash(ctx context.Context) (digest *kalkan.Digest, err error) {
	client, err := kalkan.Open(ctx,
		kalkan.WithLibraryPath(os.Getenv("KALKANCRYPT_LIBRARY")),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, client.Close())
	}()

	return client.Hash(ctx, kalkan.HashRequest{
		Algorithm: kalkan.GOST2015_512,
		Data:      kalkan.Bytes([]byte("document payload")),
	})
}
```

По умолчанию `Open` настраивает production endpoints:

- TSA: `http://tsp.pki.gov.kz:80`
- OCSP: `http://ocsp.pki.gov.kz`

Соответствующие test endpoints:

- TSA: `http://test.pki.gov.kz/tsp/`
- OCSP: `http://test.pki.gov.kz/ocsp/`

Test endpoints задаются явно:

```go
client, err := kalkan.Open(ctx,
	kalkan.WithLibraryPath(os.Getenv("KALKANCRYPT_LIBRARY")),
	kalkan.WithTSAURL("http://test.pki.gov.kz/tsp/"),
	kalkan.WithOCSPURL("http://test.pki.gov.kz/ocsp/"),
)
```

`WithTSAURL` и `WithOCSPURL` настраиваются независимо. Для операций подписания нужен `LoadKeyStore`; примеры находятся в [`example_test.go`](example_test.go).

## Модель выполнения

Состояние KalkanCrypt глобально для процесса. Нативные вызовы сериализуются. `context.Context` отменяет ожидание блокировки, но не прерывает уже начавшийся вызов KalkanCrypt.

`Client.Close()` ждёт активный вызов и может заблокироваться навсегда. `Client.CloseContext(ctx)` прекращает ожидание вызывающего кода по `ctx.Err()`, оставляет клиент в состоянии `closing` и отклоняет новые операции. Жёсткие дедлайны требуют изоляции процесса.

В Windows `LoadLibraryExW` вызывается с `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`. Текущий рабочий каталог и `PATH` исключены. Узкие `char*` аргументы передаются как UTF-8 с завершающим NUL.

## Входы и лимиты

Операции используют значения `Source`:

- `kalkan.Bytes(data)`: непреобразованные байты в памяти для данных, XML или уже декодированного бинарного объекта; конкретная операция выбирает нативные флаги
- `kalkan.Base64(data)`: вход в памяти, уже содержащий Base64-текст; конструктор не кодирует `data`
- `kalkan.PEM(data)`: готовый PEM-блок; конструктор не создаёт PEM-оболочку
- `kalkan.DER(data)`: готовый DER-объект для явного выбора DER в CMS и операциях с сертификатами
- `kalkan.File(path)`: путь, передаваемый KalkanCrypt операциями с поддержкой `KC_IN_FILE`

Допустимые варианты зависят от операции.

Конструкторы источников в памяти не копируют и не преобразуют переданный срез. Валидация конкретной операции может декодировать PEM или Base64 до нативного вызова. `File` передаёт исходный путь после проверки на пустое значение и NUL. Не изменяйте заимствованные срезы и файлы до завершения вызова.

`WithMaxInputSize` ограничивает входы в памяти на уровне корневого API. Ограничение не распространяется на файловые источники и нативные выходные буферы. Для нативных выходных буферов по умолчанию действует жёсткий лимит 64 MiB (`kalkan.DefaultMaxOutputBufferSize`). `WithMaxOutputBufferSize(0)` восстанавливает это значение; положительное значение задаёт меньший или больший лимит (до максимума нативного C `int`), а отрицательное приводит к `ErrInvalidInput` из `Open`. Опция передаётся в `ckalkan.WithMaxBufferSize`. При превышении действующего лимита до чрезмерного повторного вызова или выделения памяти возвращается `ckalkan.OutputBufferLimitError`.

Бинарные результаты возвращаются строго по сообщённому SDK значению `outLen`; нулевые байты внутри этой длины сохраняются. У возвращённого среза `len` и `cap` ограничены логическим результатом, поэтому неиспользованная ёмкость буфера наружу не видна. Результаты-срезы являются ограниченными представлениями, а не копиями: пока результат используется, в памяти остаётся успешная исходная аллокация, зато не создаются вторая большая аллокация и копия. Известные текстовые результаты обрабатываются как C-строки и заканчиваются на первом NUL: некоторые методы KalkanCrypt сообщают размер фиксированного блока и оставляют после терминатора неопределённые байты.

`KeyStore.Password` и `Proxy.Password` имеют тип `string`. Пакет не может обнулить память Go, состояние KalkanCrypt и внутренние копии SDK.

## CMS и подписание хеша

По умолчанию CMS возвращается как DER. Для текстового вывода используйте `CMSOutputBase64` или `CMSOutputPEM`.

`SignHashRequest.Digest` содержит заранее вычисленный дайджест. `DigestAlgorithm` должен соответствовать алгоритму хеша; нулевое значение поля равно `SHA256`. Для 512-битного ГОСТ Р 34.11-2015 используйте `GOST2015_512`.

## XML и WS-Security

`VerifyXML` передаёт криптографическую проверку в KalkanCrypt. Для SOAP 1.1 и SOAP 1.2 обязателен `ExpectedBodyID`; до нативного вызова проверяются:

- ровно один `ds:Signature`
- ровно один `ds:SignedInfo`, являющийся непосредственным дочерним элементом подписи
- ровно один SOAP Body, являющийся непосредственным дочерним элементом Envelope и имеющий ожидаемый `wsu:Id`
- прямая `ds:Reference` на `#ExpectedBodyID`
- у Body reference либо нет `ds:Transforms`, либо есть ровно один непосредственный `ds:Transform` с Exclusive XML Canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- отсутствие дубликатов `wsu:Id`, `xml:id`, `Id` или `ID` с тем же значением

Операции XML принимают `kalkan.Bytes`; файловые и предварительно закодированные источники отклоняются.

Дополнительные прямые `ds:Reference` могут покрывать другие элементы WS-Security. SOAP должен быть в UTF-8. Для XML вне SOAP также допускается объявленная ASCII-совместимая кодировка, если пролог и корневой тег записаны в ASCII.

Wrapper не применяет собственную allowlist-политику к `CanonicalizationMethod`, `DigestMethod` и `SignatureMethod`: набор поддерживаемых криптографических алгоритмов зависит от установленной версии KalkanCrypt, а fixtures репозитория не задают стабильного полного списка. Отклонение неподдерживаемых методов остаётся ответственностью KalkanCrypt.

## Проверка сертификатов

`ValidateCertificateRequest.Mode` должен быть `CertificateValidationOCSP`, `CertificateValidationCRL` или `CertificateValidationNone`. Нулевое значение недопустимо. `CertificateValidationNone` явно отключает внешнюю проверку отзыва.

Входной сертификат поддерживает DER, PEM и base64; `kalkan.File` отклоняется. PEM должен содержать ровно один блок `CERTIFICATE`. `RevocationSource` задаёт путь к CRL в CRL-режиме или переопределяет OCSP URL в OCSP-режиме.

`WithOCSPURL` и `WithTSAURL` переопределяют значения пакета по умолчанию. URL проверяется синтаксически, без ограничения адреса назначения.

Для выборочного чтения метаданных используйте `X509CertificateGetInfoFields`. `CertificateInfo` возвращает ИИН, БИН, тип субъекта и распознанные роли НУЦ при запросе соответствующих полей.

## ZIP-контейнеры

`SignZIPRequest.OutputPath` должен оканчиваться на `.zip` без учёта регистра. До нативного вызова проверяется отсутствие файла как по исходному, так и по нормализованному пути. KalkanCrypt создаёт выходной файл без атомарной гарантии эксклюзивного создания.

Входные пути ZIP передаются после проверки на пустое значение и NUL. Не изменяйте файлы до завершения операции.

`VerifyZIP` и `ExtractZIPSignerCertificate` независимы. Извлечение сертификата не проверяет ZIP-подпись. Если нужны оба результата, сначала вызывайте `VerifyZIP`.

## Проверки

```sh
make check
```

```sh
KALKANCRYPT_LIBRARY=/opt/kalkan/lib/libkalkancryptwr-64.so \
KALKANCRYPT_SDK_ASSETS=./testdata \
LD_LIBRARY_PATH=/opt/kalkan/lib \
make test-native
```

`make docker-test` ожидает Linux-библиотеки SDK в `.local/kalkancrypt/lib/linux/`.

В Windows:

```powershell
$env:KALKANCRYPT_LIBRARY = "C:\KalkanCrypt\KalkanCrypt.dll"
go test ./...
```

## Правила проекта

- [Участие в разработке](.github/CONTRIBUTING.md)
- [Политика безопасности](.github/SECURITY.md)
- [Кодекс поведения](.github/CODE_OF_CONDUCT.md)
- [Лицензия MIT](LICENSE.md)

Лицензия репозитория не предоставляет прав на бинарные файлы KalkanCrypt SDK.
