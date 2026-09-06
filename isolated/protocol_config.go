package isolated

import "github.com/skarm/kalkan"

// libraryConfig carries the worker's [kalkan.Open] options. String bytes travel
// in raw blocks, including invalid UTF-8. Validation and default values are
// supplied by kalkan.Open when the worker applies [libraryConfig.Options].
type libraryConfig struct {
	// CollectObservations enables native-call observations in responses.
	CollectObservations bool
	// LibraryPath is the absolute path to the native shared library.
	LibraryPath string
	// TSAURL overrides the timestamp endpoint; nil omits the option.
	TSAURL *string
	// OCSPURL overrides the default OCSP endpoint; nil omits the option.
	OCSPURL *string
	// Proxy configures the native HTTP proxy; nil omits the option.
	Proxy *kalkan.Proxy
	// TrustedCertificates are loaded into the worker's trust store at startup.
	TrustedCertificates []kalkan.TrustedCertificate
	// MaxInputSize is passed to [kalkan.WithMaxInputSize].
	MaxInputSize int64
	// MaxOutputBufferSize is passed to [kalkan.WithMaxOutputBufferSize].
	MaxOutputBufferSize int
	// AtomicZIPOutput enables [kalkan.WithAtomicZIPOutput].
	AtomicZIPOutput bool
	// EndpointPolicy restricts explicit TSA and OCSP URLs; nil omits the policy.
	EndpointPolicy *kalkan.EndpointPolicy
}

func encodeConfig(config libraryConfig) (wirePayload, error) {
	e := payloadEncoder{inputLimit: config.MaxInputSize}
	e.boolean(config.CollectObservations)
	e.text(config.LibraryPath)
	encodeOptional(&e, config.TSAURL, (*payloadEncoder).text)
	encodeOptional(&e, config.OCSPURL, (*payloadEncoder).text)
	encodeOptional(&e, config.Proxy, (*payloadEncoder).proxy)

	if e.length(len(config.TrustedCertificates), config.TrustedCertificates != nil) {
		for _, cert := range config.TrustedCertificates {
			e.trustedCertificate(cert)
		}
	}

	e.int64(config.MaxInputSize)
	e.integer(config.MaxOutputBufferSize)
	e.boolean(config.AtomicZIPOutput)
	encodeOptional(&e, config.EndpointPolicy, (*payloadEncoder).endpointPolicy)

	return e.finish()
}

func decodeConfig(payload wirePayload) (libraryConfig, error) {
	d := decodePayload(payload)
	config := libraryConfig{
		CollectObservations: d.boolean(),
		LibraryPath:         d.text(), TSAURL: decodeOptional(&d, (*payloadDecoder).text),
		OCSPURL: decodeOptional(&d, (*payloadDecoder).text), Proxy: decodeOptional(&d, (*payloadDecoder).proxy),
	}

	count := d.length(24)
	if count >= 0 {
		config.TrustedCertificates = make([]kalkan.TrustedCertificate, count)
		for i := range config.TrustedCertificates {
			config.TrustedCertificates[i] = d.trustedCertificate()
		}
	}

	config.MaxInputSize = d.int64()
	config.MaxOutputBufferSize = d.integer()
	config.AtomicZIPOutput = d.boolean()
	config.EndpointPolicy = decodeOptional(&d, (*payloadDecoder).endpointPolicy)

	return config, d.finish()
}

func (e *payloadEncoder) endpointPolicy(policy kalkan.EndpointPolicy) {
	encodeStrings(e, policy.AllowedHosts)
	encodeStrings(e, policy.AllowedPorts)
	e.boolean(policy.RequireHTTPS)
	e.boolean(policy.AllowIPAddresses)
}

func (d *payloadDecoder) endpointPolicy() kalkan.EndpointPolicy {
	return kalkan.EndpointPolicy{AllowedHosts: decodeStrings[string](d), AllowedPorts: decodeStrings[string](d), RequireHTTPS: d.boolean(), AllowIPAddresses: d.boolean()}
}

func encodeStrings[S ~string](e *payloadEncoder, values []S) {
	if !e.length(len(values), values != nil) {
		return
	}

	for _, value := range values {
		e.text(string(value))
	}
}

func decodeStrings[S ~string](d *payloadDecoder) []S {
	count := d.length(4)
	if count < 0 {
		return nil
	}

	values := make([]S, count)
	for i := range values {
		values[i] = S(d.text())
	}

	return values
}

// Options returns options for [kalkan.Open], which validates their values and
// applies defaults. Options does not load the library or validate configuration.
func (config libraryConfig) Options() []kalkan.Option {
	options := []kalkan.Option{
		kalkan.WithLibraryPath(config.LibraryPath),
		kalkan.WithMaxInputSize(config.MaxInputSize),
		kalkan.WithMaxOutputBufferSize(config.MaxOutputBufferSize),
	}

	if config.TSAURL != nil {
		options = append(options, kalkan.WithTSAURL(*config.TSAURL))
	}

	if config.OCSPURL != nil {
		options = append(options, kalkan.WithOCSPURL(*config.OCSPURL))
	}

	if config.Proxy != nil {
		options = append(options, kalkan.WithProxy(*config.Proxy))
	}

	for _, certificate := range config.TrustedCertificates {
		options = append(options, kalkan.WithTrustedCertificate(certificate))
	}

	if config.AtomicZIPOutput {
		options = append(options, kalkan.WithAtomicZIPOutput())
	}

	if config.EndpointPolicy != nil {
		options = append(options, kalkan.WithEndpointPolicy(*config.EndpointPolicy))
	}

	return options
}
