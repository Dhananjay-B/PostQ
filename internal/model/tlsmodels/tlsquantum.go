package tlsmodels

type TLSProtocolQuantum struct {
	HighestVersion           string
	LowestVersion            string
	TLS13Enabled             bool
	TLS12Enabled             bool
	LegacyEnabled            bool
	ClassicalFallbackPresent bool

	PQMigrationReady    bool
	HybridBypassSurface bool
	QuantumSignals      []string
}

type TLSVersionCipherQuantum struct {
	Version                     string
	KeyExchangeTypes            []string
	AuthenticationTypes         []string
	StaticRSAKeyExchangePresent bool
	ForwardSecrecyPresent       bool
	AllKeyExchangesClassical    bool
	AllAuthenticationClassical  bool
	TLS13Cipher                 bool
}

type TLSCipherQuantum struct {
	PerVersion                 []TLSVersionCipherQuantum
	AnyStaticRSA               bool
	AnyForwardSecrecy          bool
	AllKeyExchangesClassical   bool
	AllAuthenticationClassical bool
	HarvestNowDecryptLaterRisk bool
	QuantumSignals             []string
}
