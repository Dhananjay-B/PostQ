package tlsmodels

type QuantumAssessment struct {
	Asset       string
	Findings    []string
	Description []string
	Risks       []string
	Severity    string // Informational, Critical, High, Medium, Low, None
}

type TLSProtocolQuantum struct {
	HighestVersion           string
	LowestVersion            string
	TLS13Enabled             bool
	TLS12Enabled             bool
	LegacyEnabled            bool
	ClassicalFallbackPresent bool

	PQMigrationReady    bool
	HybridBypassSurface bool
	QuantumAssessment   []QuantumAssessment
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
	QuantumAssessment           []QuantumAssessment
}

type TLSCipherQuantum struct {
	PerVersion                 []TLSVersionCipherQuantum
	AnyStaticRSA               bool
	AnyForwardSecrecy          bool
	AllKeyExchangesClassical   bool
	AllAuthenticationClassical bool
	HarvestNowDecryptLaterRisk bool
	QuantumAssessment          []QuantumAssessment
}
