package analysis

import (
	"database/sql"
	"fmt"

	standardmodel "github.com/Dhananjay-B/PostQ/internal/model/db/standard"
	tlsmodel "github.com/Dhananjay-B/PostQ/internal/model/db/tls"
)

type AnalysisService struct {
	DB *sql.DB
}

func New(db *sql.DB) *AnalysisService {
	return &AnalysisService{DB: db}
}

func (service *AnalysisService) AnalyseTLSScan(scanID int) {
	var scan_result *tlsmodel.ScanResult

	row, err := service.DB.Query("SELECT * FROM tls.scan_results WHERE scan_id = $1", scanID)
	if err != nil {
		return
	}
	defer row.Close()
	scan_result = &tlsmodel.ScanResult{}
	if row.Next() {
		err := row.Scan(&scan_result.ScanID, &scan_result.TLSVersion, &scan_result.CipherSuite, &scan_result.ServerName)
		if err != nil {
			return
		}
	}

	peer_certificates := []*tlsmodel.TLSCertificate{}

	cert_rows, cert_err := service.DB.Query("SELECT * FROM tls.certificates WHERE scan_id = $1", scanID)
	if cert_err != nil {
		return
	}
	defer cert_rows.Close()

	for cert_rows.Next() {
		var cert tlsmodel.TLSCertificate
		err := cert_rows.Scan(&cert.CertID, &cert.ScanID, &cert.Position, &cert.SubjectDN, &cert.IssuerDN, &cert.SerialNumber,
			&cert.NotBefore, &cert.NotAfter, &cert.PublicKeyAlg, &cert.SignatureAlg, &cert.IsCA, &cert.IsSelfSigned)
		if err != nil {
			return
		}
		peer_certificates = append(peer_certificates, &cert)
	}

	// Get standard algorithms info
	var standard_algorithms []standardmodel.Algorithm
	alg_rows, alg_err := service.DB.Query("SELECT algorithm_name, role, quantum_vulnerable, note FROM standard.algorithms")
	if alg_err != nil {
		return
	}
	defer alg_rows.Close()
	for alg_rows.Next() {
		var alg standardmodel.Algorithm
		err := alg_rows.Scan(&alg.AlgorithmName, &alg.Role, &alg.QuantumVulnerable, &alg.Note)
		if err != nil {
			return
		}
		standard_algorithms = append(standard_algorithms, alg)
	}

	type CertificateVulnerabilityAnalysis struct {
		CertID            int64
		PublicKeyAlg      string
		SignatureAlg      string
		PublicKeyAlgQVuln bool
		SignatureAlgQVuln bool
	}

	type ScanVulnerabilityAnalysis struct {
		ScanID                           int
		TLSVersion                       string
		CipherSuite                      string
		ServerName                       string
		PeerCertificates                 []*tlsmodel.TLSCertificate
		TLSVersionVuln                   bool
		KeyExchangeAlgVuln               bool
		CertificateVulnerabilityAnalysis []CertificateVulnerabilityAnalysis
	}

	certVulnerabilityResults := []CertificateVulnerabilityAnalysis{}

	for _, cert := range peer_certificates {
		analysis := CertificateVulnerabilityAnalysis{
			CertID:       cert.CertID,
			PublicKeyAlg: cert.PublicKeyAlg,
			SignatureAlg: cert.SignatureAlg,
		}

		for _, alg := range standard_algorithms {
			if alg.AlgorithmName == cert.PublicKeyAlg && alg.Role == "signature" && alg.QuantumVulnerable {
				analysis.PublicKeyAlgQVuln = true
			}
			if alg.AlgorithmName == cert.SignatureAlg && alg.Role == "signature" && alg.QuantumVulnerable {
				analysis.SignatureAlgQVuln = true
			}
		}
		certVulnerabilityResults = append(certVulnerabilityResults, analysis)
	}

	scanVulnerabilityResults := ScanVulnerabilityAnalysis{
		ScanID:                           scan_result.ScanID,
		TLSVersion:                       scan_result.TLSVersion,
		CipherSuite:                      scan_result.CipherSuite,
		ServerName:                       scan_result.ServerName,
		PeerCertificates:                 peer_certificates,
		TLSVersionVuln:                   isTLSVersionVulnerable(scan_result.TLSVersion),
		KeyExchangeAlgVuln:               isKeyExchangeAlgVulnerable(scan_result.CipherSuite, standard_algorithms),
		CertificateVulnerabilityAnalysis: certVulnerabilityResults,
	}

	fmt.Println(scanVulnerabilityResults)
}

func isKeyExchangeAlgVulnerable(KeyExchangeAlg string, standard_algorithms []standardmodel.Algorithm) bool {
	for _, alg := range standard_algorithms {
		if alg.AlgorithmName == KeyExchangeAlg && alg.Role == "key_exchange" && alg.QuantumVulnerable {
			return true
		}
	}
	return false
}

func isTLSVersionVulnerable(tlsVersion string) bool {
	vulnerableVersions := []string{"TLS 1.2", "TLS 1.1"}
	for _, v := range vulnerableVersions {
		if tlsVersion == v {
			return true
		}
	}
	return false
}
