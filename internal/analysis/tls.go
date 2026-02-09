package analysis

import (
	"database/sql"

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
		CertID              int64
		PublicKeyAlg        string
		PublicKeyAlgQVuln   bool
		SignatureAlg        string
		SignatureAlgQVuln   bool
		IsQuantumVulnerable bool
	}

	vulnerabilityResults := []CertificateVulnerabilityAnalysis{}

	for _, cert := range peer_certificates {
		analysis := CertificateVulnerabilityAnalysis{
			CertID:       cert.CertID,
			PublicKeyAlg: cert.PublicKeyAlg,
			SignatureAlg: cert.SignatureAlg,
		}

		for _, alg := range standard_algorithms {
			if alg.AlgorithmName == cert.PublicKeyAlg && alg.Role == "key_exchange" && alg.QuantumVulnerable {
				analysis.PublicKeyAlgQVuln = true
			}
			if alg.AlgorithmName == cert.SignatureAlg && alg.Role == "signature" && alg.QuantumVulnerable {
				analysis.SignatureAlgQVuln = true
			}
		}

		analysis.IsQuantumVulnerable = analysis.PublicKeyAlgQVuln || analysis.SignatureAlgQVuln
		vulnerabilityResults = append(vulnerabilityResults, analysis)
	}
}
