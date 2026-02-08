package helper

// import (
// 	"crypto/x509"
// 	"github.com/Dhananjay-B/PostQ/internal/model"
// )

// func ParseTLSCertificate(cert *x509.Certificate) model.TLSCertificate {
// 	return model.TLSCertificate{
// 		Subject:            cert.Subject.String(),
// 		Issuer:             cert.Issuer.String(),
// 		NotBefore:          cert.NotBefore.Format("2006-01-02 15:04:05"),
// 		NotAfter:           cert.NotAfter.Format("2006-01-02 15:04:05"),
// 		SerialNumber:       cert.SerialNumber.String(),
// 		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
// 		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
// 		PublicKey: 			cert.PublicKey,
// 	}
// }