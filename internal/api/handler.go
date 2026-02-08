package api

import (
	"database/sql"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/Dhananjay-B/PostQ/internal/model"
	"github.com/Dhananjay-B/PostQ/internal/model/db/tls"
	"github.com/Dhananjay-B/PostQ/internal/probe"
)

type Handler struct {
	DB *sql.DB
}

//......................................//
// 			TLS assets endpoints		//
//......................................//

func (handler *Handler) ListTLSAssets(c *gin.Context) {
	rows, err := handler.DB.Query("SELECT * FROM tls.assets")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	defer rows.Close()

	assets := []tls.TLSAsset{}

	for rows.Next() {
		var asset tls.TLSAsset
		err := rows.Scan(&asset.AssetID, &asset.Endpoint, &asset.Port, &asset.CreatedAt)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		assets = append(assets, asset)
	}

	c.JSON(200, gin.H{"status": "ok", "assets": assets})
}

func (handler *Handler) GetTLSAsset(c *gin.Context) {
	id := c.Param("asset_id")
	assetID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid asset_id"})
		return
	}
	asset, err := handler.GetTLSAssetByID(int(assetID))
	if err != nil {
		c.JSON(404, gin.H{"error": "Asset not found"})
		return
	}
	c.JSON(200, gin.H{"status": "ok", "asset": asset})
}

func (handler *Handler) CreateTLSAsset(c *gin.Context) {
	var newAsset tls.TLSAsset
	_ = c.BindJSON(&newAsset)

	_, err := handler.DB.Exec("INSERT INTO tls.assets (endpoint, port) VALUES ($1, $2)", newAsset.Endpoint, newAsset.Port)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

func (handler *Handler) DeleteTLSAsset(c *gin.Context) {
	id := c.Param("asset_id")
	_, err := handler.DB.Exec("DELETE FROM tls.assets WHERE asset_id = $1", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

func (handler *Handler) GetTLSAssetByID(assetID int) (*tls.TLSAsset, error) {
	row := handler.DB.QueryRow("SELECT asset_id, endpoint, port, created_at FROM tls.assets WHERE asset_id = $1", assetID)

	var asset tls.TLSAsset
	err := row.Scan(&asset.AssetID, &asset.Endpoint, &asset.Port, &asset.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

//......................................//
// 			TLS scan endpoints		    //
//......................................//

func (handler *Handler) ListTLSScans(c *gin.Context) {
	rows, err := handler.DB.Query("SELECT * FROM tls.scans")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	scans := []tls.TLSScan{}

	for rows.Next() {
		var scan tls.TLSScan
		err := rows.Scan(&scan.ScanID, &scan.AssetID, &scan.StartedAt, &scan.Status, &scan.FinishedAt)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		scans = append(scans, scan)
	}
	c.JSON(200, gin.H{"status": "ok", "scans": scans})
}

func (handler *Handler) CreateTLSScan(c *gin.Context) {
	assetID := c.Param("asset_id")
	var scan tls.TLSScan
	err := handler.DB.QueryRow("INSERT INTO tls.scans (asset_id, status) VALUES ($1, 'running') RETURNING scan_id, asset_id, started_at, finished_at, status", assetID).Scan(&scan.ScanID, &scan.AssetID, &scan.StartedAt, &scan.FinishedAt, &scan.Status)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	go handler.startTLSScan(scan.AssetID, scan.ScanID)

	c.JSON(201, gin.H{"status": "ok", "scan": scan})
}

func (handler *Handler) GetTLSScanResults(c *gin.Context) {
	scanID := c.Param("scan_id")
	rows, err := handler.DB.Query("SELECT scan_id, tls_version, cipher_suite, server_name FROM tls.scan_results WHERE scan_id = $1", scanID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	results := []tls.ScanResult{}
	for rows.Next() {
		var result tls.ScanResult
		err := rows.Scan(&result.ScanID, &result.TLSVersion, &result.CipherSuite, &result.ServerName)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		results = append(results, result)
	}
	c.JSON(200, gin.H{"status": "ok", "results": results})
}

func (handler *Handler) startTLSScan(assetID, scanID int) {
	asset, err := handler.GetTLSAssetByID(assetID)
	if err != nil {
		return
	}
	endpoint := model.Endpoint{
		HostName: asset.Endpoint,
		Port:     asset.Port,
	}
	tlsRaw, err := probe.ScanTLS(endpoint)
	if err != nil {
		handler.markScanFailed(scanID, err)
		return
	}
	handler.markScanCompleted(scanID)
	handler.DB.Exec(`
		INSERT INTO tls.scan_results (scan_id, tls_version, cipher_suite, server_name)
		VALUES ($1, $2, $3, $4)
	`, scanID, tlsRaw.Version, tlsRaw.CipherSuite, tlsRaw.ServerName)

	peerCertificates := tlsRaw.PeerCertificates
	for _, cert := range peerCertificates {
		handler.DB.Exec(`
			INSERT INTO tls.certificates (scan_id, position, subject_dn, issuer_dn, serial_number, not_before, not_after, public_key_algorithm, signature_algorithm, is_ca, is_self_signed)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, scanID, cert.Position, cert.SubjectDN, cert.IssuerDN, cert.SerialNumber, cert.NotBefore, cert.NotAfter, cert.PublicKeyAlg, cert.SignatureAlg, cert.IsCA, cert.IsSelfSigned)
	}
}

func (handler *Handler) markScanCompleted(scanID int) {
	handler.DB.Exec(`
		UPDATE tls.scans
		SET status = 'completed', finished_at = now()
		WHERE scan_id = $1
	`, scanID)
}

func (handler *Handler) markScanFailed(scanID int, err error) {
	handler.DB.Exec(`
		UPDATE tls.scans
		SET status = 'failed', finished_at = now()
		WHERE scan_id = $1
	`, scanID)
}
