package tls

type TLSScan struct {
	ScanID     int    `json:"scan_id"`
	AssetID    int    `json:"asset_id"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Status     string `json:"status"`
}
