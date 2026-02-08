package tls

type TLSAsset struct {
	AssetID   int    `json:"asset_id"`
	Endpoint  string `json:"endpoint"`
	Port      int    `json:"port"`
	CreatedAt string `json:"created_at"`
}
