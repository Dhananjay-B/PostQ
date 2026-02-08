package main

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/Dhananjay-B/PostQ/internal/api"
	"github.com/Dhananjay-B/PostQ/internal/config"
)

func main() {
	// Get configs
	appConfigs := config.LoadAppConfig()

	db := api.GetDatabaseConnection()
	defer db.Close()

	handler := &api.Handler{DB: db}

	router := gin.Default()

	v1 := router.Group("/api/v1")

	{
		tls := v1.Group("/tls")
		{
			// TLS assets endpoints
			tls.GET("/assets", handler.ListTLSAssets)
			tls.GET("/assets/:asset_id", handler.GetTLSAsset)
			tls.POST("/assets", handler.CreateTLSAsset)
			tls.DELETE("/assets/:asset_id", handler.DeleteTLSAsset)

			// TLS scans endpoints
			tls.GET("/scans", handler.ListTLSScans)
			tls.POST("/scans/:asset_id", handler.CreateTLSScan)
			tls.GET("/scans/results/:scan_id", handler.GetTLSScanResults)
		}
	}

	router.Run(fmt.Sprintf("%s:%s", appConfigs.Host, appConfigs.Port))
}
