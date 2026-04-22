package handlers

import (
	"github.com/gin-gonic/gin"

	tlsanalysis "github.com/Dhananjay-B/PostQ/internal/analysis/tlsanalysis"
	tlsmodel "github.com/Dhananjay-B/PostQ/internal/model/tlsmodels"
	probe "github.com/Dhananjay-B/PostQ/internal/probe"
)

func ScanTLSHandler(c *gin.Context) {
	var target tlsmodel.TLSTarget

	if err := c.ShouldBindJSON(&target); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	tlsProbe, err := probe.ScanTLS(target)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to scan TLS"})
		return
	}

	risks, err := tlsanalysis.AnalyzeTLSProbe(tlsProbe)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to analyze TLS probe"})
		return
	}

	c.JSON(200, risks)
}
