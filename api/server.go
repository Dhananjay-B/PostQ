package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	handler "github.com/Dhananjay-B/PostQ/api/handlers"
)

func StartServer() error {
	router := gin.Default()
	router.Use(cors.Default())

	v1 := router.Group("/api/v1")
	{
		v1.POST("/scan/tls", handler.ScanTLSHandler)

	}

	if err := router.Run(":8080"); err != nil {
		return err
	}
	return nil
}
