package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	handler "github.com/Dhananjay-B/PostQ/api/handlers"
)

func main() {
	router := gin.Default()
	router.Use(cors.Default())

	v1 := router.Group("/api/v1")
	{
		v1.POST("/scan/tls", handler.ScanTLSHandler)

	}

	router.Run("localhost:8080")
}
