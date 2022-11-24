// Package app implements the middleware and the URL required to run the api
package app

import (
	"ValueStory/auth-valuestory-io/logger"

	"github.com/gin-gonic/gin"
)

// corsMiddleware handles the CORS Headers
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST,HEAD,PATCH, OPTIONS, GET, PUT")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

var (
	router = gin.Default()
)

// StartApplication is called by main function to start the api
func StartApplication() {
	router.Use(corsMiddleware())
	// Disable log's color
	gin.DisableConsoleColor()
	gin.SetMode(gin.ReleaseMode)
	MapUrls(router)
	logger.Info("About to Start the application")
	router.Run(":8080")
}
