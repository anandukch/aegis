package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/anandudevops/aegis/internal/auth"
	"github.com/anandudevops/aegis/internal/db"
	"github.com/anandudevops/aegis/internal/middleware"
	"github.com/anandudevops/aegis/internal/vault"
	"github.com/anandudevops/aegis/pkg/response"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var startTime = time.Now()

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, using environment variables")
	}

	database, err := db.Connect()
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}

	authRepo := auth.NewRepository(database)
	authSvc := auth.NewService(authRepo)
	authHandler := auth.NewHandler(authSvc)

	vaultRepo := vault.NewRepository(database)
	vaultSvc := vault.NewService(vaultRepo)
	vaultHandler := vault.NewHandler(vaultSvc)

	if os.Getenv("APP_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		response.Success(c, 200, gin.H{
			"status":  "ok",
			"version": "1.0.0",
			"uptime":  fmt.Sprintf("%.0fs", time.Since(startTime).Seconds()),
		})
	})

	authGroup := r.Group("/api/v1/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
	}

	api := r.Group("/api/v1", middleware.Auth())
	{
		api.POST("/vault/tokenize", vaultHandler.Tokenize)
		api.POST("/vault/detokenize", vaultHandler.Detokenize)
		api.GET("/vault/:token/metadata", vaultHandler.GetMetadata)
	}

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("server starting on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server: %v", err)
	}
}
