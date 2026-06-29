package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/anandudevops/aegis/internal/audit"
	"github.com/anandudevops/aegis/internal/auth"
	"github.com/anandudevops/aegis/internal/db"
	"github.com/anandudevops/aegis/internal/middleware"
	"github.com/anandudevops/aegis/internal/rbac"
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

	auditRepo := audit.NewRepository(database)
	auditSvc := audit.NewService(auditRepo)
	auditHandler := audit.NewHandler(auditSvc)

	rbacRepo := rbac.NewRepository(database)
	rbacSvc := rbac.NewService(rbacRepo)

	authRepo := auth.NewRepository(database)
	authSvc := auth.NewService(authRepo, rbacSvc)
	authHandler := auth.NewHandler(authSvc)
	rbacHandler := rbac.NewHandler(rbacSvc, authSvc)

	vaultRepo := vault.NewRepository(database)
	vaultSvc := vault.NewService(vaultRepo, rbacSvc)
	vaultHandler := vault.NewHandler(vaultSvc, auditSvc)

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
		api.DELETE("/vault/:token", middleware.RequireRole("ADMIN"), vaultHandler.Delete)
		api.GET("/vault/:token/metadata", vaultHandler.GetMetadata)

		api.GET("/roles", rbacHandler.GetRoles)
		api.POST("/users/:id/role", middleware.RequireRole("ADMIN"), rbacHandler.AssignRole)

		rbacGroup := api.Group("/rbac", middleware.RequireRole("ADMIN"))
		{
			rbacGroup.POST("/roles", rbacHandler.CreateRole)
			rbacGroup.GET("/roles", rbacHandler.ListRoles)
			rbacGroup.GET("/roles/:id", rbacHandler.GetRole)
			rbacGroup.PUT("/roles/:id", rbacHandler.UpdateRole)
			rbacGroup.DELETE("/roles/:id", rbacHandler.DeleteRole)
			rbacGroup.POST("/roles/:id/permissions", rbacHandler.SetPermission)
			rbacGroup.DELETE("/roles/:id/permissions/:field_type", rbacHandler.DeletePermission)
		}

		api.GET("/audit/logs", middleware.RequireRole("ADMIN"), auditHandler.GetLogs)
		api.GET("/audit/logs/:token", middleware.RequireRole("ADMIN"), auditHandler.GetLogsByToken)
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
