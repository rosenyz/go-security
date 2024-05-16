package main

import (
	"go-security/config"
	"go-security/internal/database"
	"go-security/internal/handlers"
	"go-security/internal/middleware"
	"go-security/internal/models"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Config{
		DB: config.DBConfig{
			Dialect: "postgres",
			URL:     "host=localhost user=postgres dbname=go-security sslmode=disable password=pass",
		},
		JWT: config.JWTConfig{
			Secret:             "secret-go-security-SOSFIJofis9afh9sa",
			Issuer:             "issuer",
			ExpirationTime:     5 * time.Minute,
			TokenLookup:        "user",
			AuthScheme:         "Bearer",
			SigningAlgorithm:   "HS256",
			DisableAutoRefresh: false,
		},
		ServerAddr: ":8080",
	}

	db, err := database.Connect(cfg)
	if err != nil {
		panic("Failed to connect to db")
	}
	defer db.Close()

	db.AutoMigrate(&models.User{})

	jwtMiddleware := middleware.JWTAuthMiddleware(cfg)

	r := gin.Default()

	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", handlers.RegisterHandler(db))
		authGroup.POST("/login", handlers.LoginHandler(db, cfg))
	}

	userGroup := r.Group("/user")
	userGroup.Use(jwtMiddleware)
	{
		userGroup.GET("/:id", handlers.GetUserIdHandler(db))
		userGroup.GET("/profile", handlers.GetUsernameHandler(db))
	}

	r.Run(cfg.ServerAddr)
}
