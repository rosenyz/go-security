package handlers

import (
	"log"
	"time"

	"go-security/config"
	"go-security/internal/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		user.Password = string(hashedPassword)

		if err := db.Create(&user).Error; err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
		}

		c.JSON(201, gin.H{"message": "User created", "user": user})
	}
}

func LoginHandler(db *gorm.DB, cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var inputUser models.User
		if err := c.BindJSON(&inputUser); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
		}

		var dbUser models.User
		if err := db.Where("username = ?", inputUser.Username).First(&dbUser).Error; err != nil {
			c.JSON(401, gin.H{"error": "Invalid username or password"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(inputUser.Password)); err != nil {
			c.JSON(401, gin.H{"error": "Invalid username or password"})
			return
		}

		log.Println(dbUser.Password)
		log.Println(inputUser.Password)

		expirationTime := time.Now().Add(cfg.JWT.ExpirationTime)
		claims := jwt.MapClaims{
			"user_id": dbUser.ID,
			"exp":     expirationTime.Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(cfg.JWT.Secret))
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{
			"message":         "success",
			"token":           tokenString,
			"expiration_time": expirationTime.Format(time.RFC3339),
		})
	}
}
