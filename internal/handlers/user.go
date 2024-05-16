package handlers

import (
	"go-security/internal/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

func GetUserIdHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var user models.User
		if err := db.Where("id = ?", id).First(&user).Error; err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		c.JSON(200, gin.H{"user_id": user.ID})
	}
}

func GetUsernameHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsInterface, ok := c.Get("user")
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token"})
			return
		}

		claims, ok := claimsInterface.(jwt.MapClaims)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token"})
			return
		}

		userID, ok := claims["user_id"].(float64)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token"})
			return
		}

		uintUserID := uint(userID)

		var dbUser models.User
		if err := db.Where("id = ?", uintUserID).First(&dbUser).Error; err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		c.JSON(200, gin.H{
			"username": dbUser.Username,
		})
	}
}
