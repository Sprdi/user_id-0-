package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		fmt.Println("Received token:", tokenString) // Added log
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Anda tidak bisa mengakses halaman ini. Silahkan Login Terlebih Dahulu atau Anda Bisa Register Terlebih Dahulu Kepada Admin"})
			c.Abort()
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Metode penandatanganan tidak sesuai")
			}
			return []byte("rahasia"), nil
		})

		if err != nil {
			fmt.Println("Error parsing token:", err) // Added log
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("username", claims["username"])
			c.Set("role", claims["role"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			c.Abort()
			return
		}
	}
}

func RoleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "Akses tidak diizinkan"})
			c.Abort()
			return
		}
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Parse token and get userID
		userID, err := parseToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set userID to context
		c.Set("userID", userID)
		c.Next()
	}
}

// parseToken parses the JWT token and returns the userID
func parseToken(tokenString string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("rahasia"), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			return 0, fmt.Errorf("user_id not found in token claims")
		}
		return uint(userIDFloat), nil
	}

	return 0, fmt.Errorf("invalid token")
}