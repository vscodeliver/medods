package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Здесь должен быть инициализирован Redis клиент и контекст
var (
	jwtSecret   = []byte("your_secret_key") // замените на ваш секрет
)

// CustomClaims расширяет jwt.RegisteredClaims, добавляя UserID и JTI (уникальный ID токена)
type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateUUID — простой генератор UUID
func GenerateUUID() string {
	return uuid.NewString()
}

// GenerateAccessToken создает JWT access токен с JTI
func GenerateAccessToken(userID string) (string, string, error) {
    jti := uuid.NewString() // Генерируем уникальный jti

    claims := &CustomClaims{
        UserID: userID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ID:        jti, // Уникальный ID токена (jti)
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenStr, err := token.SignedString(jwtSecret)
    if err != nil {
        return "", "", err
    }

    return tokenStr, jti, nil
}

// ValidateAccessToken проверяет токен и смотрит blacklist в Redis по JTI
func ValidateAccessToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func ParseAccessToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// ExtractBearerToken извлекает токен из заголовка Authorization
func ExtractBearerToken(header string) string {
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return ""
}

// HashPassword хеширует пароль bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash проверяет пароль и хеш
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// SendIPAlertWebhook отправляет webhook при смене IP
func SendIPAlertWebhook(userID, newIP, userAgent string) error {
	webhookURL := "https://your-webhook-url.example.com/alert" // замените на ваш URL

	payload := map[string]string{
		"user_id":    userID,
		"new_ip":     newIP,
		"user_agent": userAgent,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with status %d", resp.StatusCode)
	}

	return nil
}
