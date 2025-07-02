// internal/handlers/auth.go

package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"medods/internal/models"
	"medods/internal/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	DB *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{DB: db}
}

// type tokenRequest struct {
// 	ID string `json:"id"` // GUID пользователя
// }

// tokenResponse represents tokens returned to client
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// refreshRequest represents refresh token request body
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// GenerateToken godoc
// @Summary Generate access and refresh tokens for a user by user ID
// @Description Generates JWT access token and refresh token session. If user does not exist, creates user with given userId.
// @Tags auth
// @Accept json
// @Produce json
// @Param userId path string true "User ID (GUID)"
// @Success 200 {object} tokenResponse
// @Failure 400 {string} string "missing user id"
// @Failure 500 {string} string "internal server error"
// @Router /auth/token/{userId} [post]
func (h *Handler) GenerateToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]

	if userID == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	exists, err := models.UserExists(ctx, h.DB, userID)
	if err != nil {
		log.Printf("error checking user existence: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !exists {
		err := models.CreateUserWithID(ctx, h.DB, userID)
		if err != nil {
			log.Printf("failed to create user: %v", err)
			http.Error(w, "failed to create user", http.StatusInternalServerError)
			return
		}
	}

	accessToken, _, err := utils.GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	rawRefresh := utils.GenerateUUID()
	hashedRefresh, err := utils.HashPassword(rawRefresh)
	if err != nil {
		http.Error(w, "failed to hash refresh token", http.StatusInternalServerError)
		return
	}

	session := &models.Session{
		ID:           utils.GenerateUUID(),
		UserID:       userID,
		RefreshToken: hashedRefresh,
		UserAgent:    r.Header.Get("User-Agent"),
		IP:           utils.GetIPFromRequest(r),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	if err := models.InsertSession(h.DB, session); err != nil {
		log.Printf("failed to store session: %v", err)
		http.Error(w, "failed to store session", http.StatusInternalServerError)
		return
	}

	resp := tokenResponse{
		AccessToken:  accessToken,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(rawRefresh)),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RefreshToken godoc
// @Summary Refresh access and refresh tokens using refresh token and user ID
// @Description Validates refresh token and user ID, issues new tokens.
// @Tags auth
// @Accept json
// @Produce json
// @Param userId path string true "User ID (GUID)"
// @Param refreshRequest body refreshRequest true "Refresh token request body"
// @Success 200 {object} tokenResponse
// @Failure 400 {string} string "invalid refresh request"
// @Failure 401 {string} string "invalid or expired refresh token / unauthorized device"
// @Security AccessToken
// @Router /auth/refresh/{userId} [post]
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest

	vars := mux.Vars(r)
	userID := vars["userId"]

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" || userID == "" {
		http.Error(w, "invalid refresh request", http.StatusBadRequest)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		http.Error(w, "invalid token encoding", http.StatusBadRequest)
		return
	}
	rawToken := string(raw)

	sessions, err := models.GetSessionsByUserID(h.DB, userID)
	if err != nil || len(sessions) == 0 {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	var session *models.Session
	for _, s := range sessions {
		if bcrypt.CompareHashAndPassword([]byte(s.RefreshToken), []byte(rawToken)) == nil {
			session = &s
			break
		}
	}

	if session == nil || session.ExpiresAt.Before(time.Now()) {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	userAgent := r.Header.Get("User-Agent")
	ip := utils.GetIPFromRequest(r)

	if session.UserAgent != userAgent {
		_ = models.DeleteSession(h.DB, session.ID)
		http.Error(w, "unauthorized device", http.StatusUnauthorized)
		return
	}

	if session.IP != ip {
		go utils.SendIPAlertWebhook(session.UserID, ip, userAgent)
	}

	accessToken, _, err := utils.GenerateAccessToken(session.UserID)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	newRaw := utils.GenerateUUID()
	newHash, err := utils.HashPassword(newRaw)
	if err != nil {
		http.Error(w, "failed to hash new refresh token", http.StatusInternalServerError)
		return
	}

	session.RefreshToken = newHash
	session.ExpiresAt = time.Now().Add(24 * time.Hour)
	if err := models.UpdateSession(h.DB, session); err != nil {
		http.Error(w, "failed to update session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:  accessToken,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(newRaw)),
	})
}

// Me godoc
// @Summary Get info about current authenticated user
// @Description Extracts user ID from access token and returns it.
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]string "user_id returned"
// @Failure 401 {string} string "missing token or invalid token"
// @Security AccessToken
// @Router /auth/me [get]
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	token := utils.ExtractBearerToken(authHeader)
	claims, err := utils.ValidateAccessToken(token)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"user_id": claims.UserID})
}

// Logout godoc
// @Summary Logout current user and blacklist access token
// @Description Blacklists current access token and deletes user session.
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]string "message: logged out"
// @Failure 400 {string} string "token has no jti"
// @Failure 401 {string} string "missing or invalid authorization header or token"
// @Failure 500 {string} string "server error or redis error"
// @Security AccessToken
// @Router /auth/logout [get]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := utils.ParseAccessToken(tokenStr)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	log.Printf("Logout — token jti (claims.ID): %s", claims.ID)

	if claims.ID == "" {
		http.Error(w, "token has no jti", http.StatusBadRequest)
		return
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > 0 {
		err := utils.RedisClient.Set(utils.Ctx, claims.ID, "blacklisted", ttl).Err()
		if err != nil {
			http.Error(w, "Redis error", http.StatusInternalServerError)
		}
	}

	// Удаляем сессию пользователя по UserID, UserAgent и IP
	err = models.DeleteSessionByUserID(h.DB, claims.UserID, r.Header.Get("User-Agent"), utils.GetIPFromRequest(r))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}
