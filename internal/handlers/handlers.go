package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"medods/internal/models"
	"medods/internal/utils"
	"net"
	"net/http"
	"strings"
	"time"
	"log"
)

type Handler struct {
	DB *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{DB: db}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	_, err := models.GetUserByEmail(h.DB, req.Email)
	if err == nil {
		http.Error(w, "email already in use", http.StatusBadRequest)
		return
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	user := &models.User{
		ID:           utils.GenerateUUID(),
		Email:        req.Email,
		PasswordHash: hashedPassword,
		CreatedAt:    time.Now(),
	}

	if err := models.InsertUser(h.DB, user); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id":    user.ID,
		"email": user.Email,
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := models.GetUserByEmail(h.DB, req.Email)
	if err != nil {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	if !utils.CheckPasswordHash(req.Password, user.PasswordHash) {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	accessToken, _, err := utils.GenerateAccessToken(user.ID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	rawRefreshToken := utils.GenerateUUID()
	hashedRefreshToken, err := utils.HashPassword(rawRefreshToken)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	session := &models.Session{
		ID:           utils.GenerateUUID(),
		UserID:       user.ID,
		RefreshToken: hashedRefreshToken,
		UserAgent:    r.Header.Get("User-Agent"),
		IP:           getIPFromRequest(r),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	if err := models.InsertSession(h.DB, session); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(loginResponse{
		AccessToken:  accessToken,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(rawRefreshToken)),
		SessionID:    session.ID,
	})
}

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
	err = models.DeleteSessionByUserID(h.DB, claims.UserID, r.Header.Get("User-Agent"), getIPFromRequest(r))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}

type refreshRequest struct {
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" || req.SessionID == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		http.Error(w, "invalid token encoding", http.StatusBadRequest)
		return
	}
	rawToken := string(decoded)

	session, err := models.GetSessionByID(h.DB, req.SessionID)
	if err != nil {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}
	if session == nil || session.ExpiresAt.Before(time.Now()) {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	if !utils.CheckPasswordHash(rawToken, session.RefreshToken) {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	userAgent := r.Header.Get("User-Agent")
	ip := getIPFromRequest(r)

	if session.UserAgent != userAgent {
		_ = models.DeleteSession(h.DB, session.ID)
		http.Error(w, "unauthorized device", http.StatusUnauthorized)
		return
	}

	if session.IP != ip {
		go utils.SendIPAlertWebhook(session.UserID, ip, userAgent)
	}

	newAccessToken, _, err := utils.GenerateAccessToken(session.UserID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	newRawRefresh := utils.GenerateUUID()
	newHash, err := utils.HashPassword(newRawRefresh)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	session.RefreshToken = newHash
	session.ExpiresAt = time.Now().Add(24 * time.Hour)

	if err := models.UpdateSession(h.DB, session); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(loginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(newRawRefresh)),
		SessionID:    session.ID,
	})
}

// getIPFromRequest extracts only the IP address without port
func getIPFromRequest(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
