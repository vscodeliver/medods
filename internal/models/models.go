// cmd/models/models.go

package models

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type Session struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	RefreshToken string    `db:"refresh_token"`
	UserAgent    string    `db:"user_agent"` // new field
	IP           string    `db:"ip"`         // new field
	CreatedAt    time.Time `db:"created_at"`
	ExpiresAt    time.Time `db:"expires_at"`
}

func InsertUser(db *sql.DB, u *User) error {
	_, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)`,
		u.ID, u.Email, u.PasswordHash, time.Now())
	return err
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	u := &User{}
	err := db.QueryRow(`SELECT id, email, password_hash, created_at FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	return u, err
}

func InsertSession(db *sql.DB, s *Session) error {
	_, err := db.Exec(`INSERT INTO sessions (id, user_id, refresh_token, user_agent, ip, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		s.ID, s.UserID, s.RefreshToken, s.UserAgent, s.IP, s.ExpiresAt, s.CreatedAt)
	return err
}

func UserExists(ctx context.Context, db *sql.DB, userID string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`
	err := db.QueryRowContext(ctx, query, userID).Scan(&exists)
	return exists, err
}

func CreateUserWithID(ctx context.Context, db *sql.DB, userID string) error {
	// Insert user with only ID, no email or password_hash
	query := `INSERT INTO users (id) VALUES ($1)`
	_, err := db.ExecContext(ctx, query, userID)
	return err
}

func UpdateSession(db *sql.DB, s *Session) error {
	_, err := db.Exec(`UPDATE sessions SET refresh_token = $1, expires_at = $2 WHERE id = $3`,
		s.RefreshToken, s.ExpiresAt, s.ID)
	return err
}

func DeleteSession(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func GetSessionByRefreshToken(db *sql.DB, refreshTokenHash string) (*Session, error) {
	var session Session
	query := "SELECT id, user_id, refresh_token, user_agent, ip, created_at, expires_at FROM sessions WHERE refresh_token = $1"
	err := db.QueryRow(query, refreshTokenHash).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.UserAgent,
		&session.IP,
		&session.CreatedAt,
		&session.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func DeleteSessionByUserID(db *sql.DB, userID, userAgent, ip string) error {
	query := `DELETE FROM sessions WHERE user_id = $1 AND user_agent = $2 AND ip = $3`
	_, err := db.Exec(query, userID, userAgent, ip)
	return err
}

func GetSessionByID(db *sql.DB, id string) (*Session, error) {
	var session Session
	query := "SELECT id, user_id, refresh_token, user_agent, ip, created_at, expires_at FROM sessions WHERE id = $1"
	err := db.QueryRow(query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.UserAgent,
		&session.IP,
		&session.CreatedAt,
		&session.ExpiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &session, nil
}

func GetSessionsByUserID(db *sql.DB, userID string) ([]Session, error) {
	rows, err := db.Query(`SELECT id, user_id, refresh_token, user_agent, ip, created_at, expires_at FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.RefreshToken, &s.UserAgent, &s.IP, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}
