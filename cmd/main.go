package main

import (
	"database/sql"
	"log"
	"medods/internal/handlers"
	_ "github.com/lib/pq"
	"net/http"
	"os"
    
    "medods/internal/utils"
    "medods/internal/middleware"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

    redisAddr := os.Getenv("REDIS_ADDR")
    if redisAddr == "" {
        redisAddr = "redis:6379"
    }
    err = utils.InitRedis(redisAddr)
    if err != nil {
        log.Fatalf("failed to connect redis: %v", err)
    }

	h := handlers.NewHandler(db)

    mux := http.NewServeMux()
    
    // Роуты без авторизации
    mux.HandleFunc("/api/register", h.Register)
    mux.HandleFunc("/api/login", h.Login)

    // Роуты с авторизацией — оборачиваем в middleware
    mux.Handle("/api/me", middleware.AuthMiddleware(http.HandlerFunc(h.Me)))
    mux.Handle("/api/logout", middleware.AuthMiddleware(http.HandlerFunc(h.Logout)))
    mux.Handle("/api/refresh", middleware.AuthMiddleware(http.HandlerFunc(h.Refresh)))

    log.Println("Server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
