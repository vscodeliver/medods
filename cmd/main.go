// @securityDefinitions.apiKey AccessToken
// @in header
// @name Authorization
// @description Enter your bearer token in the format **Bearer &lt;token>**

package main

import (
	"database/sql"
	"log"
	"medods/internal/handlers"
	"net/http"
	"os"

	_ "github.com/lib/pq"

	"medods/internal/middleware"
	"medods/internal/utils"

	"github.com/gorilla/mux"

	_ "medods/docs"

	httpSwagger "github.com/swaggo/http-swagger"
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

	mux := mux.NewRouter()

	// Роуты без авторизации
	mux.HandleFunc("/auth/token/{userId}", h.GenerateToken).Methods("POST")

	// Роуты с авторизацией — оборачиваем в middleware
	mux.Handle("/auth/me", middleware.AuthMiddleware(http.HandlerFunc(h.Me))).Methods("GET")
	mux.Handle("/auth/logout", middleware.AuthMiddleware(http.HandlerFunc(h.Logout))).Methods("GET")
	mux.Handle("/auth/refresh/{userId}", middleware.AuthMiddleware(http.HandlerFunc(h.RefreshToken))).Methods("POST")

	mux.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
