package database

import (
    "database/sql"
    "fmt"
    "os"

    _ "github.com/lib/pq"
)

func InitDB() (*sql.DB, error) {
    dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
        os.Getenv("POSTGRES_USER"),
        os.Getenv("POSTGRES_PASSWORD"),
        os.Getenv("POSTGRES_HOST"),
        os.Getenv("POSTGRES_PORT"),
        os.Getenv("POSTGRES_DB"),
    )
    return sql.Open("postgres", dsn)
}