package utils

import (
    "context"
    "github.com/redis/go-redis/v9"
    "log"
)

var RedisClient *redis.Client
var Ctx = context.Background()

// func InitRedis(addr, password string, db int) error
func InitRedis(addr string) error {
    RedisClient = redis.NewClient(&redis.Options{
        Addr:     addr,
        // Password: password,
        // DB:       db,
    })

    _, err := RedisClient.Ping(Ctx).Result()
    if err != nil {
        return err
    }
    log.Println("Redis connected")
    return nil
}

func IsTokenBlacklisted(jti string) (bool, error) {
	exists, err := RedisClient.Exists(Ctx, jti).Result()
	if err != nil {
		return false, err
	}
	if exists == 1 {
		return true, nil
	}
	return false, nil
}