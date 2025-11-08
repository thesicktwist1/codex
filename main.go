package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	Addr := os.Getenv("REDIS_URL")
	if Addr == "" {
		log.Fatal("REDIS_URL environment variable is not set")
	}
	redisDB := redis.NewClient(&redis.Options{
		Addr:     Addr,
		DB:       0,
		Username: "Example",
	})
	_ = NewConfig(redisDB)

}
