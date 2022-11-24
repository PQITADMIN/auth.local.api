package redisdb

import (
	"ValueStory/auth-valuestory-io/datasources/config"
	"log"

	"github.com/go-redis/redis"
)

var (
	// Client is the global export for redis instance
	Client *redis.Client
	// RedisSessionClient for redis session
	RedisSessionClient *redis.Client
	redisHost          = config.REDISHost
	redisPassword      = config.REDISPassword
)

func init() {
	//Initializing redis
	Client = redis.NewClient(&redis.Options{
		Network:  "",
		Addr:     redisHost,
		Password: redisPassword,
		DB:       0,
	})
	_, err := Client.Ping().Result()
	if err != nil {
		panic(err)
	}
	//Initiate Session Client
	RedisSessionClient = redis.NewClient(&redis.Options{
		Network:  "",
		Addr:     redisHost,
		Password: redisPassword,
		DB:       1,
	})
	_, err = RedisSessionClient.Ping().Result()
	if err != nil {
		panic(err)
	}
	log.Printf("Redis successfully configured")

}
