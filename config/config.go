package config

import "time"

type Config struct {
	DB         DBConfig
	JWT        JWTConfig
	ServerAddr string
}

type DBConfig struct {
	Dialect string
	URL     string
}

type JWTConfig struct {
	Secret           string
	ExpirationTime   time.Duration
	TokenLookup      string
	SigningAlgorithm string
}
