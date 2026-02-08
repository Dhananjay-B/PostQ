package config

import (
	"os"

	"github.com/joho/godotenv"
)

type DBConfig struct {
	Name     string
	User     string
	Password string
	Host     string
	Port     string
}

type AppConfig struct {
	Host string
	Port string
}

func LoadDBConfig() *DBConfig {
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}
	return &DBConfig{
		Name:     os.Getenv("DB_NAME"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
	}
}

func LoadAppConfig() *AppConfig {
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}
	return &AppConfig{
		Host: os.Getenv("APP_HOST"),
		Port: os.Getenv("APP_PORT"),
	}
}
