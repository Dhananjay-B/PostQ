package api

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	"github.com/Dhananjay-B/PostQ/internal/config"
)

func GetDatabaseConnection() *sql.DB {
	databaseConfig := config.LoadDBConfig()

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		databaseConfig.Host, databaseConfig.Port, databaseConfig.User, databaseConfig.Password, databaseConfig.Name)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	return db
}
