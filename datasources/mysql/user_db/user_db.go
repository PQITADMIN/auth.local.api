// Package userdb provides connection for user database
package userdb

import (
	"ValueStory/auth-valuestory-io/datasources/config"
	"database/sql"
	"fmt"
	"log"

	// The driver should be used via the database/sql package
	_ "github.com/go-sql-driver/mysql"
)

var (
	// Client is exported to that other packages can refer and use it
	Client *sql.DB
)

func init() {

	datasourceName := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8",
		"root",
		config.MYSQLPassword,
		config.MYSQLHost,
		"auth-api",
	)
	//datasourceName := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8", username, password, host, schema)
	var err error
	Client, err = sql.Open("mysql", datasourceName)
	if err != nil {
		panic(err)
	}
	if err = Client.Ping(); err != nil {
		panic(err)
	}
	log.Printf("User database successfully configured")
}
