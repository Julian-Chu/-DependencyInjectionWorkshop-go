package AuthenticationService

import (
	"database/sql"
	"net/http"
)

type ProfileDao struct {
	client *http.Client
}

func (p ProfileDao) getPasswordFromDB(accountId string) (string, error) {
	// Get password from DB
	db, err := sql.Open("postgres", "my connection string")
	if err != nil {
		return "", err
	}
	row := db.QueryRow("call spGetUserPassword($1)", accountId)
	var passwordFromDB string
	if err := row.Scan(&passwordFromDB); err != nil {
		return "", err
	}
	return passwordFromDB, nil
}
