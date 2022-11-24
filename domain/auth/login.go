// Package auth implements all functions required for authentication
package auth

import (
	redisdb "ValueStory/auth-valuestory-io/datasources/redis_db"
	"ValueStory/auth-valuestory-io/domain/users"
	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"
	"strings"
)

const (
	errorNowRows                     = "sql: no rows in result set"
	queryGetAllCompanyAccess         = "SELECT user_company.company, domain FROM `user_company` JOIN company  WHERE company.company_name = user_company.company AND user_company.user =?;"
	queryGetAllCompanyAccessExternal = "SELECT user_company.company, ext_domain FROM `user_company` JOIN company  WHERE company.company_name = user_company.company AND user_company.user =?;"
	queryGetLicense                  = "SELECT license, ext_license from company where company_name = ?"
	queryGetUsedLicense              = "SELECT COUNT(*) FROM user_company join users WHERE users.email = user_company.user AND user_company.company= ? AND users.type = ?;"
	queryGetUserType                 = "SELECT type, role from users WHERE email = ?"
)

type company struct {
	CompanyName string `json:"company_name"`
	Domain      string `json:"domain"`
}

// Login struct for accepting user creds
type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ChangePassword for changing passwprd
type ChangePassword struct {
	Email              string `json:"email"`
	OldPassword        string `json:"old_password"`
	NewPassword        string `json:"new_password"`
	ConfirmNewPassword string `json:"confirm_new_password"`
}

// LoginUser for user login
type LoginUser struct {
	ID          int64  `json:"id"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Designation string `json:"designation"`
	Role        string `json:"role"`
	Type        string `json:"type"`
	DomainURL   string `json:"domain_url"`
	Company     string `json:"company"`
	JWTToken    string `json:"jwt_token"`
}

// LoginResponse struct for the response structure after login
type LoginResponse struct {
	Token   string    `json:"token"`
	Type    string    `json:"type"`
	Company []company `json:"company"`
}

// CreateToken struct for the token response for after validate of credentials
type CreateToken struct {
	Token     string `json:"token"`
	Company   string `json:"company"`
	DomainURL string `json:"domain_url"`
	Username  string `json:"username"`
}

// License struct for licnese response
type License struct {
	Internal          int `json:"internal"`
	External          int `json:"external"`
	InternalUsed      int `json:"internal_used"`
	ExternalUsed      int `json:"external_used"`
	InternalAvailable int `json:"internal_available"`
	ExternalAvailable int `json:"external_available"`
}

// LoginValidate check the email format, is input blank and the format of email
// Returns error if incorrect or invalid data given
func (login *Login) LoginValidate() *errors.RestErr {
	login.Username = strings.TrimSpace(strings.ToLower(login.Username))
	login.Password = strings.TrimSpace(login.Password)
	if login.Username == "" {
		return errors.NewBadRequestError("Invalid Email Given")
	}
	if login.Password == "" {
		return errors.NewBadRequestError("Invalid Password Given")
	}
	if !users.IsEmailValid(login.Username) {
		return errors.NewBadRequestError("Invalid Email Given")
	}
	return nil
}

// CheckValidPassword checks if the password given by the user is matching with the hash stored in the database
func (login *Login) CheckValidPassword() (bool, *errors.RestErr) {
	dbPassword, err := users.CheckPaswordForUserInDB(login.Username)
	if err != nil {
		return false, err
	}
	if dbPassword == login.Password {
		return true, nil
	}
	return false, errors.NewInternalServerError("Credential Incorrect")

}

// GenerateOneTimeSecureToken generates onetime token
// Saves the token in redis database with the key value pair of user email
func (login *Login) GenerateOneTimeSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	oneTimeToken := hex.EncodeToString(b)
	errAccess := redisdb.RedisSessionClient.Set(login.Username, oneTimeToken, time.Minute*5).Err()
	if errAccess != nil {
		return "error"
	}
	return oneTimeToken
}

// GetAllCompanyAccess returns the list of companies the user have access to
func (login *Login) GetAllCompanyAccess() ([]company, string, *errors.RestErr) {
	usertype, _, errType := GetUserType(login.Username)
	var companyFinal []company
	if errType != nil {
		return nil, "", errors.NewInternalServerError("Error Getting Type of User")
	}
	if usertype == "system" { //Non-removable global admin for all tenents
		company, _ := GetAllCompanyAccess(queryGetAllCompanyAccess, login)
		companyExternal, _ := GetAllCompanyAccess(queryGetAllCompanyAccessExternal, login)
		companyFinal = append(company, companyExternal...)
	} else if usertype == "internal" {
		companyFinal, _ = GetAllCompanyAccess(queryGetAllCompanyAccess, login)
	} else {
		companyFinal, _ = GetAllCompanyAccess(queryGetAllCompanyAccessExternal, login)
	}
	return companyFinal, usertype, nil
}

// GetLicense returns the list of license used and available for the application
func (login *LoginUser) GetLicense() (License, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryGetLicense)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetLicense statatement", err)
		return License{}, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	var license License
	result := stmt.QueryRow(login.Company)
	if err := result.Scan(&license.Internal, &license.External); err != nil {
		logger.Error(fmt.Sprintf("error while getting license of email and company %s: %s", login.Email, login.Company), err)
		return License{}, errors.NewInternalServerError("Database Error")
	}
	license.InternalUsed, _ = GetUsedLicense(login.Company, "internal")
	license.ExternalUsed, _ = GetUsedLicense(login.Company, "external")
	license.InternalAvailable = license.Internal - license.InternalUsed
	license.ExternalAvailable = license.External - license.ExternalUsed
	return license, nil
}

// GetUsedLicense returns the number of license used or the number of users exists group by role
func GetUsedLicense(company string, licenseType string) (int, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryGetUsedLicense)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetUsedLicense statatement", err)
		return 0, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	var licenseUsed int
	result := stmt.QueryRow(company, licenseType)
	if err := result.Scan(&licenseUsed); err != nil {
		logger.Error(fmt.Sprintf("error while getting used license of company %s", company), err)
		return 0, errors.NewInternalServerError("Database Error")
	}
	return licenseUsed, nil
}

// GetUserType return the user type of the user
func GetUserType(username string) (string, string, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryGetUserType)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetUserType statatement", err)
		return "", "", errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	var userType, userRole string
	result := stmt.QueryRow(username)
	if err := result.Scan(&userType, &userRole); err != nil {
		logger.Error(fmt.Sprintf("error while getting user type of user %s", username), err)
		return "", "", errors.NewInternalServerError("Database Error")
	}
	return userType, userRole, nil
}

// GetAllCompanyAccess returns all company the user have access to
func GetAllCompanyAccess(query string, login *Login) ([]company, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(query)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetAllCompanyAccess statement", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	var rows *sql.Rows
	rows, err = stmt.Query(login.Username)
	if err != nil {
		logger.Error("Error while running query queryGetAllCompanyAccess records", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	resultsQuery := make([]company, 0)
	for rows.Next() {
		var result company
		if err := rows.Scan(&result.CompanyName, &result.Domain); err != nil {
			logger.Error("Error while Scanning queryGetAllCompanyAccess records", err)
			return nil, errors.NewInternalServerError("Database Error")
		}
		resultsQuery = append(resultsQuery, result)
	}
	if len(resultsQuery) == 0 {
		return nil, errors.NewNotFoundError(fmt.Sprintf("Company Not Found"))
	}
	return resultsQuery, nil
}
