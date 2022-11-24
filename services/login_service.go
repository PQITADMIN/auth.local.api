package services

import (
	"ValueStory/auth-valuestory-io/datasources/config"
	redisdb "ValueStory/auth-valuestory-io/datasources/redis_db"
	"ValueStory/auth-valuestory-io/domain/auth"
	users "ValueStory/auth-valuestory-io/domain/users"

	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/twinj/uuid"
)

var (
	AccessSecretToken                       = config.AccessSecretToken
	LoginService      loginServiceInterface = &loginService{}
)

type TokenDetails struct {
	Email        string
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type loginService struct{}

type loginServiceInterface interface {
	// Loginvalidate validates the user input and returns if the user is a valid user or not
	Loginvalidate(auth.Login) (bool, *errors.RestErr)

	// CreateTokenForUser takes the temporary token, company and create a valid JWT and stores in Redis
	CreateTokenForUser(auth.CreateToken) (*auth.LoginUser, *errors.RestErr)
}

func (l *loginService) Loginvalidate(login auth.Login) (bool, *errors.RestErr) {
	if err := login.LoginValidate(); err != nil {
		return false, err
	}
	valid_user, err := CheckValidUser(login)
	if err != nil {
		return false, err
	}
	return valid_user, nil
}

func (l *loginService) CreateTokenForUser(createToken auth.CreateToken) (*auth.LoginUser, *errors.RestErr) {
	//Check if token exists in redis server
	token_from_redis, err := redisdb.RedisSessionClient.Get(createToken.Username).Result()
	if err != nil || token_from_redis != createToken.Token {
		logger.Error("Token Mismatch", err)
		return nil, errors.NewInternalServerError("Token Mismatch")
	}

	var login auth.Login
	var loginuser auth.LoginUser
	login.Username = createToken.Username

	company, user_type, errCompany := login.GetAllCompanyAccess()
	if errCompany != nil {
		return &loginuser, errCompany
	}
	for _, c := range company {
		if c.CompanyName == createToken.Company && c.Domain == createToken.DomainURL {

			//Create the JWT Token
			createResp, userid, err_token := CreateJWTToken(login, createToken.Company, user_type, createToken.DomainURL)
			if err != nil {
				return nil, err_token
			}

			saveAuthErr := CreateAuth(1, createResp)
			if saveAuthErr != nil {
				logger.Error("JWT Creation Error ", saveAuthErr)
				return nil, errors.NewInternalServerError("Server Error")
			}

			var user users.User
			user.Id = userid
			user.Get()
			user.Email = login.Username
			loginuser.ID = user.Id
			loginuser.Name = user.Name
			loginuser.Email = user.Email
			loginuser.Role = user.Role
			loginuser.Type = user_type
			loginuser.Company = createToken.Company
			loginuser.DomainURL = createToken.DomainURL
			loginuser.Designation = user.Designation
			loginuser.UUID = createResp.AccessUuid
			loginuser.JWTToken = createResp.AccessToken
			return &loginuser, nil
		}
	}
	return nil, errors.NewNotFoundError("Company or Domain not found")
}

// CheckValidUser check the user is a valid user or not
func CheckValidUser(login auth.Login) (bool, *errors.RestErr) {
	hashParameterPassword := users.HashString(login.Password, []byte(login.Username))
	login.Password = hashParameterPassword
	result, err := login.CheckValidPassword()
	if err != nil {
		return result, err
	}
	return result, nil
}

// CreateJWTToken creates the JWT token for authentication of the user
func CreateJWTToken(login auth.Login, company string, user_type string, domain_url string) (*TokenDetails, int64, *errors.RestErr) {
	//Get UserID
	userid, role, _ := users.CheckUserExist(login.Username)
	var td TokenDetails
	td.Email = login.Username
	// td.AtExpires = time.Now().Add(time.Minute * 15).Unix() //This should be in Prod
	td.AtExpires = time.Now().Add(time.Minute * 30).Unix() //This is for UAT and testing purpose
	td.AccessUuid = uuid.NewV4().String()
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["username"] = login.Username
	atClaims["userid"] = userid
	atClaims["role"] = role
	atClaims["company"] = company
	atClaims["user_type"] = user_type
	atClaims["domain_url"] = domain_url
	// atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix() //This is Prod
	atClaims["exp"] = time.Now().Add(time.Hour * 15).Unix() //This is qa or testing
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(AccessSecretToken))
	if err != nil {
		return nil, 0, errors.NewInternalServerError("cannot create jwt")
	}
	return &td, userid, nil
}

// CreateAuth saves the token in redis server
func CreateAuth(userid uint64, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	now := time.Now()

	errAccess := redisdb.RedisSessionClient.Set(td.Email, td.AccessUuid, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	return nil
}

// TokenValid checks if the JWT Token provided in the authentication header is valid or not
// Returns error if invalid token provided
func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

// VerifyToken extracts the JWT Topken from the http request
// Checks the signing algorithm and returns the jwt token
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	//logger.Info("Inside Verify Token")
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(AccessSecretToken), nil
	})
	if err != nil {
		logger.Error("Verify Token Error", err)
		return nil, err
	}
	return token, nil
}

// ExtractToken extracts the JET token from the http request from Authorization header
func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// ExtractTokenMetadata extracts the JWT token data, validate it and return in a struct
func ExtractTokenMetadata(r *http.Request) (*auth.LoginUser, error) {
	token, err := VerifyToken(r)
	if err != nil {
		logger.Error("Verify Token Error", err)
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	//logger.Info("Verify Token Successful")
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, _ := strconv.ParseInt(fmt.Sprintf("%.f", claims["userid"]), 10, 64)
		if err != nil {
			return nil, err
		}
		accessUuid_redisDB, err := FetchAuth(claims["username"].(string))
		if err != nil {
			logger.Error("Access ID NotFound Error", err)
			return nil, err
		}
		if strings.Compare(accessUuid_redisDB, claims["access_uuid"].(string)) == 1 {
			logger.Error("Access ID Mismatch Error", err)
			return nil, fmt.Errorf("Access ID Mismatch")
		}
		// if r.Header["Origin"][0] != "http://"+claims["domain_url"].(string) {
		// 	return nil, fmt.Errorf("Domain URL Mismatch")
		// }
		return &auth.LoginUser{
			UUID:      accessUuid,
			Email:     claims["username"].(string),
			ID:        userId,
			Role:      claims["role"].(string),
			Company:   claims["company"].(string),
			Type:      claims["user_type"].(string),
			DomainURL: claims["domain_url"].(string),
		}, nil
	}
	logger.Error("something error", err)
	return nil, err
}

// FetchAuth returns the auth from redis instance
func FetchAuth(email string) (string, error) {
	userid, err := redisdb.RedisSessionClient.Get(email).Result()
	// logger.Info(userid)

	if err != nil {
		logger.Error("Fetch data from redis error", err)
		return "", err
	}
	// userID, _ := strconv.ParseUint(userid, 10, 64)
	// userid64 := int64(userID)
	return userid, nil
}

// DeleteAuth deletes the JWT auth from the redis server
func DeleteAuth(email string) (int64, error) {
	deleted, err := redisdb.RedisSessionClient.Del(email).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
