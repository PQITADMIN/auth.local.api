package main

import (
	"ValueStory/auth-valuestory-io/domain/auth"
	"ValueStory/auth-valuestory-io/domain/users"
	"ValueStory/auth-valuestory-io/utils/errors"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	user     = "anup@pharmaquant.org"
	password = "Test@1234"
	company  = "PharmaQuant"
)

var (
	token     string
	jwt_token string
)

func TestShowPath(t *testing.T) {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	fmt.Println(exPath)
	fmt.Println(os.Getenv("GOMOD"))
	fmt.Println(os.Hostname())

}

func TestLoginLoginInvalidEmail(t *testing.T) {
	router := SetUpRouter()
	var login auth.Login
	login.Username = "anuppharmaquant.org"
	login.Password = password
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(login)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", &buf)
	router.ServeHTTP(w, req)

	var restErr errors.RestErr
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &restErr)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 400, restErr.Status)
	assert.Equal(t, "Invalid Email Given", restErr.Message)
}

func TestCreateTokenErrorJSON(t *testing.T) {
	router := SetUpRouter()

	payload := `
	{
		"error": "error",
		"error: "error@1234"
	}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/create_token", strings.NewReader(payload))
	router.ServeHTTP(w, req)

	var restErr errors.RestErr
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &restErr)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 400, restErr.Status)
	assert.Equal(t, "invalid json body", restErr.Message)

}

func TestCreateTokenError(t *testing.T) {
	router := SetUpRouter()
	var createToken auth.CreateToken
	createToken.Username = user
	createToken.Company = company
	createToken.Token = ""
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(createToken)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/create_token", &buf)
	router.ServeHTTP(w, req)

	var restErr errors.RestErr
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &restErr)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 500, restErr.Status)
	assert.Equal(t, "Token Mismatch", restErr.Message)
}

func TestLogin(t *testing.T) {
	router := SetUpRouter()
	var login auth.Login
	login.Username = user
	login.Password = password
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(login)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", &buf)
	router.ServeHTTP(w, req)

	var result auth.LoginResponse
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &result)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, result.Token)
	token = result.Token
}

func TestCreateToken(t *testing.T) {
	router := SetUpRouter()
	var createToken auth.CreateToken
	createToken.Username = user
	createToken.Company = company
	createToken.Token = token
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(createToken)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/create_token", &buf)
	router.ServeHTTP(w, req)

	var result auth.LoginUser
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &result)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, result.JWTToken)
	jwt_token = result.JWTToken
}

func TestVerifyAuthToken(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())
}

func TestVerifyAuthWithInvalidToken(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("Authorization", "Bearer "+"invalid_token")
	router.ServeHTTP(w, req)

	var restErr errors.RestErr
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &restErr)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 401, restErr.Status)
}

func TestGetLicense(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/license", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestChangePassword(t *testing.T) {
	router := SetUpRouter()
	var changePassword auth.ChangePassword
	changePassword.Email = user
	changePassword.OldPassword = password
	changePassword.NewPassword = "Test@12345"
	changePassword.ConfirmNewPassword = "Test@12345"

	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(changePassword)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/changepassword", &buf)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())

	//Relogin
	var login auth.Login
	login.Username = user
	login.Password = "Test@12345"
	json.NewEncoder(&buf).Encode(login)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/login", &buf)
	router.ServeHTTP(w, req)

	var result auth.LoginResponse
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &result)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, result.Token)
	token = result.Token

	//Regenerate jwttoken
	var createToken auth.CreateToken
	createToken.Username = user
	createToken.Company = company
	createToken.Token = token
	json.NewEncoder(&buf).Encode(createToken)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/create_token", &buf)
	router.ServeHTTP(w, req)

	var result_login_user auth.LoginUser
	responseData, _ = ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &result_login_user)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, result_login_user.JWTToken)
	jwt_token = result_login_user.JWTToken

	changePassword.Email = user
	changePassword.OldPassword = "Test@12345"
	changePassword.NewPassword = password
	changePassword.ConfirmNewPassword = password

	json.NewEncoder(&buf).Encode(changePassword)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/changepassword", &buf)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())

}

func TestSignupInviteInternal(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/invite/internal/it@pharmaquant.org", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// assert.Equal(t, "{\"status\":200}", w.Body.String())
}

func TestDeleteUser(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/delete/user/it@pharmaquant.org", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())
}

func TestUpdateRole(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/roles/update/it@pharmaquant.org", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())
}

func TestGetAllUsers(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Always run the logout test after all the test ends
func TestLogout(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
	req.Header.Set("Authorization", "Bearer "+jwt_token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())
}

func TestForgotPassword(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/forgot_password/anup@pharmaquant.org", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// assert.Equal(t, "{\"status\":200}", w.Body.String())
}

func TestResetPassword(t *testing.T) {
	router := SetUpRouter()

	var resetPassword users.ResetPassword
	resetPassword.Password = "Test@1234"
	resetPassword.ConfirmPassword = resetPassword.Password
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(resetPassword)
	code, _ := users.VerifyCodeFromDB(user)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/reset/"+user+"/"+code, &buf)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":\"Password Reset Successfull\"}", w.Body.String())
}
