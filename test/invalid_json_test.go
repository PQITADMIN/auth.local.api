package main

import (
	"ValueStory/auth-valuestory-io/utils/errors"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginErrorJSON(t *testing.T) {
	path := [5]string{
		"/contact_us",
		"/create_token",
		"/login",
		"/complete_invite/anup@pharmaquant.org/token",
		"/reset/anup@pharmaquant.org/token",
	}
	for _, element := range path {
		SendRequestAndCheck(t, element)
	}
}

func SendRequestAndCheck(t *testing.T, path string) {
	router := SetUpRouter()

	payload := `
	{
		"error": "error",
		"error: "error@1234"
	}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(payload))
	router.ServeHTTP(w, req)

	var restErr errors.RestErr
	responseData, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(responseData, &restErr)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 400, restErr.Status)
	assert.Equal(t, "invalid json body", restErr.Message)
}
