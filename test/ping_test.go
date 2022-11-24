package main

import (
	"ValueStory/auth-valuestory-io/app"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func SetUpRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	app.MapUrls(router)
	return router
}

func TestRootRoute(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "pong", w.Body.String())
}

func TestPingRoute(t *testing.T) {
	router := SetUpRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "pong", w.Body.String())
}

func TestContactUs(t *testing.T) {
	router := SetUpRouter()
	payload := `
	{
		"name": "Anup",
		"email": "anup@pharmaquant.org",
		"contact": "7003291377",
		"message": "Test message"
	}`

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/contact_us", strings.NewReader(payload))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"status\":200}", w.Body.String())
}
