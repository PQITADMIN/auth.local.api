// Package middleware implements the middleware components for authentication and authorization
package middleware

import (
	"ValueStory/auth-valuestory-io/services"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"

	sqladapter "github.com/Blank-Xu/sql-adapter"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gin-gonic/gin"
)

// Authentication function to check the if the authentication token is present
// If token is present, validate the token
func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := services.TokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusOK, errors.NewUnauthorised("UnAuthorised"))
			c.Abort()
			return
		}
		c.Next()
	}
}

// Authorization determines if current subject has been authorized to take an action on an object.
func Authorization(obj string, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Initialize  casbin adapter
		adapter, _ := sqladapter.NewAdapter(userdb.Client, "mysql", "casbin_rule_test")
		au, err := services.ExtractTokenMetadata(c.Request)
		if err != nil {
			c.JSON(http.StatusOK, errors.NewUnauthorised("UnAuthorised"))
			c.Abort()
			return
		}
		// casbin enforces policy
		ok, err := enforce(au.Role, obj, act, adapter)
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(500, errors.NewInternalServerError("Internal Server Error"))
			return
		}
		if !ok {
			c.AbortWithStatusJSON(403, errors.NewUnauthorised("Authorization Not Permitted"))
			return
		}
		c.Next()
	}
}

func enforce(sub string, obj string, act string, adapter persist.Adapter) (bool, error) {
	path := ""
	hostname, _ := os.Hostname()
	if isInTests() {
		if strings.Contains(hostname, "PC12-ANUP") {
			path = "/mnt/c/Users/AnupShaw/AppDev/auth-valuestory-api/"
		} else {
			path = "/home/runner/work/auth-valuestory-api/auth-valuestory-api/"
		}
	}

	enforcer, err := casbin.NewEnforcer(path+"datasources/config/rbac_model.conf", adapter)
	if err != nil {
		return false, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	// Load policies from DB dynamically
	err = enforcer.LoadPolicy()
	if err != nil {
		return false, fmt.Errorf("failed to load policy from DB: %w", err)
	}
	ok, err := enforcer.Enforce(sub, obj, act)
	return ok, err
}

func isInTests() bool {
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test") {
			return true
		}
	}
	return false
}
