// Package ping implements ping and contact-us server implementations
package ping

import (
	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"
	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ContactUSDetails is used for accepting data from the contact-us api
type ContactUSDetails struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Contact string `json:"contact"`
	Message string `json:"message"`
}

const (
	querySaveContact = "INSERT INTO `contact_us` (`id`, `name`, `email`, `contact`, `message`, `timestamp`) VALUES (NULL, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
)

// Ping function returns health check string in response
func Ping(c *gin.Context) {
	// Returns the string in plain text
	c.String(http.StatusOK, "pong")
}

// ContactUs saves the details received by the form on contact us page from valuestory homepage
func ContactUs(c *gin.Context) {

	var contactus ContactUSDetails
	if err := c.ShouldBindJSON(&contactus); err != nil {
		restErr := errors.NewBadRequestError("invalid json body")
		c.JSON(http.StatusOK, restErr)
		return
	}

	stmt, errPS := userdb.Client.Prepare(querySaveContact)
	if errPS != nil {
		logger.Error("Error when trying to prepare querySaveContact statatement", errPS)
		c.String(http.StatusOK, "Database Error")
		return
	}
	defer stmt.Close()
	_, err := stmt.Exec(contactus.Name, contactus.Email, contactus.Contact, contactus.Message)
	if err != nil {
		logger.Error(fmt.Sprintf("Error while trying to execute querySaveContact %s", err.Error()), err)
		c.String(http.StatusOK, "Database Error")
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}
