// Package users implement all functionalities for user
package users

import (
	"ValueStory/auth-valuestory-io/datasources/awss3"
	"ValueStory/auth-valuestory-io/domain/auth"
	"ValueStory/auth-valuestory-io/domain/users"
	"ValueStory/auth-valuestory-io/services"
	"ValueStory/auth-valuestory-io/utils"
	"ValueStory/auth-valuestory-io/utils/errors"
	"os"
	"strings"

	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LoginUser takes username and password as input
// Checks if the credentials given is valid
// Generates an temporary token and returns the list of companies the user have access to
func LoginUser(c *gin.Context) {
	var login auth.Login
	if err := c.ShouldBindJSON(&login); err != nil {
		restErr := errors.NewBadRequestError("invalid json body")
		c.JSON(http.StatusOK, restErr)
		return
	}
	result, err := services.LoginService.Loginvalidate(login)
	if err != nil || result == false {
		c.JSON(http.StatusOK, err)
		return
	}
	var response auth.LoginResponse
	response.Token = login.GenerateOneTimeSecureToken(48)
	response.Company, response.Type, err = login.GetAllCompanyAccess()
	if err != nil {
		c.JSON(http.StatusOK, map[string]string{"message": "The user is does not have access of any company"})
		return
	}
	c.JSON(http.StatusOK, response)
}

// CreateToken takes the temporary token with the company and creates a JWT token for authentication
func CreateToken(c *gin.Context) {
	var createToken auth.CreateToken
	if err := c.ShouldBindJSON(&createToken); err != nil {
		restErr := errors.NewBadRequestError("invalid json body")
		c.JSON(http.StatusOK, restErr)
		return
	}
	result, err := services.LoginService.CreateTokenForUser(createToken)
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// InviteUser takes the email with the user_type as internal or external and adds the user to the application
func InviteUser(c *gin.Context) {
	au, _ := services.ExtractTokenMetadata(c.Request)
	userEmail := c.Param("email")
	userType := c.Param("user_type")

	//Check if user type is acceptable
	if userType != "internal" && userType != "external" {
		c.JSON(http.StatusOK, errors.NewInternalServerError("User Type Not in Acceptable Format"))
		return
	}

	//Check if license is available
	license, _ := au.GetLicense()
	if (userType == "internal" && license.InternalAvailable <= 0) || (userType == "external" && license.ExternalAvailable <= 0) {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Please purchase more license"))
		return
	}

	err := services.UsersService.InviteUser(userEmail, userType, au)
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// GetLicense returns the current license used, available by the client
func GetLicense(c *gin.Context) {
	au, _ := services.ExtractTokenMetadata(c.Request)

	license, err := au.GetLicense()
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, license)
}

// CompleteUserInvite verifies the invite token
// Makes the user from inactive to active status. Registers the name, designation and password
// The user can log in to the application after this step is completed successfully
func CompleteUserInvite(c *gin.Context) {
	var user users.User
	if err := c.ShouldBindJSON(&user); err != nil {
		restErr := errors.NewBadRequestError("invalid json body")
		c.JSON(http.StatusOK, restErr)
		return
	}
	userEmail := c.Param("user_email")
	verifyToken := c.Param("verify_token")
	if userEmail == "" || verifyToken == "" || user.Password != user.ConfirmPassword {
		c.JSON(http.StatusOK, map[string]string{"status": "Data Not Acceptable"})
		return
	}
	//Verify if user has already verified with the link provided
	if err := services.UsersService.VerifyUser(userEmail, verifyToken); err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	user.Email = userEmail

	err := services.UsersService.UpdateUserDetailsViaSignupInvite(user)
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// VerifyAuthentication helps to verify the authentication ( JWT token structure, data and expiry)
func VerifyAuthentication(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// Logout logs out the current user by deleting the JWT token from the redis server
func Logout(c *gin.Context) {
	au, _ := services.ExtractTokenMetadata(c.Request)
	deleted, delErr := services.DeleteAuth(au.Email)
	if delErr != nil || deleted == 0 { //if any goes wrong
		c.JSON(http.StatusOK, errors.NewUnauthorised("UnAuthorised"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// ChangePassword changes the user password
func ChangePassword(c *gin.Context) {
	var changePassword auth.ChangePassword
	if err := c.ShouldBindJSON(&changePassword); err != nil {
		restErr := errors.NewBadRequestError("invalid json body")
		c.JSON(http.StatusOK, restErr)
		return
	}
	if changePassword.NewPassword != changePassword.ConfirmNewPassword {
		c.JSON(http.StatusOK, errors.NewBadRequestError("Passwords do not match"))
		return
	}
	if changePassword.OldPassword == changePassword.NewPassword {
		c.JSON(http.StatusOK, errors.NewBadRequestError("New Password is Same as Old Password"))
		return
	}
	au, authErr := services.ExtractTokenMetadata(c.Request)
	if authErr != nil {
		c.JSON(http.StatusUnauthorized, errors.NewUnauthorised("UnAuthorised"))
		return
	}
	//This will update the user password with new password
	if err := users.ChangePassword(au.Email, changePassword.OldPassword, changePassword.NewPassword); err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// ForgotPassword initiates the forgot password and sends email with the link
func ForgotPassword(c *gin.Context) {
	var user users.User
	user.Email = c.Param("user_email")
	saveErr := services.UsersService.ForgotPassword(user)
	if saveErr != nil {
		c.JSON(saveErr.Status, saveErr)
		return
	}
	// Email will be sent by GenerateCode inside ForgotPassword
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// ResetForgotPassword resets the password and verifies the token
func ResetForgotPassword(c *gin.Context) {
	userEmail := c.Param("user_email")
	resetToken := c.Param("reset_token")
	var resetPassword users.ResetPassword
	if err := c.ShouldBindJSON(&resetPassword); err != nil {
		//TODO Handle JSON Error
		restErr := errors.NewBadRequestError("invalid json body")
		c.JSON(http.StatusOK, restErr)
		return
	}
	if userEmail == "" || resetToken == "" || resetPassword.Password == "" || resetPassword.ConfirmPassword == "" || resetPassword.Password != resetPassword.ConfirmPassword {
		c.JSON(http.StatusOK, map[string]string{"status": "Data Not Acceptable"})
		return
	}
	saveErr := services.UsersService.ResetPassword(userEmail, resetToken, resetPassword.Password)
	if saveErr != nil {
		c.JSON(saveErr.Status, saveErr)
		return
	}
	c.JSON(http.StatusOK, map[string]string{"status": "Password Reset Successfull"})
}

// GetAllUsers returns the list of users
func GetAllUsers(c *gin.Context) {
	_, _ = services.ExtractTokenMetadata(c.Request)

	users, err := services.UsersService.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

// DeleteUser deletes the user
func DeleteUser(c *gin.Context) {
	au, _ := services.ExtractTokenMetadata(c.Request)

	var user users.User
	user.Email = c.Param("email")
	if au.Email != user.Email {
		err := services.UsersService.DeleteUser(au.Email, au.Company, user)
		if err != nil {
			c.JSON(http.StatusOK, err)
			return
		}
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// UpdateUserRole updates user role with the role provided in the role parameter
func UpdateUserRole(c *gin.Context) {
	au, _ := services.ExtractTokenMetadata(c.Request)

	email := c.Param("email")
	role := c.Param("role")

	if email == au.Email {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Cannot update role for self of admin"))
		return
	}
	err := services.UsersService.UpdateUserRole(email, role)
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	services.DeleteAuth(email)
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// UploadFileForComments uploads the JSON structure for comments for the file
func UploadFileForComments(c *gin.Context) {
	//Only Pharmaquant user can upload file
	au, _ := services.ExtractTokenMetadata(c.Request)
	if !strings.Contains(au.Email, "@pharmaquant.org") {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Only PharmaQuant user can upload file"))
		return
	}
	// End of only pharmaquant user can upload file

	projectID := c.Param("project_id")
	_, header, _ := c.Request.FormFile("file")
	if err := c.SaveUploadedFile(header, header.Filename); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "Unable to save the file",
		})
		return
	}
	_, errFileCheck := utils.CheckFileTypePDF(header.Filename) //Check mime type of file is pdf
	if errFileCheck != nil {
		awss3.UploadS3BadFiles(header.Filename, au.Email) //upload bad files to s3
		os.Remove(header.Filename)                        //remove bad files
		c.JSON(http.StatusOK, errFileCheck)
		return
	}
	errUpload := utils.UploadFileToS3(header.Filename, projectID, au)
	if errUpload != nil {
		c.JSON(http.StatusOK, errUpload)
		return
	}
	os.Remove(header.Filename)
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// SaveComment saves the comment data in json to the table with respective projects
func SaveComment(c *gin.Context) {
	fileID := c.Param("file_id")

	jsonData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Post body is not in JSON"))
		return
	}
	saveErr := services.UsersService.SaveComment(fileID, &jsonData)
	if saveErr != nil {
		c.JSON(http.StatusOK, saveErr)
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// GetComment saves the comment data in json to the table with respective projects
func GetComment(c *gin.Context) {
	fileID := c.Param("file_id")

	jsonData, saveErr := services.UsersService.GetComment(fileID)
	if saveErr != nil {
		c.JSON(http.StatusOK, saveErr)
		return
	}
	c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	c.String(http.StatusOK, jsonData)
}

// GetAllCommentsFile retreives all comments file
func GetAllCommentsFile(c *gin.Context) {
	projectID := c.Param("project_id")
	listFiles, errList := services.UsersService.ListUploadedFile(projectID)
	if errList != nil {
		c.JSON(http.StatusOK, errList)
		return
	}
	c.JSON(http.StatusOK, listFiles)

}
