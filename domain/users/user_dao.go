package users

import (
	"ValueStory/auth-valuestory-io/datasources/awss3"
	"ValueStory/auth-valuestory-io/datasources/config"
	"ValueStory/auth-valuestory-io/datasources/email"
	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"
	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	indexUniqueEmail              = "Error 1062: Duplicate entry"
	errorNowRows                  = "sql: no rows in result set"
	queryCheckUserStatus          = "SELECT status FROM  users WHERE email = ?"
	queryDeleteUserToken          = "DELETE FROM users_uniq_code WHERE email = ?;"
	queryGetCodeFromEmail         = "SELECT code, randcode FROM `users_uniq_code` WHERE email = ? ORDER BY date_created DESC LIMIT 1;"
	queryUpdateUserStatus         = "UPDATE users SET status = ? where userid = ?;"
	queryInsertUserEmailVerifyLog = "INSERT INTO `users_email_verify_log` (`email`, `token` , `action`) VALUES (?,?,?)"
	queryCheckPasswordForUser     = "SELECT password FROM users WHERE email = ?;"
	queryInsertUser               = "INSERT INTO users (name, email, password, designation, role, type,  created_by ) VALUES (? , ?,  ?, ?, ?, ?, ?);"
	queryGetUser                  = "SELECT userid, name, email, designation, role FROM users WHERE userid = ?;"
	checkUserExist                = "SELECT userid , role FROM  users WHERE email = ? AND status = 'active';"
	queryGenerateCode             = "INSERT INTO `users_uniq_code` (`email`, `code` , `randcode`) VALUES (?,?,?);"
	queryDeletetUser              = "DELETE FROM `users` WHERE email = ?"
	queryInsertUserCompany        = "INSERT INTO `user_company` ( `user`, `company`, `created_by`) VALUES ( ?, ?, ?)"
	queryCheckUserExistVerify     = "SELECT userid FROM  users WHERE email = ?;"
	queryUpdateSignupViaInvite    = "UPDATE users SET name =? , designation =? , password = ?  where email = ?;"
	queryChangeUserPassword       = "UPDATE users SET password = ? where email = ?;"
	queryGetAllUsers              = "Select userid, name, email, designation, status, role, type from users;"
	queryUpdateUserRoleDB         = "UPDATE `users` SET `role` = ? WHERE `users`.`email` = ?;"
	querySaveCommentDB            = "INSERT INTO `comments` (`id`, `file_id`, `comment`) VALUES (NULL, ?, ?);"
	queryUpdateCommentDB          = "UPDATE `comments` SET `comment` = ? WHERE file_id = ?"
	queryGetCommentDB             = "SELECT comment from comments WHERE file_id = ?"
	queryListUploadedFile         = "SELECT id, project_id, filename, created_by, timestamp from comments_file WHERE project_id = ?"
)

// This functoin verifies if the user has the same verify_token present in the database
func (user *User) VerifyUser(verify_token string) *errors.RestErr {
	userId, err := CheckUserExistVerify(user.Email)
	if err != nil {
		logger.Error("Error user does not exist %s", err)
		return errors.NewInternalServerError("User Does Not Exist")
	}
	status := CheckUserStatus(user.Email)
	if status == "active" {
		logger.Error(fmt.Sprintf("User already Verified %s", user.Email), err)
		return errors.NewInternalServerError("User Already Verified")
	}
	user.Id = userId
	fmt.Println(" User Exist Proceed to verify ")
	code, randcode := VerifyCodeFromDB(user.Email)
	if code == verify_token {
		updateStatus := ChangeUserStatus("active", user.Id)
		if updateStatus {
			VerifyEmailLog(user.Email, code, "register")
			return nil
		}
	} else {
		logger.Error(fmt.Sprintf("Wrong Code Provided %d , %s, VerifyToken - %s , DBToken - %s ", user.Id, user.Email, verify_token, randcode), err)
		return errors.NewNotFoundError("Error in Token")
	}
	return nil
}

// CheckUserStatus returns the user status
func CheckUserStatus(email string) string {
	stmt, err := userdb.Client.Prepare(queryCheckUserStatus)
	if err != nil {
		logger.Error("Error when trying to prepare queryCheckUserStatus statatement", err)
		return err.Error()
	}
	defer stmt.Close()
	result := stmt.QueryRow(email)
	var status string
	if err := result.Scan(&status); err != nil {
		if strings.Contains(err.Error(), errorNowRows) {
			logger.Error(fmt.Sprintf("error while fetching status %s", email), err)
			return err.Error()
		}
		logger.Error(fmt.Sprintf("error while fetching status %s", email), err)
		return err.Error()
	}
	return status
}

// VerifyCodeFromDB returns the invite code of the user from the database
func VerifyCodeFromDB(user_email string) (string, string) {
	stmt, err := userdb.Client.Prepare(queryGetCodeFromEmail)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetCodeFromEmail statatement", err)
		return "err", "err"
	}
	defer stmt.Close()
	result := stmt.QueryRow(user_email)
	var code string
	var randcode string
	if err := result.Scan(&code, &randcode); err != nil {
		logger.Error(fmt.Sprintf("error while getting code and randcode %s: %s", code, randcode), err)
		return "err", "err"
	}
	return code, randcode
}

// ChangeUserStatus updates the user status
func ChangeUserStatus(status string, userID int64) bool {
	stmt, err := userdb.Client.Prepare(queryUpdateUserStatus)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateUserStatus statatement", err)
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec(status, userID)
	if err != nil {
		return false
	}
	return true
}

// VerifyEmailLog inserts the data of the user to verify email log table for audit purpose
func VerifyEmailLog(email string, code string, action string) {
	stmt, err := userdb.Client.Prepare(queryInsertUserEmailVerifyLog)
	if err != nil {
		logger.Error("Error when trying to prepare queryInsertUserEmailVerifyLog statatement", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(email, code, action)
	DeleteToken(email)
}

// DeleteToken deletes the token from the database
func DeleteToken(email string) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryDeleteUserToken)
	if err != nil {
		logger.Error("Error when trying to prepare QueryDeleteUserToken statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(email)
	if err != nil {
		logger.Error(fmt.Sprintf("No token exists for user %s", email), err)
		return errors.NewNotFoundError("Error")
	}
	return nil
}

// Save creates the user in the company
func (user *User) Save(role string, created_by string, user_type string) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryInsertUser)
	if err != nil {
		logger.Error("Error when trying to prepare queryInsertUser statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	password := HashString(user.Password, []byte(user.Email))
	insertResult, err := stmt.Exec(user.Name, user.Email, password, user.Designation, role, user_type, created_by)
	if err != nil {
		if strings.Contains(err.Error(), indexUniqueEmail) {
			logger.Error("email already exists", err)
			return errors.NewInternalServerError("Email Already Exists")
		}
		logger.Error(fmt.Sprintf("Error while trying to execute queryInsertUser %s", err.Error()), err)
		return errors.NewInternalServerError("Database Error")
	}
	userId, err := insertResult.LastInsertId()
	if err != nil {
		logger.Error(fmt.Sprintf("Error while fetching last insert id of queryInsertUser, %s", err.Error()), err)
		return errors.NewInternalServerError("Database Read Error")
	}
	user.Id = userId
	//Add to user_company table
	stmt, err = userdb.Client.Prepare(queryInsertUserCompany)
	if err != nil {
		logger.Error("Error when trying to prepare queryInsertUser statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(user.Email, user.Company, created_by)
	return nil
}

// CheckPaswordForUserInDB checks the user password from the database
func CheckPaswordForUserInDB(user_email string) (string, *errors.RestErr) {
	_, _, err := CheckUserExist(user_email)
	if err != nil {
		logger.Error("User Does not exist", err)
		return "err", errors.NewInternalServerError("Credential Incorrect")
	}
	stmt, err := userdb.Client.Prepare(queryCheckPasswordForUser)
	if err != nil {
		logger.Error("Error when trying to prepare queryCheckPasswordForUser statatement", err)
		return "err", errors.NewInternalServerError("Database error")
	}
	defer stmt.Close()
	result := stmt.QueryRow(user_email)
	var password string
	if err := result.Scan(&password); err != nil {
		logger.Error(fmt.Sprintf("error while getting password: %s", password), err)
		return "err", errors.NewInternalServerError("Database Error")
	}
	return password, nil
}

// Get gets all the details of the user saved from the database
func (user *User) Get() *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryGetUser)
	if err != nil {
		logger.Error("Error when trying to prepare GET USER statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	result := stmt.QueryRow(user.Id)
	if err := result.Scan(&user.Id, &user.Name, &user.Email, &user.Designation, &user.Role); err != nil {
		if strings.Contains(err.Error(), errorNowRows) {
			logger.Error(fmt.Sprintf("user %d does not exist", user.Id), err)
			return errors.NewNotFoundError("Database Error")
		}
		logger.Error(fmt.Sprintf("error while getting user id %d: %s", user.Id, err.Error()), err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}

// CheckUserExist checks if the user exists with the given email and retuen userid and role of the same
func CheckUserExist(email string) (int64, string, error) {
	stmt, err := userdb.Client.Prepare(checkUserExist)
	if err != nil {
		logger.Error("Error when trying to prepare CheckUserExist statatement", err)
		return 0, "", err
	}
	defer stmt.Close()
	result := stmt.QueryRow(email)
	var user_id int64
	var role string
	if err := result.Scan(&user_id, &role); err != nil {
		if strings.Contains(err.Error(), errorNowRows) {
			logger.Error(fmt.Sprintf("user %d does not exist", user_id), err)
			return 0, role, err
		}
		logger.Error(fmt.Sprintf("error while getting user id %d: %s", user_id, err.Error()), err)
		return 0, role, err
	}
	return user_id, role, nil
}

// GenerateInviteCode generates an invite code
func (user *User) GenerateInviteCode(company string) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryGenerateCode)
	if err != nil {
		logger.Error("Error when trying to prepare QueryGenerateCode statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	code, randcode, err := user.GenerateHash()
	if err != nil {
		logger.Error("Error in generating user hash", err)
		return errors.NewNotFoundError("Error")
	}
	_, err = stmt.Exec(user.Email, code, randcode)
	if err != nil {
		fmt.Println(randcode)
		logger.Error(fmt.Sprintf("User does not exist with id %d", user.Id), err)
		return errors.NewNotFoundError("Error")
	}
	//if all good send email to user with code
	// finalVerifyLink := "https://internal-tools.pharmaquant.org/verify-invite/" + company + "/" + user.Email + "/" + code
	// email.SendEmail(finalVerifyLink, user.Email)
	finalVerifyLink := config.AuthUIDomain + "verify-invite/" + user.Email + "/" + code
	email.SendInviteEmail(finalVerifyLink, user.Email)
	return nil
}

// Delete deletes the user
func (user *User) Delete() *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryDeletetUser)
	if err != nil {
		logger.Error("Error when trying to prepare queryDeletetUser statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(user.Email)
	if err != nil {
		logger.Error("Error when trying to execute queryDeletetUser statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}

// CheckUserExistVerify checks if the user exists
func CheckUserExistVerify(email string) (int64, error) {
	stmt, err := userdb.Client.Prepare(queryCheckUserExistVerify)
	if err != nil {
		logger.Error("Error when trying to prepare queryCheckUserExistVerify statatement", err)
		return 0, err
	}
	defer stmt.Close()
	result := stmt.QueryRow(email)
	var user_id int64
	if err := result.Scan(&user_id); err != nil {
		if strings.Contains(err.Error(), errorNowRows) {
			logger.Error(fmt.Sprintf("user %d does not exist", user_id), err)
			return 0, err
		}
		logger.Error(fmt.Sprintf("error while getting user id %d: %s", user_id, err.Error()), err)
		return 0, err
	}
	return user_id, nil
}

// UpdateSignupViaInvite helps to update the details of the user in the database
func (user *User) UpdateSignupViaInvite() *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryUpdateSignupViaInvite)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateSignupViaInvite statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	user.Password = HashString(user.Password, []byte(user.Email))
	_, err = stmt.Exec(user.Name, user.Designation, user.Password, user.Email)
	if err != nil {
		logger.Error("Error ", err)
		return errors.NewInternalServerError("Database Error, Unable to Save Details")
	}
	return nil
}

// ChangePassword checks the old password and updates with the new password
func ChangePassword(email string, oldPassword string, newPassword string) *errors.RestErr {
	//Change raw password to hash
	currPasswordHash := HashString(oldPassword, []byte(email))
	newPasswordHash := HashString(newPassword, []byte(email))
	// Check if curr password is same as provided
	passwordfromDB, _ := CheckPaswordForUserInDB(email)
	if passwordfromDB == currPasswordHash {
		if err := ChangePasswordFromDB(email, newPasswordHash); err != nil {
			return err
		}
		return nil
	} else {
		return errors.NewBadRequestError("Exising Password do not match")
	}
}

// ChangePasswordFromDB updates the password hash of the user to the database
func ChangePasswordFromDB(email string, passwordHash string) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryChangeUserPassword)
	if err != nil {
		logger.Error("Error when trying to prepare CheckPasswordForUser statatement", err)
		return errors.NewInternalServerError("Database error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(passwordHash, email)
	if err != nil {
		logger.Error(fmt.Sprintf("Cannot Update user with new password User %s ", email), err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}

// GenerateCodeForgotPassword generate the code that will be used to verify email for forgot password
func (user *User) GenerateCodeForgotPassword() *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryGenerateCode)
	if err != nil {
		logger.Error("Error when trying to prepare QueryGenerateCode statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	code, randcode, err := user.GenerateHash()
	if err != nil {
		logger.Error("Error in generating user hash", err)
		return errors.NewNotFoundError("Error")
	}
	_, err = stmt.Exec(user.Email, code, randcode)
	if err != nil {
		fmt.Println(randcode)
		logger.Error(fmt.Sprintf("User does not exist with id %d", user.Id), err)
		return errors.NewNotFoundError("Error")
	}
	//if all good TODO function to send email to user with code
	finalVerifyLink := config.AuthUIDomain + "verify-forgot-password/" + user.Email + "/" + code
	email.SendForgotPasswordEmail(finalVerifyLink, user.Email)

	return nil
}

// ResetUserPassword resets the user password in the database
func ResetUserPassword(email string, resetToken string, password string) *errors.RestErr {
	var user User
	var err error
	currPasswordHash := HashString(password, []byte(email))
	user.Email = email
	user.Id, _, err = CheckUserExist(user.Email)
	if err != nil {
		logger.Error("Error user does not exist %s", err)
		return errors.NewInternalServerError("User Does Not Exist")
	}
	status := CheckUserStatus(user.Email)
	if status == "inactive" {
		logger.Error(fmt.Sprintf("User already Verified %s", user.Email), err)
		return errors.NewInternalServerError("User is InActive, Contact admin")
	}
	code, randcode := VerifyCodeFromDB(user.Email)
	if code == resetToken {
		updateStatus := ChangePasswordFromDB(user.Email, currPasswordHash)
		if updateStatus == nil {
			DeleteToken(user.Email)
			VerifyEmailLog(user.Email, code, "reset")
			return nil
		}
	} else {
		logger.Error(fmt.Sprintf("Wrong Code Provided %d , %s, ResetToken - %s , DBToken - %s ", user.Id, user.Email, resetToken, randcode), err)
		return errors.NewNotFoundError("Error in Token")
	}
	return nil
}

// GetAllUsers returns list of all users
func GetAllUsers() ([]User, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryGetAllUsers)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetAllUsers statatement", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryGetAllUsers records", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.Id, &user.Name, &user.Email, &user.Designation, &user.Status, &user.Role, &user.Type); err != nil {
			logger.Error("Error while Scanning ListPrismaProjects records", err)
			return nil, errors.NewInternalServerError("Database Error")
		}
		results = append(results, user)
	}
	if len(results) == 0 {
		return nil, errors.NewNotFoundError(fmt.Sprintf("No Users Found"))
	}
	return results, nil
}

// UpdateUserRoleDB updates user role in database to manager and vice versa
func UpdateUserRoleDB(email string, role string) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryUpdateUserRoleDB)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateUserRoleDB statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(role, email)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateUserRoleDB statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}

// SaveCommentDB saves the comment JSON in the database
func SaveCommentDB(file_id string, jsonData *[]byte) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(querySaveCommentDB)
	if err != nil {
		logger.Error("Error when trying to prepare querySaveCommentDB statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()

	_, err = stmt.Exec(file_id, string(*jsonData))
	if err != nil {
		//If keyword json data exits, then we need to update keyword data
		if strings.Contains(err.Error(), "Duplicate") {
			UpdateCommentDB(file_id, jsonData)
			return nil
		}
		logger.Error(fmt.Sprintf("Error while trying to save project comment data %s", err.Error()), err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}

// UpdateCommentDB updates the comment JSON in the database
func UpdateCommentDB(project_id string, jsonData *[]byte) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryUpdateCommentDB)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateCommentDB statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()

	_, err = stmt.Exec(string(*jsonData), project_id)
	if err != nil {
		logger.Error(fmt.Sprintf("Error while trying to update project comment data %s", err.Error()), err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}

// GetCommentDB returns the comment JSON from the database
func GetCommentDB(file_id string) (string, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryGetCommentDB)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetCommentDB statatement", err)
		return "", errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	result := stmt.QueryRow(file_id)
	var json_data string
	if err := result.Scan(&json_data); err != nil {
		if strings.Contains(err.Error(), errorNowRows) {
			logger.Error(fmt.Sprintf("fileid %d does not exist"), err)
			return json_data, errors.NewInternalServerError("Database Error")
		}
		logger.Error(fmt.Sprintf("error while getting json keyword data from file %d: %s", file_id, err.Error()), err)
		return json_data, errors.NewInternalServerError("Database Error")
	}
	return json_data, nil
}

// ListUploadedFile list the total files thats been uploaded
func ListUploadedFile(project_id string) ([]ProjectFiles, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryListUploadedFile)
	if err != nil {
		logger.Error("Error when trying to prepare queryListUploadedFile statatement", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	rows, err := stmt.Query(project_id)
	if err != nil {
		logger.Error("Error while running query queryListUploadedFile records", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]ProjectFiles, 0)
	for rows.Next() {
		var project ProjectFiles
		if err := rows.Scan(&project.Id, &project.ProjectID, &project.FileName, &project.CreatedBy, &project.Timestamp); err != nil {
			logger.Error("Error while Scanning queryListUploadedFile records", err)
			return nil, errors.NewInternalServerError("Database Error")
		}
		project.URL, _ = ReadUploadedFile(project_id, project.FileName)
		results = append(results, project)
	}
	if len(results) == 0 {
		return nil, errors.NewNotFoundError(fmt.Sprintf("No Comments Files Found"))
	}
	return results, nil
}

// ReadUploadedFile returns the uploaded file from the server
func ReadUploadedFile(project_id string, file_name string) (string, *errors.RestErr) {
	s, err := session.NewSession(&aws.Config{Region: aws.String(config.S3Region)})
	if err != nil {
		return "", errors.NewInternalServerError("AWS S3 New Session Failed")
	}
	// GetS3Url
	url, err := awss3.GetURLOfS3FileActiveSLRProjects(s, file_name, project_id)
	if err != nil {
		return "", errors.NewInternalServerError("Failed to GetURLOfS3FileActiveSLRProjects")
	}
	return url, nil
}
