// Package utils implements utility package for app
package utils

import (
	"ValueStory/auth-valuestory-io/datasources/awss3"
	"ValueStory/auth-valuestory-io/datasources/config"
	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"
	"ValueStory/auth-valuestory-io/domain/auth"
	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	querySaveDetailsOfS3File = "INSERT INTO `comments_file` (`id`, `project_id`, `filename`, `created_by`, `timestamp`) VALUES (NULL, ?, ?, ?, CURRENT_TIMESTAMP)"
	queryDeleteUploadedFile  = "DELETE from comments_file WHERE project_id = ? AND id = ?"
)

// CheckFileTypePDF check if the file is a pdf
func CheckFileTypePDF(fileDir string) (string, *errors.RestErr) {
	file, _ := os.Open(fileDir)
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, _ := file.Stat()
	var size int64 = fileInfo.Size()
	buffer := make([]byte, size)
	file.Read(buffer)

	if http.DetectContentType(buffer) == "application/pdf" || http.DetectContentType(buffer) == "application/x-pdf" {
		return http.DetectContentType(buffer), nil
	}
	return http.DetectContentType(buffer), errors.NewBadRequestError("File Type Not PDF")

}

// UploadFileToS3 uploads the file to S3
func UploadFileToS3(file string, projectID string, au *auth.LoginUser) *errors.RestErr {
	s, err := session.NewSession(&aws.Config{Region: aws.String(config.S3Region)})
	if err != nil {
		return errors.NewInternalServerError("AWS S3 New Session Failed")
	}
	file_id, dbSaveErr := SaveDetailsOfS3File(file, projectID, au)
	if dbSaveErr != nil {
		return errors.NewInternalServerError("File already exists for this project")
	}
	file_id_str := strconv.FormatInt(file_id, 10)
	// Upload
	err = awss3.AddFileToS3ActiveSLRProjects(s, file, projectID)
	if err != nil {
		DeleteUploadedFile(projectID, file_id_str, au)
		return errors.NewInternalServerError("Failed to addFileToS2ActiveSLRProjects")
	}
	return nil
}

// SaveDetailsOfS3File saves the details of S3 files
func SaveDetailsOfS3File(fileName string, projectID string, au *auth.LoginUser) (int64, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(querySaveDetailsOfS3File)
	if err != nil {
		logger.Error("Error when trying to prepare querySaveDetailsOfS3File statatement", err)
		return 0, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	a, err := stmt.Exec(projectID, fileName, au.Email)
	file_id, _ := a.LastInsertId()
	if err != nil {
		logger.Error(fmt.Sprintf("Error while trying to save comment file %s", err.Error()), err)
		return 0, errors.NewInternalServerError("Database Error")
	}
	return file_id, nil
}

// DeleteUploadedFile deletes the uploaded file
func DeleteUploadedFile(projectID string, fileID string, au *auth.LoginUser) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryDeleteUploadedFile)
	if err != nil {
		logger.Error("Error when trying to prepare queryDeleteUploadedFile statement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(projectID, fileID)
	if err != nil {
		logger.Error(fmt.Sprintf("Error while trying to delete comment uploaded file %s", err.Error()), err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}
