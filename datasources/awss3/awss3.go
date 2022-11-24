// Package awss3 implement all functions required for files engaging with amazon s3
package awss3

import (
	"ValueStory/auth-valuestory-io/datasources/config"
	"bytes"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// AddFileToS3ActiveSLRProjects uploads the given file to Amaazon S3
func AddFileToS3ActiveSLRProjects(s *session.Session, fileDir string, projectID string) error {
	// Open the file for use
	file, err := os.Open(fileDir)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, _ := file.Stat()
	var size int64 = fileInfo.Size()
	buffer := make([]byte, size)
	file.Read(buffer)
	fileDir = projectID + "/" + fileDir
	// Config settings: this is where you choose the bucket, filename, content-type etc.
	// of the file you're uploading.
	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(config.S3Bucket),
		Key:                  aws.String(fileDir),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(size),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}

// GetURLOfS3FileActiveSLRProjects send the URL for the uploaded Amazon S3 file
func GetURLOfS3FileActiveSLRProjects(s *session.Session, fileName string, projectID string) (string, error) {
	// Create S3 service client
	svc := s3.New(s)
	fileDir := projectID + "/" + fileName
	req, _ := svc.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(config.S3Bucket),
		Key:    aws.String(fileDir),
	})
	urlStr, err := req.Presign(15 * time.Minute)
	if err != nil {
		log.Println("Failed to sign request", err)
		return "", err
	}
	// urlStr = strings.Replace(urlStr, "https://"+config.S3Bucket+".s3.amazonaws.com", config.CLOUDFRONT_DNS, 1)
	return urlStr, nil

}

// UploadS3BadFiles uploads any rejected file to s3 for future analysis
func UploadS3BadFiles(fileDir string, email string) error {
	s, err := session.NewSession(&aws.Config{Region: aws.String(config.S3Region)})
	// Open the file for use
	file, err := os.Open(fileDir)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, _ := file.Stat()
	var size int64 = fileInfo.Size()
	buffer := make([]byte, size)
	file.Read(buffer)
	fileDir = "bad_files" + "/" + email + "_" + strconv.Itoa(rand.Intn(100000)) + "_" + fileDir
	// Config settings: this is where you choose the bucket, filename, content-type etc.
	// of the file you're uploading.
	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(config.S3Bucket),
		Key:                  aws.String(fileDir),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(size),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}
