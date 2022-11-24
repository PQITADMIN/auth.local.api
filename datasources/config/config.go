// Package config contains all variables required for application
package config

import "os"

var (
	// AuthUIDomain contains the domain name for user interface
	AuthUIDomain = os.Getenv("AuthUIDomain")
	// AccessSecretToken has the access secret token
	AccessSecretToken = os.Getenv("AccessSecretToken")
	// MYSQLHost for hostname and port for mysql instance
	MYSQLHost = os.Getenv("MYSQLHost")
	// MYSQLPassword for the password of mysql instance
	MYSQLPassword = os.Getenv("MYSQLPassword")
	// REDISHost for the host and port of redis server
	REDISHost = os.Getenv("REDISHost")
	// REDISPassword for the password of redis server
	REDISPassword = os.Getenv("REDISPassword")
	// SMTPEmail for the connection string for sending emails
	SMTPEmail = os.Getenv("SMTPEmail")
	// SMTPPassword for the password of smtp creds
	SMTPPassword = os.Getenv("SMTPPassword")
	// S3Bucket for the place to upload files in aws s3
	S3Bucket = "qa-pharmaquant-valuestory"
	// S3Region is the region of s3
	S3Region = "us-east-1"
)
