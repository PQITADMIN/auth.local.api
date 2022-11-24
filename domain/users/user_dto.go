package users

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"regexp"
)

const (
	salt = "sampleSalt"
)

type User struct {
	Id              int64  `json:"id"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	Designation     string `json:"designation"`
	Company         string `json:"company,omitempty"`
	Role            string `json:"role,omitempty"`
	Type            string `json:"type,omitempty"`
	DateCreated     string `json:"date_created,omitempty"`
	Status          string `json:"status,omitempty"`
	Password        string `json:"password,omitempty"`
	ConfirmPassword string `json:"confirm_password,omitempty"`
	CreatedBy       string `json:"created_by,omitempty"`
}

type ResetPassword struct {
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type ProjectFiles struct {
	Id        string `json:"id"`
	ProjectID string `json:"project_id"`
	FileName  string `json:"filename"`
	URL       string `json:"url"`
	CreatedBy string `json:"created_by"`
	Timestamp string `json:"timestamp"`
}

// IsEmailValid checks if the email passed is a valid email address.
func IsEmailValid(e string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(e)
}

// HashString convers password into hash
func HashString(password string, salt []byte) string {
	// Convert password string to byte slice
	var passwordBytes = []byte(password)
	// Create sha-512 hasher
	var sha512Hasher = sha512.New()
	// Append salt to password
	passwordBytes = append(passwordBytes, salt...)
	// Write password bytes to the hasher
	sha512Hasher.Write(passwordBytes)
	// Get the SHA-512 hashed password
	var hashedPasswordBytes = sha512Hasher.Sum(nil)
	// Convert the hashed password to a base64 encoded string
	var base64EncodedPasswordHash = base64.URLEncoding.EncodeToString(hashedPasswordBytes)
	return base64EncodedPasswordHash
}

// GenerateHash generates hash
func (user *User) GenerateHash() (string, string, error) {
	randtoken, err := GenerateRandomString(32)
	if err != nil {
		return "", "", err
	}
	data := user.Email + randtoken
	hashedCode := HashString(data, []byte(salt))
	return hashedCode, randtoken, nil
}

// GenerateRandomString generates random string
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}
