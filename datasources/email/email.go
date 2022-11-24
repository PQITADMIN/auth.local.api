// Package email implements the functionalities required for emails
package email

import (
	"ValueStory/auth-valuestory-io/datasources/config"
	"bytes"
	"html/template"
	"log"

	"gopkg.in/gomail.v2"
)

type verificationLink struct {
	Link string
}

// SendInviteEmail sends invite email to the email given with the body parameter as the invite link
func SendInviteEmail(body string, email string) {

	m := gomail.NewMessage()
	m.SetHeader("From", config.SMTPEmail)
	m.SetHeader("To", email)
	t, _ := template.ParseFiles("template/email_verification.html")
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, verificationLink{Link: body}); err != nil {
		log.Println(err)
	}

	result := tpl.String()
	// m.SetAddressHeader("Cc", "dan@example.com", "Dan")
	m.SetHeader("Subject", "[ValueStory] Welcome to Valuestory.io")

	m.SetBody("text/html", result)
	// m.Attach("/home/Alex/lolcat.jpg")

	d := gomail.NewDialer("smtp.office365.com", 587, config.SMTPEmail, config.SMTPPassword)

	// Send the email to Bob, Cora and Dan.
	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}
}

// SendForgotPasswordEmail sends email for forgot password
func SendForgotPasswordEmail(body string, email string) {

	m := gomail.NewMessage()
	m.SetHeader("From", config.SMTPEmail)
	m.SetHeader("To", email)
	t, _ := template.ParseFiles("template/forgot_password.html")
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, verificationLink{Link: body}); err != nil {
		log.Println(err)
	}

	result := tpl.String()
	// m.SetAddressHeader("Cc", "dan@example.com", "Dan")
	m.SetHeader("Subject", "[ValueStory] Forgot Password")

	m.SetBody("text/html", result)
	// m.Attach("/home/Alex/lolcat.jpg")

	d := gomail.NewDialer("smtp.office365.com", 587, config.SMTPEmail, config.SMTPPassword)

	// Send the email to Bob, Cora and Dan.
	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}
}
