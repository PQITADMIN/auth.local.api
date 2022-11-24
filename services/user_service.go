package services

import (
	"ValueStory/auth-valuestory-io/domain/auth"
	users "ValueStory/auth-valuestory-io/domain/users"
	"ValueStory/auth-valuestory-io/utils/errors"
)

var (
	UsersService usersServiceInterface = &usersService{}
)

type usersService struct{}

type usersServiceInterface interface {
	// VerifyUser verifies if the token is valid for the respective email provided
	VerifyUser(string, string) *errors.RestErr

	// InviteUser takes the usertype and user_email and sends a email with invitation link, adds the user to the application and the database
	InviteUser(string, string, *auth.LoginUser) *errors.RestErr

	// DeleteUser deletes the user in a given company
	DeleteUser(string, string, users.User) *errors.RestErr

	// UpdateUserDetailsViaSignupInvite updates the details of the user after the user verification of the invite
	// Updates details such as name, designation and password
	UpdateUserDetailsViaSignupInvite(users.User) *errors.RestErr

	// ForgotPassword sends the the forgot password email to the user
	ForgotPassword(users.User) *errors.RestErr

	// ResetPassword resets the password after verifying the token
	ResetPassword(string, string, string) *errors.RestErr

	// GetAllUsers returns list of all users for the application
	GetAllUsers() ([]users.User, *errors.RestErr)

	// UpdateUserRole updates user role to manager and vice versa
	UpdateUserRole(string, string) *errors.RestErr

	// SaveComment saves the comment of the users to the project
	SaveComment(string, *[]byte) *errors.RestErr

	// GetComment retreive the comment of the users to the project
	GetComment(string) (string, *errors.RestErr)

	// ListUploadedFile returns the list of uploaded file
	ListUploadedFile(string) ([]users.ProjectFiles, *errors.RestErr)
}

func (s *usersService) VerifyUser(user_email string, verify_token string) *errors.RestErr {
	if user_email == "" || verify_token == "" {
		return errors.NewBadRequestError("Invalid Data")
	}
	if !users.IsEmailValid(user_email) {
		return errors.NewBadRequestError("Invalid Email Format")
	}
	result := &users.User{Email: user_email}
	return result.VerifyUser(verify_token)
}

func (s *usersService) InviteUser(email string, user_type string, au *auth.LoginUser) *errors.RestErr {
	var user users.User
	user.Company = au.Company
	user.CreatedBy = au.Email
	user.Email = email
	if !users.IsEmailValid(email) {
		return errors.NewBadRequestError("Email Is Invalid")
	}
	if email != au.Email {
		s.DeleteUser(email, au.Company, user)
	}
	if err := user.Save("user", au.Email, user_type); err != nil {
		return err
	}
	//This will generate one time code for the user to validate and register for password
	if err := user.GenerateInviteCode(au.Company); err != nil {
		return err
	}
	return nil
}

func (s *usersService) DeleteUser(email string, company string, user users.User) *errors.RestErr {
	user.Company = company
	if !users.IsEmailValid(user.Email) {
		return errors.NewBadRequestError("Email Is Invalid")
	}
	if err := user.Delete(); err != nil {
		return err
	}
	return nil
}

func (s *usersService) UpdateUserDetailsViaSignupInvite(user users.User) *errors.RestErr {
	if err := user.UpdateSignupViaInvite(); err != nil {
		return err
	}
	return nil
}

func (s *usersService) ForgotPassword(user users.User) *errors.RestErr {
	var err error
	user.Id, _, err = users.CheckUserExist(user.Email)
	if err != nil {
		return nil
	}
	if !users.IsEmailValid(user.Email) {
		return errors.NewBadRequestError("Invalid Email Format")
	}
	if err := user.GenerateCodeForgotPassword(); err != nil {
		return err
	}
	return nil
}

func (s *usersService) ResetPassword(email string, resetToken string, password string) *errors.RestErr {
	err := users.ResetUserPassword(email, resetToken, password)
	if err != nil {
		return err
	}
	return nil
}

func (s *usersService) GetAllUsers() ([]users.User, *errors.RestErr) {
	alluser, err := users.GetAllUsers()
	if err != nil {
		return nil, err
	}
	return alluser, nil
}

func (s *usersService) UpdateUserRole(email string, role string) *errors.RestErr {
	if err := users.UpdateUserRoleDB(email, role); err != nil {
		return err
	}
	return nil
}

func (s *usersService) SaveComment(file_id string, jsonData *[]byte) *errors.RestErr {
	dbSaveErr := users.SaveCommentDB(file_id, jsonData)
	if dbSaveErr != nil {
		return dbSaveErr
	}

	return nil
}

func (*usersService) GetComment(file_id string) (string, *errors.RestErr) {
	jsonData, dbSaveErr := users.GetCommentDB(file_id)
	if dbSaveErr != nil {
		return "", dbSaveErr
	}
	return jsonData, nil
}

func (*usersService) ListUploadedFile(project_id string) ([]users.ProjectFiles, *errors.RestErr) {
	return users.ListUploadedFile(project_id)
}
