// Package app implements the url routing for the application
package app

import (
	"ValueStory/auth-valuestory-io/controllers/middleware"
	"ValueStory/auth-valuestory-io/controllers/ping"
	"ValueStory/auth-valuestory-io/controllers/projects"
	"ValueStory/auth-valuestory-io/controllers/roles"
	"ValueStory/auth-valuestory-io/controllers/users"

	"github.com/gin-gonic/gin"
)

// MapUrls lists al urls for for the api
func MapUrls(router *gin.Engine) {

	//------------Start of Un-Authenticated Routes--------------------
	router.GET("/", ping.Ping) //This is for AWS EKS and Apprunner
	router.GET("/ping", ping.Ping)
	router.POST("/contact_us", ping.ContactUs)
	router.POST("/login", users.LoginUser)
	router.POST("/create_token", users.CreateToken)
	router.POST("/complete_invite/:user_email/:verify_token", users.CompleteUserInvite)
	router.GET("/forgot_password/:user_email", users.ForgotPassword)
	router.POST("/reset/:user_email/:reset_token", users.ResetForgotPassword)
	//--------------End of Un-Authenticated Route--------------------

	//------------Below this all routes are authenticated--------------------
	router.Use(middleware.Authentication())
	//------------Below this all routes are authenticated--------------------

	router.GET("/auth/verify", users.VerifyAuthentication) //Verify Authentication
	router.GET("/logout", users.Logout)
	router.GET("/license", middleware.Authorization("license", "read"), users.GetLicense)
	router.GET("/invite/:user_type/:email", middleware.Authorization("invite_user", "read"), users.InviteUser)
	router.POST("/changepassword", users.ChangePassword)
	router.GET("/users", middleware.Authorization("all_user", "read"), users.GetAllUsers)
	router.GET("/delete/user/:email", middleware.Authorization("delete_user", "read"), users.DeleteUser)
	router.GET("/roles/update/:email/:role", middleware.Authorization("update_role", "read"), users.UpdateUserRole)

	//Roles and Permission
	router.GET("/roles", middleware.Authorization("roles", "read"), roles.GetRoles)
	router.GET("/roles/add/:role", middleware.Authorization("roles", "read"), roles.AddRole)
	router.GET("/roles/delete/:role", middleware.Authorization("roles", "read"), roles.DeleteRole)
	router.GET("/permission", middleware.Authorization("permission", "read"), roles.GetPermission) //Hardcoded in database
	router.GET("/roles/add/permission/:role/:permission", middleware.Authorization("add_permission", "read"), roles.AddPermissionToRole)
	router.GET("/roles/list/permission", middleware.Authorization("list_permission", "read"), roles.ListPermissionToRole)
	router.GET("/roles/delete/permission/:role/:permission", middleware.Authorization("add_permission", "read"), roles.DeletePermissionToRole)
	router.GET("/modules", middleware.Authorization("modules_permission", "read"), roles.GetModules) //modules such as litvencity, hardcoded to database
	router.GET("/modules/add/:module/:user_email", middleware.Authorization("modules_permission", "read"), roles.AddModuleToUser)
	router.GET("/modules/delete/:module/:user_email", middleware.Authorization("modules_permission", "read"), roles.DeleteModuleToUser)
	router.GET("/modules/list/user", middleware.Authorization("modules_permission", "read"), roles.ListModuleToUser)

	// Comments
	router.POST("comments/upload_file/:project_id", users.UploadFileForComments)
	router.GET("comments/file/get/:project_id", users.GetAllCommentsFile)
	router.POST("comments/save/:file_id", users.SaveComment)
	router.GET("comments/get/:file_id", users.GetComment)

	//Projects
	router.GET("projects", middleware.Authorization("projects", "read"), projects.GetAllProjects)
	router.GET("projects/update/status/:project_id", middleware.Authorization("projects", "read"), projects.UpdateProjectStatus)

}
