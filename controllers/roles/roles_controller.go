// Package roles implement all functions for user roles and permission
package roles

import (
	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
	"net/http"

	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"

	sqladapter "github.com/Blank-Xu/sql-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

// Role serves content for role of application
type Role struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Permission serves content in application
type Permission struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Modules serves content in application
type Modules struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// PermissionToRole for mapping of permission with role
type PermissionToRole struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	Permission string `json:"permission"`
	Access     string `json:"access"`
}

// ModuleToUser for mapping of module to user
type ModuleToUser struct {
	ID     string `json:"id"`
	Module string `json:"role"`
	User   string `json:"permission"`
}

const (
	errorNowRows              = "sql: no rows in result set"
	queryGetRole              = "SELECT  id, type from role"
	queryGetPermission        = "SELECT id , permission_type from permission order by id asc"
	queryGetModules           = "SELECT id, modules from modules order by id asc"
	queryAddRole              = "INSERT INTO `role` (`id`, `type`) VALUES (NULL, ?)"
	queryDeleteRole           = "DELETE FROM `role` WHERE `role`.`type` = ?"
	queryListPermissionToRole = "SELECT id, v0, v1, v2 from casbin_rule_test;"
	queryListModuleToUser     = "SELECT id, v0, v1 from casbin_module;"
)

// GetRoles function returns all roles in the applicaiton
func GetRoles(c *gin.Context) {
	stmt, err := userdb.Client.Prepare(queryGetRole)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetRole statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryGetRole records", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Type); err != nil {
			logger.Error("Error while Scanning queryGetRole records", err)
			c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
			return
		}
		results = append(results, role)
	}
	if len(results) == 0 {
		c.JSON(http.StatusOK, errors.NewInternalServerError("No Roles Found"))
		return
	}
	c.JSON(http.StatusOK, results)
}

// AddRole adds a new role to the application
func AddRole(c *gin.Context) {
	role := c.Param("role")
	stmt, err := userdb.Client.Prepare(queryAddRole)
	if err != nil {
		logger.Error("Error when trying to prepare queryAddRole statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(role)
	if err != nil {
		logger.Error(fmt.Sprintf("Cannot add role in the database ", role), err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// DeleteRole deletes the role from the application
func DeleteRole(c *gin.Context) {
	role := c.Param("role")
	stmt, err := userdb.Client.Prepare(queryDeleteRole)
	if err != nil {
		logger.Error("Error when trying to prepare queryDeleteRole statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(role)
	if err != nil {
		logger.Error(fmt.Sprintf("Cannot delete role in the database ", role), err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// GetPermission returns all the permisison in the application
func GetPermission(c *gin.Context) {
	stmt, err := userdb.Client.Prepare(queryGetPermission)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetPermission statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryGetPermission records", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]Permission, 0)
	for rows.Next() {
		var permission Permission
		if err := rows.Scan(&permission.ID, &permission.Type); err != nil {
			logger.Error("Error while Scanning queryGetPermission records", err)
			c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
			return
		}
		results = append(results, permission)
	}
	if len(results) == 0 {
		c.JSON(http.StatusOK, errors.NewInternalServerError("No Permission Found"))
		return
	}
	c.JSON(http.StatusOK, results)
}

// AddPermissionToRole adds the permission to the role
func AddPermissionToRole(c *gin.Context) {
	role := c.Param("role")
	permission := c.Param("permission")
	adapter, _ := sqladapter.NewAdapter(userdb.Client, "mysql", "casbin_rule_test")
	enforcer, _ := casbin.NewEnforcer("datasources/config/rbac_model.conf", adapter)
	_, err := enforcer.AddPermissionForUser(role, permission, "read")
	if err != nil {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Error in Adding Permisison to Role"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// ListPermissionToRole returns the list of permission with the role
func ListPermissionToRole(c *gin.Context) {
	stmt, err := userdb.Client.Prepare(queryListPermissionToRole)
	if err != nil {
		logger.Error("Error when trying to prepare queryListPermissionToRole statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryListPermissionToRole records", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]PermissionToRole, 0)
	for rows.Next() {
		var role PermissionToRole
		if err := rows.Scan(&role.ID, &role.Role, &role.Permission, &role.Access); err != nil {
			logger.Error("Error while Scanning queryListPermissionToRole records", err)
			c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
			return
		}
		results = append(results, role)
	}
	if len(results) == 0 {
		c.JSON(http.StatusOK, errors.NewInternalServerError("No Roles Found"))
		return
	}
	c.JSON(http.StatusOK, results)

}

// DeletePermissionToRole removes the permission from the role
func DeletePermissionToRole(c *gin.Context) {
	role := c.Param("role")
	permission := c.Param("permission")
	adapter, _ := sqladapter.NewAdapter(userdb.Client, "mysql", "casbin_rule_test")
	enforcer, _ := casbin.NewEnforcer("datasources/config/rbac_model.conf", adapter)
	_, err := enforcer.DeletePermissionForUser(role, permission)
	if err != nil {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Error in Deleting Permisison to Role"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// GetModules returns all modules in the application
func GetModules(c *gin.Context) {
	stmt, err := userdb.Client.Prepare(queryGetModules)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetModules statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryGetModules records", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]Modules, 0)
	for rows.Next() {
		var modules Modules
		if err := rows.Scan(&modules.ID, &modules.Type); err != nil {
			logger.Error("Error while Scanning queryGetModules records", err)
			c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
			return
		}
		results = append(results, modules)
	}
	if len(results) == 0 {
		c.JSON(http.StatusOK, errors.NewInternalServerError("No Modules Found"))
		return
	}
	c.JSON(http.StatusOK, results)
}

// AddModuleToUser adds the module access to the user
func AddModuleToUser(c *gin.Context) {
	userEmail := c.Param("user_email")
	module := c.Param("module")
	adapter, _ := sqladapter.NewAdapter(userdb.Client, "mysql", "casbin_module")
	enforcer, _ := casbin.NewEnforcer("datasources/config/rbac_model.conf", adapter)
	_, err := enforcer.AddPermissionForUser(module, userEmail, "read")
	if err != nil {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Error in Adding User to Module"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// DeleteModuleToUser removes the module access from the user
func DeleteModuleToUser(c *gin.Context) {
	user_email := c.Param("user_email")
	module := c.Param("module")
	adapter, _ := sqladapter.NewAdapter(userdb.Client, "mysql", "casbin_module")
	enforcer, _ := casbin.NewEnforcer("datasources/config/rbac_model.conf", adapter)
	_, err := enforcer.DeletePermissionForUser(module, user_email, "read")
	if err != nil {
		c.JSON(http.StatusOK, errors.NewInternalServerError("Error in Deleting User to Module"))
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})
}

// ListModuleToUser returns all user with respective module access
func ListModuleToUser(c *gin.Context) {
	stmt, err := userdb.Client.Prepare(queryListModuleToUser)
	if err != nil {
		logger.Error("Error when trying to prepare queryListModuleToUser statatement", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryListModuleToUser records", err)
		c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
		return
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]ModuleToUser, 0)
	for rows.Next() {
		var role ModuleToUser
		if err := rows.Scan(&role.ID, &role.Module, &role.User); err != nil {
			logger.Error("Error while Scanning queryListModuleToUser records", err)
			c.JSON(http.StatusOK, errors.NewInternalServerError("Database Error"))
			return
		}
		results = append(results, role)
	}
	if len(results) == 0 {
		c.JSON(http.StatusOK, errors.NewInternalServerError("No Roles Found"))
		return
	}
	c.JSON(http.StatusOK, results)

}
