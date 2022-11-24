// Package projects implements all functions for projects
package projects

import (
	"ValueStory/auth-valuestory-io/domain/projects"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetAllProjects returns the current license used, available by the client
func GetAllProjects(c *gin.Context) {
	projects, err := projects.GetAllProjects()
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, projects)
}

// UpdateProjectStatus updates the project status to inactive/active
func UpdateProjectStatus(c *gin.Context) {
	projectID := c.Param("project_id")

	err := projects.UpdateProjectStatus(projectID)
	if err != nil {
		c.JSON(http.StatusOK, err)
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"status": 200})

}
