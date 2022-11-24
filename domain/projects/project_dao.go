// Package projects implements all functions for projects
package projects

import (
	userdb "ValueStory/auth-valuestory-io/datasources/mysql/user_db"
	"ValueStory/auth-valuestory-io/logger"
	"ValueStory/auth-valuestory-io/utils/errors"
	"fmt"
)

const (
	indexUniqueEmail         = "Error 1062: Duplicate entry"
	errorNowRows             = "sql: no rows in result set"
	queryGetAllProjects      = "Select id, type, proj_name, active from projects;"
	queryUpdateProjectStatus = "UPDATE projects SET `active` = IF (active = '0' , '1', '0') WHERE id = ?"
)

func GetAllProjects() ([]Project, *errors.RestErr) {
	stmt, err := userdb.Client.Prepare(queryGetAllProjects)
	if err != nil {
		logger.Error("Error when trying to prepare queryGetAllProjects statatement", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logger.Error("Error while running query  queryGetAllProjects records", err)
		return nil, errors.NewInternalServerError("Database Error")
	}
	defer rows.Close() //always close the rows open and always put it after error is handled
	results := make([]Project, 0)
	for rows.Next() {
		var project Project
		if err := rows.Scan(&project.Id, &project.Type, &project.ProjectName, &project.Active); err != nil {
			logger.Error("Error while Scanning projects records", err)
			return nil, errors.NewInternalServerError("Database Error")
		}
		results = append(results, project)
	}
	if len(results) == 0 {
		return nil, errors.NewNotFoundError(fmt.Sprintf("No projects Found"))
	}
	return results, nil
}

func UpdateProjectStatus(project_id string) *errors.RestErr {
	stmt, err := userdb.Client.Prepare(queryUpdateProjectStatus)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateProjectStatus statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	defer stmt.Close()
	_, err = stmt.Exec(project_id)
	if err != nil {
		logger.Error("Error when trying to prepare queryUpdateProjectStatus statatement", err)
		return errors.NewInternalServerError("Database Error")
	}
	return nil
}
