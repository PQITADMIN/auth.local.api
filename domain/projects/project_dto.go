package projects

type Project struct {
	Id                 string `json:"id"`
	Type               string `json:"type"`
	TypeDesc           string `json:"type_desc,omitempty"`
	ProjectName        string `json:"project_name"`
	ProjectDescription string `json:"project_description,omitempty"`
	Active             string `json:"active"`
}
