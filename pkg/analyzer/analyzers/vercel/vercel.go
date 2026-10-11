//go:generate generate_permissions permissions.yaml permissions.go vercel
package vercel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	defaultAPIBase = "https://api.vercel.com"
	maxResources   = 25
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg     *config.Config
	baseURL string
}

type SecretInfo struct {
	User        User
	Teams       []Team
	Projects    []Project
	Permissions []string
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

type Team struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type Project struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Framework string `json:"framework"`
	AccountID string `json:"accountId"`
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeVercel
}

func (a Analyzer) apiBase() string {
	if a.baseURL != "" {
		return strings.TrimRight(a.baseURL, "/")
	}
	return defaultAPIBase
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationValidateCredentials, analyzers.ServiceConfig, "", errors.New("key not found in credential info"))
	}

	info, err := analyzePermissions(analyzers.NewAnalyzeClient(a.Cfg), a.apiBase(), key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationAnalyzePermissions, analyzers.ServiceAPI, "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
	}
	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid Vercel API token\n\n")
	printUser(info.User)
	printPermissions(info.Permissions)
	printTeams(info.Teams)
	printProjects(info.Projects)
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	return analyzePermissions(analyzers.NewAnalyzeClient(cfg), defaultAPIBase, key)
}

func analyzePermissions(client *http.Client, baseURL, key string) (*SecretInfo, error) {
	info := &SecretInfo{}

	user, err := fetchUser(client, baseURL, key)
	if err != nil {
		return nil, err
	}
	info.User = user
	info.Permissions = append(info.Permissions, PermissionStrings[UserRead])

	if teams, err := fetchTeams(client, baseURL, key); err == nil {
		info.Teams = teams
		if len(teams) > 0 {
			info.Permissions = append(info.Permissions, PermissionStrings[TeamsRead])
		}
	}

	if projects, err := fetchProjects(client, baseURL, key); err == nil {
		info.Projects = projects
		if len(projects) > 0 {
			info.Permissions = append(info.Permissions, PermissionStrings[ProjectsRead])
		}
	}

	return info, nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	userName := firstNonEmpty(info.User.Username, info.User.Email, info.User.ID, "vercel-user")
	userResource := analyzers.Resource{
		Name:               userName,
		FullyQualifiedName: "vercel/user/" + firstNonEmpty(info.User.ID, userName),
		Type:               "user",
		Metadata: map[string]any{
			"email":    info.User.Email,
			"name":     info.User.Name,
			"username": info.User.Username,
		},
	}

	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeVercel,
		Metadata: map[string]any{
			"username": info.User.Username,
			"email":    info.User.Email,
		},
		Bindings: analyzers.BindAllPermissions(userResource, permissionValues(info.Permissions)...),
	}

	for _, team := range info.Teams {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               firstNonEmpty(team.Name, team.Slug),
			FullyQualifiedName: "vercel/team/" + team.ID,
			Type:               "team",
			Parent:             &userResource,
			Metadata: map[string]any{
				"slug": team.Slug,
			},
		})
	}
	for _, project := range info.Projects {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               project.Name,
			FullyQualifiedName: "vercel/project/" + project.ID,
			Type:               "project",
			Parent:             &userResource,
			Metadata: map[string]any{
				"framework":  project.Framework,
				"account_id": project.AccountID,
			},
		})
	}

	return result
}

func fetchUser(client *http.Client, baseURL, key string) (User, error) {
	body, status, err := doVercelGET(client, baseURL+"/v2/user", key)
	if err != nil {
		return User{}, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return User{}, errors.New("invalid Vercel token")
	}
	if status != http.StatusOK {
		return User{}, fmt.Errorf("unexpected status code: %d", status)
	}

	var resp struct {
		User User `json:"user"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return User{}, err
	}
	if resp.User.ID == "" && resp.User.Username == "" {
		// Some tokens return the user object at the top level.
		if err := json.Unmarshal(body, &resp.User); err != nil {
			return User{}, err
		}
	}
	return resp.User, nil
}

func fetchTeams(client *http.Client, baseURL, key string) ([]Team, error) {
	body, status, err := doVercelGET(client, baseURL+"/v2/teams?limit=25", key)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Teams []Team `json:"teams"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Teams) > maxResources {
		return resp.Teams[:maxResources], nil
	}
	return resp.Teams, nil
}

func fetchProjects(client *http.Client, baseURL, key string) ([]Project, error) {
	body, status, err := doVercelGET(client, baseURL+"/v9/projects?limit=25", key)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Projects []Project `json:"projects"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Projects) > maxResources {
		return resp.Projects[:maxResources], nil
	}
	return resp.Projects, nil
}

func doVercelGET(client *http.Client, endpoint, key string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func permissionValues(perms []string) []analyzers.Permission {
	out := make([]analyzers.Permission, 0, len(perms))
	for _, perm := range perms {
		out = append(out, analyzers.Permission{Value: perm})
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func printUser(user User) {
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Username", "Name", "Email"})
	t.AppendRow(table.Row{
		color.GreenString(user.ID),
		color.GreenString(user.Username),
		color.GreenString(user.Name),
		color.GreenString(user.Email),
	})
	t.Render()
}

func printPermissions(permissions []string) {
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, perm := range permissions {
		t.AppendRow(table.Row{color.GreenString(perm)})
	}
	t.Render()
}

func printTeams(teams []Team) {
	if len(teams) == 0 {
		return
	}
	color.Yellow("[i] Teams:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Slug", "ID"})
	for _, team := range teams {
		t.AppendRow(table.Row{color.GreenString(team.Name), color.GreenString(team.Slug), color.GreenString(team.ID)})
	}
	t.Render()
}

func printProjects(projects []Project) {
	if len(projects) == 0 {
		return
	}
	color.Yellow("[i] Projects:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Framework", "ID"})
	for _, project := range projects {
		t.AppendRow(table.Row{color.GreenString(project.Name), color.GreenString(project.Framework), color.GreenString(project.ID)})
	}
	t.Render()
}
