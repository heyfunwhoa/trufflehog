//go:generate generate_permissions permissions.yaml permissions.go doppler
package doppler

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
	defaultAPIBase = "https://api.doppler.com"
	maxProjects    = 20
	maxConfigs     = 20
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg     *config.Config
	baseURL string
}

type SecretInfo struct {
	Token       TokenInfo
	Projects    []Project
	Configs     []Config
	SecretNames []string
	Permissions []string
}

type TokenInfo struct {
	Name      string
	Type      string
	Workplace string
	Slug      string
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type Config struct {
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Project     string `json:"project"`
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeDoppler
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

	color.Green("[!] Valid Doppler token\n\n")
	printTokenInfo(info.Token)
	printPermissions(info.Permissions)
	printProjects(info.Projects)
	printConfigs(info.Configs)
	if len(info.SecretNames) > 0 {
		printSecretNames(info.SecretNames)
	}
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	return analyzePermissions(analyzers.NewAnalyzeClient(cfg), defaultAPIBase, key)
}

func analyzePermissions(client *http.Client, baseURL, key string) (*SecretInfo, error) {
	info := &SecretInfo{}

	token, err := fetchMe(client, baseURL, key)
	if err != nil {
		return nil, err
	}
	info.Token = token
	info.Permissions = permissionsForTokenType(token.Type)
	if token.Workplace != "" {
		info.Permissions = appendUnique(info.Permissions, PermissionStrings[WorkplaceRead])
	}

	projects, err := fetchProjects(client, baseURL, key)
	if err == nil {
		info.Projects = projects
		if len(projects) > 0 {
			info.Permissions = appendUnique(info.Permissions, PermissionStrings[ProjectsRead])
		}
		for i, project := range projects {
			if i >= maxProjects {
				break
			}
			configs, cfgErr := fetchConfigs(client, baseURL, key, project.Slug)
			if cfgErr != nil {
				continue
			}
			info.Configs = append(info.Configs, configs...)
			if len(configs) > 0 {
				info.Permissions = appendUnique(info.Permissions, PermissionStrings[ConfigsRead])
			}
		}
	}

	// Service tokens are scoped to a single config and can list secret names.
	if names, namesErr := fetchSecretNames(client, baseURL, key); namesErr == nil && len(names) > 0 {
		info.SecretNames = names
		info.Permissions = appendUnique(info.Permissions, PermissionStrings[SecretsRead])
	}

	return info, nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	workplaceName := info.Token.Workplace
	if workplaceName == "" {
		workplaceName = "doppler-workplace"
	}
	workplace := analyzers.Resource{
		Name:               workplaceName,
		FullyQualifiedName: "doppler/workplace/" + workplaceName,
		Type:               "workplace",
		Metadata: map[string]any{
			"token_name": info.Token.Name,
			"token_type": info.Token.Type,
		},
	}

	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeDoppler,
		Metadata: map[string]any{
			"token_name": info.Token.Name,
			"token_type": info.Token.Type,
			"workplace":  info.Token.Workplace,
		},
		Bindings: analyzers.BindAllPermissions(workplace, permissionValues(info.Permissions)...),
	}

	for _, project := range info.Projects {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               project.Name,
			FullyQualifiedName: "doppler/project/" + project.Slug,
			Type:               "project",
			Parent:             &workplace,
			Metadata: map[string]any{
				"id":   project.ID,
				"slug": project.Slug,
			},
		})
	}
	for _, cfg := range info.Configs {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               cfg.Name,
			FullyQualifiedName: "doppler/config/" + cfg.Project + "/" + cfg.Name,
			Type:               "config",
			Parent:             &workplace,
			Metadata: map[string]any{
				"environment": cfg.Environment,
				"project":     cfg.Project,
			},
		})
	}
	for _, name := range info.SecretNames {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               name,
			FullyQualifiedName: "doppler/secret/" + name,
			Type:               "secret_name",
			Parent:             &workplace,
		})
	}

	return result
}

func permissionValues(perms []string) []analyzers.Permission {
	out := make([]analyzers.Permission, 0, len(perms))
	for _, perm := range perms {
		out = append(out, analyzers.Permission{Value: perm})
	}
	return out
}

func permissionsForTokenType(tokenType string) []string {
	switch strings.ToLower(tokenType) {
	case "scim":
		return []string{PermissionStrings[ScimAccess]}
	case "audit":
		return []string{PermissionStrings[AuditRead]}
	case "service":
		return []string{PermissionStrings[SecretsRead]}
	default:
		return nil
	}
}

func fetchMe(client *http.Client, baseURL, key string) (TokenInfo, error) {
	body, status, err := doGET(client, baseURL+"/v3/me", key)
	if err != nil {
		return TokenInfo{}, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return TokenInfo{}, errors.New("invalid Doppler token")
	}
	if status != http.StatusOK {
		return TokenInfo{}, fmt.Errorf("unexpected status code: %d", status)
	}

	var resp struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Workplace struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"workplace"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return TokenInfo{}, err
	}
	return TokenInfo{
		Name:      resp.Name,
		Type:      resp.Type,
		Workplace: resp.Workplace.Name,
		Slug:      resp.Workplace.Slug,
	}, nil
}

func fetchProjects(client *http.Client, baseURL, key string) ([]Project, error) {
	body, status, err := doGET(client, baseURL+"/v3/projects", key)
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
	if len(resp.Projects) > maxProjects {
		return resp.Projects[:maxProjects], nil
	}
	return resp.Projects, nil
}

func fetchConfigs(client *http.Client, baseURL, key, projectSlug string) ([]Config, error) {
	body, status, err := doGET(client, baseURL+"/v3/configs?project="+projectSlug, key)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Configs []Config `json:"configs"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Configs) > maxConfigs {
		return resp.Configs[:maxConfigs], nil
	}
	return resp.Configs, nil
}

func fetchSecretNames(client *http.Client, baseURL, key string) ([]string, error) {
	body, status, err := doGET(client, baseURL+"/v3/configs/config/secrets/names", key)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp.Names, nil
}

func doGET(client *http.Client, url, key string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

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

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func printTokenInfo(token TokenInfo) {
	color.Yellow("[i] Token Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type", "Workplace"})
	t.AppendRow(table.Row{color.GreenString(token.Name), color.GreenString(token.Type), color.GreenString(token.Workplace)})
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

func printProjects(projects []Project) {
	if len(projects) == 0 {
		return
	}
	color.Yellow("[i] Projects:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Slug"})
	for _, project := range projects {
		t.AppendRow(table.Row{color.GreenString(project.Name), color.GreenString(project.Slug)})
	}
	t.Render()
}

func printConfigs(configs []Config) {
	if len(configs) == 0 {
		return
	}
	color.Yellow("[i] Configs:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Project", "Config", "Environment"})
	for _, cfg := range configs {
		t.AppendRow(table.Row{color.GreenString(cfg.Project), color.GreenString(cfg.Name), color.GreenString(cfg.Environment)})
	}
	t.Render()
}

func printSecretNames(names []string) {
	color.Yellow("[i] Secret Names:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name"})
	for _, name := range names {
		t.AppendRow(table.Row{color.GreenString(name)})
	}
	t.Render()
}
