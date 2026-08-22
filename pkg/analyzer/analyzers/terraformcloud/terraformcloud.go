//go:generate generate_permissions permissions.yaml permissions.go terraformcloud
package terraformcloud

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

const defaultBaseURL = "https://app.terraform.io"

type Analyzer struct {
	Cfg     *config.Config
	baseURL string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeTerraformCloud
}

func (a Analyzer) apiURL() string {
	if a.baseURL != "" {
		return a.baseURL
	}
	return defaultBaseURL
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationValidateCredentials, analyzers.ServiceConfig, "", errors.New("key not found in credential info"))
	}

	info, err := AnalyzePermissions(a.Cfg, key, a.apiURL())
	if err != nil {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationAnalyzePermissions, analyzers.ServiceAPI, "", err)
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key, defaultBaseURL)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid Terraform Cloud / HCP Terraform token\n\n")

	printAccount(info.Account)
	printPermissions(info)
	printOrganizations(info.Organizations)
	printWorkspaces(info.Organizations)
	printVarsets(info.Organizations)

	if n := info.workspacesWithVariableRead(); n > 0 {
		color.Yellow("\n[i] This token can read workspace variables in %d workspace(s). Variable values are not retrieved.", n)
	}
}

func AnalyzePermissions(cfg *config.Config, key, baseURL string) (*SecretInfo, error) {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	client := analyzers.NewAnalyzeClient(cfg)
	secretInfo := &SecretInfo{}

	if err := captureAccount(client, baseURL, key, secretInfo); err != nil {
		return nil, err
	}

	if err := captureOrganizations(client, baseURL, key, secretInfo); err != nil {
		return secretInfo, err
	}

	return secretInfo, nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeTerraformCloud,
		Metadata: map[string]any{
			"username":                    info.Account.Username,
			"email":                       info.Account.Email,
			"is_service_account":          info.Account.IsServiceAccount,
			"authenticated_resource_type": info.Account.AuthenticatedResourceType,
			"authenticated_resource_id":   info.Account.AuthenticatedResourceID,
		},
		Bindings: make([]analyzers.Binding, 0),
	}

	accountResource := accountToResource(info.Account)
	accountPerms := append([]string{PermissionStrings[AccountRead]}, info.Account.Permissions...)
	result.Bindings = append(result.Bindings, analyzers.BindAllPermissions(*accountResource, permsFromStrings(accountPerms)...)...)

	for _, org := range info.Organizations {
		orgResource := organizationToResource(org, accountResource)
		orgPerms := append([]string{PermissionStrings[OrganizationsRead]}, org.Permissions...)
		result.Bindings = append(result.Bindings, analyzers.BindAllPermissions(*orgResource, permsFromStrings(orgPerms)...)...)

		for _, ws := range org.Workspaces {
			wsResource := workspaceToResource(ws, orgResource)
			wsPerms := append([]string{PermissionStrings[WorkspacesRead]}, ws.Permissions...)
			if ws.hasPermission(permCanReadVariable) {
				wsPerms = append(wsPerms, PermissionStrings[VariablesRead])
			}
			result.Bindings = append(result.Bindings, analyzers.BindAllPermissions(*wsResource, permsFromStrings(wsPerms)...)...)
		}

		for _, vs := range org.Varsets {
			vsResource := varsetToResource(vs, orgResource)
			result.Bindings = append(result.Bindings, analyzers.BindAllPermissions(*vsResource, analyzers.Permission{Value: PermissionStrings[VarsetsRead]})...)
		}
	}

	return &result
}

func permsFromStrings(values []string) []analyzers.Permission {
	seen := make(map[string]struct{}, len(values))
	perms := make([]analyzers.Permission, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		perms = append(perms, analyzers.Permission{Value: value})
	}
	return perms
}

func accountToResource(account Account) *analyzers.Resource {
	return &analyzers.Resource{
		Name:               account.Username,
		FullyQualifiedName: "terraformcloud/user/" + account.ID,
		Type:               resourceTypeAccount,
		Metadata: map[string]any{
			"id":                          account.ID,
			"email":                       account.Email,
			"is_service_account":          account.IsServiceAccount,
			"is_site_admin":               account.IsSiteAdmin,
			"authenticated_resource_type": account.AuthenticatedResourceType,
			"authenticated_resource_id":   account.AuthenticatedResourceID,
		},
	}
}

func organizationToResource(org Organization, parent *analyzers.Resource) *analyzers.Resource {
	return &analyzers.Resource{
		Name:               org.Name,
		FullyQualifiedName: "terraformcloud/organization/" + org.Name,
		Type:               resourceTypeOrganization,
		Metadata: map[string]any{
			"id":    org.ID,
			"email": org.Email,
		},
		Parent: parent,
	}
}

func workspaceToResource(ws Workspace, parent *analyzers.Resource) *analyzers.Resource {
	return &analyzers.Resource{
		Name:               ws.Name,
		FullyQualifiedName: "terraformcloud/workspace/" + ws.ID,
		Type:               resourceTypeWorkspace,
		Metadata: map[string]any{
			"id":                  ws.ID,
			"execution_mode":      ws.ExecutionMode,
			"terraform_version":   ws.TerraformVersion,
			"locked":              ws.Locked,
			"can_read_variable":   ws.hasPermission(permCanReadVariable),
			"can_update_variable": ws.hasPermission(permCanUpdateVariable),
		},
		Parent: parent,
	}
}

func varsetToResource(vs Varset, parent *analyzers.Resource) *analyzers.Resource {
	return &analyzers.Resource{
		Name:               vs.Name,
		FullyQualifiedName: "terraformcloud/varset/" + vs.ID,
		Type:               resourceTypeVariableSet,
		Metadata: map[string]any{
			"id":          vs.ID,
			"description": vs.Description,
			"global":      vs.Global,
			"priority":    vs.Priority,
		},
		Parent: parent,
	}
}

func printAccount(account Account) {
	if account.ID == "" {
		color.Red("[x] No account information found")
		return
	}

	color.Yellow("[i] Account Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Username", "Email", "Service Account", "Authenticated Resource"})
	authResource := account.AuthenticatedResourceType
	if account.AuthenticatedResourceID != "" {
		authResource = fmt.Sprintf("%s/%s", account.AuthenticatedResourceType, account.AuthenticatedResourceID)
	}
	t.AppendRow(table.Row{
		color.GreenString(account.ID),
		color.GreenString(account.Username),
		color.GreenString(account.Email),
		color.GreenString(fmt.Sprintf("%t", account.IsServiceAccount)),
		color.GreenString(authResource),
	})
	t.Render()
}

func printPermissions(info *SecretInfo) {
	perms := uniquePermissions(info)
	if len(perms) == 0 {
		color.Red("[x] No permissions found")
		return
	}

	color.Yellow("\n[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, perm := range perms {
		t.AppendRow(table.Row{color.GreenString(perm)})
	}
	t.Render()
}

func printOrganizations(orgs []Organization) {
	if len(orgs) == 0 {
		color.Red("\n[x] No organizations found")
		return
	}

	color.Yellow("\n[i] Organizations:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "ID", "Create Workspace", "Read Varsets", "Manage Varsets", "Destroy"})
	for _, org := range orgs {
		t.AppendRow(table.Row{
			color.GreenString(org.Name),
			color.GreenString(org.ID),
			color.GreenString(fmt.Sprintf("%t", org.hasPermission(permCanCreateWorkspace))),
			color.GreenString(fmt.Sprintf("%t", org.hasPermission(permCanReadVarsets))),
			color.GreenString(fmt.Sprintf("%t", org.hasPermission(permCanManageVarsets))),
			color.GreenString(fmt.Sprintf("%t", org.hasPermission(permCanDestroy))),
		})
	}
	t.Render()
}

func printWorkspaces(orgs []Organization) {
	hasWorkspaces := false
	for _, org := range orgs {
		if len(org.Workspaces) > 0 {
			hasWorkspaces = true
			break
		}
	}
	if !hasWorkspaces {
		return
	}

	color.Yellow("\n[i] Workspaces:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Organization", "Name", "Read Variables", "Update Variables", "Queue Run", "Destroy"})
	for _, org := range orgs {
		for _, ws := range org.Workspaces {
			t.AppendRow(table.Row{
				color.GreenString(org.Name),
				color.GreenString(ws.Name),
				color.GreenString(fmt.Sprintf("%t", ws.hasPermission(permCanReadVariable))),
				color.GreenString(fmt.Sprintf("%t", ws.hasPermission(permCanUpdateVariable))),
				color.GreenString(fmt.Sprintf("%t", ws.hasPermission(permCanQueueRun))),
				color.GreenString(fmt.Sprintf("%t", ws.hasPermission(permCanDestroy))),
			})
		}
	}
	t.Render()
}

func printVarsets(orgs []Organization) {
	hasVarsets := false
	for _, org := range orgs {
		if len(org.Varsets) > 0 {
			hasVarsets = true
			break
		}
	}
	if !hasVarsets {
		return
	}

	color.Yellow("\n[i] Variable Sets (names only; values are not retrieved):")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Organization", "Name", "Global", "Priority"})
	for _, org := range orgs {
		for _, vs := range org.Varsets {
			t.AppendRow(table.Row{
				color.GreenString(org.Name),
				color.GreenString(vs.Name),
				color.GreenString(fmt.Sprintf("%t", vs.Global)),
				color.GreenString(fmt.Sprintf("%t", vs.Priority)),
			})
		}
	}
	t.Render()
}

func uniquePermissions(info *SecretInfo) []string {
	seen := map[string]struct{}{
		PermissionStrings[AccountRead]: {},
	}
	for _, perm := range info.Account.Permissions {
		seen[perm] = struct{}{}
	}
	if len(info.Organizations) > 0 {
		seen[PermissionStrings[OrganizationsRead]] = struct{}{}
	}

	hasWorkspaces := false
	hasVarsets := false
	hasVariableRead := false
	for _, org := range info.Organizations {
		for _, perm := range org.Permissions {
			seen[perm] = struct{}{}
		}
		if len(org.Workspaces) > 0 {
			hasWorkspaces = true
		}
		if len(org.Varsets) > 0 {
			hasVarsets = true
		}
		for _, ws := range org.Workspaces {
			for _, perm := range ws.Permissions {
				seen[perm] = struct{}{}
			}
			if ws.hasPermission(permCanReadVariable) {
				hasVariableRead = true
			}
		}
	}
	if hasWorkspaces {
		seen[PermissionStrings[WorkspacesRead]] = struct{}{}
	}
	if hasVarsets {
		seen[PermissionStrings[VarsetsRead]] = struct{}{}
	}
	if hasVariableRead {
		seen[PermissionStrings[VariablesRead]] = struct{}{}
	}

	perms := make([]string, 0, len(seen))
	for perm := range seen {
		perms = append(perms, perm)
	}
	slices.Sort(perms)
	return perms
}
