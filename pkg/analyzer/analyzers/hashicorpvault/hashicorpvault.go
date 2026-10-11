//go:generate generate_permissions permissions.yaml permissions.go hashicorpvault
package hashicorpvault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const maxMounts = 50

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

type SecretInfo struct {
	DisplayName string
	EntityID    string
	TokenType   string
	ExpireTime  string
	Orphan      bool
	Renewable   bool
	Policies    []string
	Mounts      []Mount
	Permissions []string
}

type Mount struct {
	Path        string
	Type        string
	Description string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeHashiCorpVault
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationValidateCredentials, analyzers.ServiceConfig, "", errors.New("key not found in credential info"))
	}
	vaultURL, ok := credInfo["url"]
	if !ok {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationValidateCredentials, analyzers.ServiceConfig, "", errors.New("url not found in credential info"))
	}

	info, err := AnalyzePermissions(a.Cfg, token, vaultURL)
	if err != nil {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationAnalyzePermissions, analyzers.ServiceAPI, "", err)
	}
	return secretInfoToAnalyzerResult(info, vaultURL), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token, vaultURL string) {
	info, err := AnalyzePermissions(cfg, token, vaultURL)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
	}
	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid HashiCorp Vault token\n\n")
	printTokenInfo(info)
	printPermissions(info.Permissions)
	printPolicies(info.Policies)
	printMounts(info.Mounts)
}

func AnalyzePermissions(cfg *config.Config, token, vaultURL string) (*SecretInfo, error) {
	return analyzePermissions(analyzers.NewAnalyzeClient(cfg), token, vaultURL)
}

func analyzePermissions(client *http.Client, token, vaultURL string) (*SecretInfo, error) {
	baseURL := strings.TrimRight(vaultURL, "/")
	info := &SecretInfo{}

	if err := captureLookupSelf(client, baseURL, token, info); err != nil {
		return nil, err
	}
	info.Permissions = append(info.Permissions, PermissionStrings[LookupSelf])

	if err := captureMounts(client, baseURL, token, info); err == nil {
		info.Permissions = append(info.Permissions, PermissionStrings[ListMounts])
	}

	return info, nil
}

func secretInfoToAnalyzerResult(info *SecretInfo, vaultURL string) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	tokenResource := analyzers.Resource{
		Name:               firstNonEmpty(info.DisplayName, "vault-token"),
		FullyQualifiedName: "vault/token/" + firstNonEmpty(info.EntityID, info.DisplayName, vaultURL),
		Type:               "token",
		Metadata: map[string]any{
			"url":         vaultURL,
			"type":        info.TokenType,
			"expire_time": info.ExpireTime,
			"orphan":      info.Orphan,
			"renewable":   info.Renewable,
			"entity_id":   info.EntityID,
		},
	}

	perms := permissionValues(info.Permissions)
	for _, policy := range info.Policies {
		perms = append(perms, analyzers.Permission{Value: "policy:" + policy})
	}

	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeHashiCorpVault,
		Metadata: map[string]any{
			"url":         vaultURL,
			"type":        info.TokenType,
			"expire_time": info.ExpireTime,
			"orphan":      info.Orphan,
			"renewable":   info.Renewable,
		},
		Bindings: analyzers.BindAllPermissions(tokenResource, perms...),
	}

	for _, mount := range info.Mounts {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               mount.Path,
			FullyQualifiedName: "vault/mount/" + mount.Path,
			Type:               "mount",
			Parent:             &tokenResource,
			Metadata: map[string]any{
				"type":        mount.Type,
				"description": mount.Description,
			},
		})
	}

	return result
}

func captureLookupSelf(client *http.Client, baseURL, token string, info *SecretInfo) error {
	lookupURL, err := url.JoinPath(baseURL, "/v1/auth/token/lookup-self")
	if err != nil {
		return err
	}
	body, status, err := doVaultGET(client, lookupURL, token)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return errors.New("invalid Vault token")
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", status)
	}

	var resp struct {
		Data struct {
			DisplayName string   `json:"display_name"`
			EntityID    string   `json:"entity_id"`
			ExpireTime  string   `json:"expire_time"`
			Orphan      bool     `json:"orphan"`
			Policies    []string `json:"policies"`
			Renewable   bool     `json:"renewable"`
			Type        string   `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}

	info.DisplayName = resp.Data.DisplayName
	info.EntityID = resp.Data.EntityID
	info.ExpireTime = resp.Data.ExpireTime
	info.Orphan = resp.Data.Orphan
	info.Policies = resp.Data.Policies
	info.Renewable = resp.Data.Renewable
	info.TokenType = resp.Data.Type
	return nil
}

func captureMounts(client *http.Client, baseURL, token string, info *SecretInfo) error {
	mountsURL, err := url.JoinPath(baseURL, "/v1/sys/mounts")
	if err != nil {
		return err
	}
	body, status, err := doVaultGET(client, mountsURL, token)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", status)
	}

	var wrapped struct {
		Data map[string]struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return err
	}

	mounts := wrapped.Data
	if len(mounts) == 0 {
		// Older Vault versions return mounts at the top level.
		var topLevel map[string]struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(body, &topLevel); err == nil {
			mounts = topLevel
		}
	}

	for path, mount := range mounts {
		if mount.Type == "" {
			continue
		}
		info.Mounts = append(info.Mounts, Mount{
			Path:        path,
			Type:        mount.Type,
			Description: mount.Description,
		})
		if len(info.Mounts) >= maxMounts {
			break
		}
	}
	return nil
}

func doVaultGET(client *http.Client, endpoint, token string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", token)
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

func printTokenInfo(info *SecretInfo) {
	color.Yellow("[i] Token Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Display Name", "Type", "Entity ID", "Expires", "Orphan", "Renewable"})
	t.AppendRow(table.Row{
		color.GreenString(info.DisplayName),
		color.GreenString(info.TokenType),
		color.GreenString(info.EntityID),
		color.GreenString(info.ExpireTime),
		color.GreenString(fmt.Sprintf("%t", info.Orphan)),
		color.GreenString(fmt.Sprintf("%t", info.Renewable)),
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

func printPolicies(policies []string) {
	if len(policies) == 0 {
		return
	}
	color.Yellow("[i] Policies:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Policy"})
	for _, policy := range policies {
		t.AppendRow(table.Row{color.GreenString(policy)})
	}
	t.Render()
}

func printMounts(mounts []Mount) {
	if len(mounts) == 0 {
		return
	}
	color.Yellow("[i] Secret Engines:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Path", "Type", "Description"})
	for _, mount := range mounts {
		t.AppendRow(table.Row{color.GreenString(mount.Path), color.GreenString(mount.Type), color.GreenString(mount.Description)})
	}
	t.Render()
}
