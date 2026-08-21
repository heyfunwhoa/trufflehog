//go:generate generate_permissions permissions.yaml permissions.go cloudflare
package cloudflare

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
	defaultAPIBase = "https://api.cloudflare.com/client/v4"
	maxResources   = 25
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg     *config.Config
	baseURL string
}

type SecretInfo struct {
	TokenID     string
	Status      string
	User        User
	Accounts    []Account
	Zones       []Zone
	Permissions []string
}

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Zone struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	Account Account `json:"account"`
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeCloudflare
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

	info, err := analyzePermissions(analyzers.NewAnalyzeClient(a.Cfg), a.apiBase(), key, credInfo["account_id"])
	if err != nil {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationAnalyzePermissions, analyzers.ServiceAPI, "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key, accountID string) {
	info, err := AnalyzePermissions(cfg, key, accountID)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
	}
	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid Cloudflare API token\n\n")
	printTokenInfo(info)
	printPermissions(info.Permissions)
	printAccounts(info.Accounts)
	printZones(info.Zones)
}

func AnalyzePermissions(cfg *config.Config, key, accountID string) (*SecretInfo, error) {
	return analyzePermissions(analyzers.NewAnalyzeClient(cfg), defaultAPIBase, key, accountID)
}

func analyzePermissions(client *http.Client, baseURL, key, accountID string) (*SecretInfo, error) {
	info := &SecretInfo{}

	if err := verifyToken(client, baseURL, key, accountID, info); err != nil {
		return nil, err
	}
	info.Permissions = append(info.Permissions, PermissionStrings[TokenVerify])

	if user, err := fetchUser(client, baseURL, key); err == nil {
		info.User = user
		info.Permissions = append(info.Permissions, PermissionStrings[UserRead])
	}

	if accounts, err := fetchAccounts(client, baseURL, key); err == nil {
		info.Accounts = accounts
		if len(accounts) > 0 {
			info.Permissions = append(info.Permissions, PermissionStrings[AccountRead])
		}
	}

	if zones, err := fetchZones(client, baseURL, key); err == nil {
		info.Zones = zones
		if len(zones) > 0 {
			info.Permissions = append(info.Permissions, PermissionStrings[ZoneRead])
		}
	}

	if info.TokenID != "" {
		if ok, err := canReadToken(client, baseURL, key, info.TokenID); err == nil && ok {
			info.Permissions = append(info.Permissions, PermissionStrings[TokensRead])
		}
	}

	return info, nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	name := firstNonEmpty(info.User.Email, info.User.Username, info.TokenID, "cloudflare-token")
	tokenResource := analyzers.Resource{
		Name:               name,
		FullyQualifiedName: "cloudflare/token/" + firstNonEmpty(info.TokenID, info.User.ID, name),
		Type:               "api_token",
		Metadata: map[string]any{
			"status":   info.Status,
			"email":    info.User.Email,
			"username": info.User.Username,
			"user_id":  info.User.ID,
		},
	}

	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeCloudflare,
		Metadata: map[string]any{
			"token_id": info.TokenID,
			"status":   info.Status,
			"email":    info.User.Email,
		},
		Bindings: analyzers.BindAllPermissions(tokenResource, permissionValues(info.Permissions)...),
	}

	for _, account := range info.Accounts {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               account.Name,
			FullyQualifiedName: "cloudflare/account/" + account.ID,
			Type:               "account",
			Parent:             &tokenResource,
		})
	}
	for _, zone := range info.Zones {
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               zone.Name,
			FullyQualifiedName: "cloudflare/zone/" + zone.ID,
			Type:               "zone",
			Parent:             &tokenResource,
			Metadata: map[string]any{
				"status":  zone.Status,
				"account": zone.Account.Name,
			},
		})
	}

	return result
}

func verifyToken(client *http.Client, baseURL, key, accountID string, info *SecretInfo) error {
	endpoint := baseURL + "/user/tokens/verify"
	if accountID != "" {
		endpoint = baseURL + "/accounts/" + accountID + "/tokens/verify"
	}

	body, status, err := doCFGET(client, endpoint, key)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return errors.New("invalid Cloudflare API token")
	}
	if status != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", status)
	}

	var resp struct {
		Success bool `json:"success"`
		Result  struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	if !resp.Success {
		return errors.New("cloudflare token verify was unsuccessful")
	}
	info.TokenID = resp.Result.ID
	info.Status = resp.Result.Status
	return nil
}

func fetchUser(client *http.Client, baseURL, key string) (User, error) {
	body, status, err := doCFGET(client, baseURL+"/user", key)
	if err != nil {
		return User{}, err
	}
	if status != http.StatusOK {
		return User{}, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Result User `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return User{}, err
	}
	return resp.Result, nil
}

func fetchAccounts(client *http.Client, baseURL, key string) ([]Account, error) {
	body, status, err := doCFGET(client, baseURL+"/accounts?per_page=25", key)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Result []Account `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Result) > maxResources {
		return resp.Result[:maxResources], nil
	}
	return resp.Result, nil
}

func fetchZones(client *http.Client, baseURL, key string) ([]Zone, error) {
	body, status, err := doCFGET(client, baseURL+"/zones?per_page=25", key)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", status)
	}
	var resp struct {
		Result []Zone `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Result) > maxResources {
		return resp.Result[:maxResources], nil
	}
	return resp.Result, nil
}

func canReadToken(client *http.Client, baseURL, key, tokenID string) (bool, error) {
	_, status, err := doCFGET(client, baseURL+"/user/tokens/"+tokenID, key)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK, nil
}

func doCFGET(client *http.Client, endpoint, key string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")

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
	t.AppendHeader(table.Row{"Token ID", "Status", "Email", "Username"})
	t.AppendRow(table.Row{
		color.GreenString(info.TokenID),
		color.GreenString(info.Status),
		color.GreenString(info.User.Email),
		color.GreenString(info.User.Username),
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

func printAccounts(accounts []Account) {
	if len(accounts) == 0 {
		return
	}
	color.Yellow("[i] Accounts:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "ID"})
	for _, account := range accounts {
		t.AppendRow(table.Row{color.GreenString(account.Name), color.GreenString(account.ID)})
	}
	t.Render()
}

func printZones(zones []Zone) {
	if len(zones) == 0 {
		return
	}
	color.Yellow("[i] Zones:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Status", "Account"})
	for _, zone := range zones {
		t.AppendRow(table.Row{color.GreenString(zone.Name), color.GreenString(zone.Status), color.GreenString(zone.Account.Name)})
	}
	t.Render()
}
