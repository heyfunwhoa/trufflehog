package terraformcloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	tfcJSONMediaType = "application/vnd.api+json"
	maxOrganizations = 10
	resourcePageSize = 25
)

type jsonAPIResource struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Attributes    map[string]any `json:"attributes"`
	Relationships map[string]struct {
		Data *struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	} `json:"relationships"`
}

type jsonAPISingle struct {
	Data jsonAPIResource `json:"data"`
}

type jsonAPIList struct {
	Data []jsonAPIResource `json:"data"`
}

func captureAccount(client *http.Client, baseURL, token string, info *SecretInfo) error {
	body, status, err := tfcGET(client, token, joinAPI(baseURL, "/api/v2/account/details"))
	if err != nil {
		return fmt.Errorf("failed to fetch account details: %w", err)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("invalid Terraform Cloud token")
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("account details returned status %d", status)
	}

	var resp jsonAPISingle
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal account details: %w", err)
	}

	info.Account = Account{
		ID:               resp.Data.ID,
		Username:         attrString(resp.Data.Attributes, "username"),
		Email:            attrString(resp.Data.Attributes, "email"),
		IsServiceAccount: attrBool(resp.Data.Attributes, "is-service-account"),
		IsSiteAdmin:      attrBool(resp.Data.Attributes, "is-site-admin"),
		Permissions:      grantedPermissions(resp.Data.Attributes["permissions"]),
	}
	if rel, ok := resp.Data.Relationships["authenticated-resource"]; ok && rel.Data != nil {
		info.Account.AuthenticatedResourceType = rel.Data.Type
		info.Account.AuthenticatedResourceID = rel.Data.ID
	}
	return nil
}

func captureOrganizations(client *http.Client, baseURL, token string, info *SecretInfo) error {
	orgsPath, err := withPageSize("/api/v2/organizations", maxOrganizations)
	if err != nil {
		return err
	}

	body, status, err := tfcGET(client, token, joinAPI(baseURL, orgsPath))
	if err != nil {
		return fmt.Errorf("failed to list organizations: %w", err)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("organizations returned status %d", status)
	}

	var resp jsonAPIList
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal organizations: %w", err)
	}

	for i, item := range resp.Data {
		if i >= maxOrganizations {
			break
		}
		org := Organization{
			ID:          item.ID,
			Name:        attrString(item.Attributes, "name"),
			Email:       attrString(item.Attributes, "email"),
			Permissions: grantedPermissions(item.Attributes["permissions"]),
		}
		if org.Name == "" {
			org.Name = item.ID
		}

		if err := captureWorkspaces(client, baseURL, token, &org); err != nil {
			info.Organizations = append(info.Organizations, org)
			return err
		}
		if err := captureVarsets(client, baseURL, token, &org); err != nil {
			info.Organizations = append(info.Organizations, org)
			return err
		}
		info.Organizations = append(info.Organizations, org)
	}
	return nil
}

func captureWorkspaces(client *http.Client, baseURL, token string, org *Organization) error {
	path, err := withPageSize("/api/v2/organizations/"+url.PathEscape(org.Name)+"/workspaces", resourcePageSize)
	if err != nil {
		return err
	}

	body, status, err := tfcGET(client, token, joinAPI(baseURL, path))
	if err != nil {
		return fmt.Errorf("failed to list workspaces for %s: %w", org.Name, err)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("workspaces for %s returned status %d", org.Name, status)
	}

	var resp jsonAPIList
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal workspaces for %s: %w", org.Name, err)
	}

	for _, item := range resp.Data {
		org.Workspaces = append(org.Workspaces, Workspace{
			ID:               item.ID,
			Name:             attrString(item.Attributes, "name"),
			ExecutionMode:    attrString(item.Attributes, "execution-mode"),
			TerraformVersion: attrString(item.Attributes, "terraform-version"),
			Locked:           attrBool(item.Attributes, "locked"),
			Permissions:      grantedPermissions(item.Attributes["permissions"]),
		})
	}
	return nil
}

func captureVarsets(client *http.Client, baseURL, token string, org *Organization) error {
	path, err := withPageSize("/api/v2/organizations/"+url.PathEscape(org.Name)+"/varsets", resourcePageSize)
	if err != nil {
		return err
	}

	body, status, err := tfcGET(client, token, joinAPI(baseURL, path))
	if err != nil {
		return fmt.Errorf("failed to list variable sets for %s: %w", org.Name, err)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("variable sets for %s returned status %d", org.Name, status)
	}

	var resp jsonAPIList
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal variable sets for %s: %w", org.Name, err)
	}

	for _, item := range resp.Data {
		org.Varsets = append(org.Varsets, Varset{
			ID:          item.ID,
			Name:        attrString(item.Attributes, "name"),
			Description: attrString(item.Attributes, "description"),
			Global:      attrBool(item.Attributes, "global"),
			Priority:    attrBool(item.Attributes, "priority"),
		})
	}
	return nil
}

func tfcGET(client *http.Client, token, endpoint string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", tfcJSONMediaType)
	req.Header.Set("Accept", tfcJSONMediaType)

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

func joinAPI(baseURL, path string) string {
	return strings.TrimRight(baseURL, "/") + path
}

func withPageSize(path string, size int) (string, error) {
	u, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("page[size]", strconv.Itoa(size))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func attrString(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	if value, ok := attrs[key].(string); ok {
		return value
	}
	return ""
}

func attrBool(attrs map[string]any, key string) bool {
	if attrs == nil {
		return false
	}
	value, ok := attrs[key].(bool)
	return ok && value
}

func grantedPermissions(raw any) []string {
	perms, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	granted := make([]string, 0, len(perms))
	for name, value := range perms {
		if allowed, ok := value.(bool); ok && allowed {
			granted = append(granted, name)
		}
	}
	slices.Sort(granted)
	return granted
}
