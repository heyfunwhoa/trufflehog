package terraformcloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const testToken = "test-tfc-token"

func TestAnalyzer_Analyze_missingKey(t *testing.T) {
	a := Analyzer{Cfg: &config.Config{}}
	got, err := a.Analyze(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if got != nil {
		t.Fatalf("expected nil result, got %+v", got)
	}
}

func TestAnalyzer_Analyze_invalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	a := Analyzer{Cfg: &config.Config{}, baseURL: srv.URL}
	got, err := a.Analyze(context.Background(), map[string]string{"key": "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if got != nil {
		t.Fatalf("expected nil result, got %+v", got)
	}
}

func TestAnalyzer_Analyze_validToken(t *testing.T) {
	srv := newTFCServer(t, http.StatusOK)
	a := Analyzer{Cfg: &config.Config{}, baseURL: srv.URL}

	got, err := a.Analyze(context.Background(), map[string]string{"key": testToken})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got == nil {
		t.Fatal("Analyze() returned nil result")
	}
	if got.AnalyzerType != analyzers.AnalyzerTypeTerraformCloud {
		t.Fatalf("AnalyzerType = %v, want TerraformCloud", got.AnalyzerType)
	}

	if got.Metadata["username"] != "kristen" {
		t.Fatalf("metadata username = %v, want kristen", got.Metadata["username"])
	}
	if got.Metadata["is_service_account"] != false {
		t.Fatalf("metadata is_service_account = %v, want false", got.Metadata["is_service_account"])
	}

	perms := permissionSet(got)
	assertHas := func(resourceType, name, perm string) {
		t.Helper()
		key := resourceType + "/" + name
		if !perms[key][perm] {
			t.Fatalf("missing permission %q on %s; have %v", perm, key, perms[key])
		}
	}

	assertHas(resourceTypeAccount, "kristen", PermissionStrings[AccountRead])
	assertHas(resourceTypeAccount, "kristen", "can-create-organizations")
	assertHas(resourceTypeOrganization, "acme", PermissionStrings[OrganizationsRead])
	assertHas(resourceTypeOrganization, "acme", permCanReadVarsets)
	assertHas(resourceTypeOrganization, "acme", permCanManageVarsets)
	assertHas(resourceTypeWorkspace, "prod", PermissionStrings[WorkspacesRead])
	assertHas(resourceTypeWorkspace, "prod", permCanReadVariable)
	assertHas(resourceTypeWorkspace, "prod", permCanUpdateVariable)
	assertHas(resourceTypeWorkspace, "prod", PermissionStrings[VariablesRead])
	assertHas(resourceTypeVariableSet, "shared-secrets", PermissionStrings[VarsetsRead])

	for _, binding := range got.Bindings {
		raw, _ := json.Marshal(binding)
		if strings.Contains(string(raw), "super-secret-value") {
			t.Fatalf("binding leaked a variable value: %s", raw)
		}
	}

	var sawWorkspaceParent bool
	for _, binding := range got.Bindings {
		if binding.Resource.Type == resourceTypeWorkspace && binding.Resource.Name == "prod" {
			if binding.Resource.Parent == nil || binding.Resource.Parent.Name != "acme" {
				t.Fatalf("workspace parent = %+v, want organization acme", binding.Resource.Parent)
			}
			sawWorkspaceParent = true
		}
	}
	if !sawWorkspaceParent {
		t.Fatal("did not find workspace binding with parent organization")
	}
}

func TestAnalyzer_Analyze_orgsForbidden(t *testing.T) {
	srv := newTFCServer(t, http.StatusForbidden)
	a := Analyzer{Cfg: &config.Config{}, baseURL: srv.URL}

	got, err := a.Analyze(context.Background(), map[string]string{"key": testToken})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got.Metadata["username"] != "kristen" {
		t.Fatalf("expected account metadata after org 403, got %v", got.Metadata)
	}

	for _, binding := range got.Bindings {
		if binding.Resource.Type == resourceTypeOrganization {
			t.Fatalf("expected no organization bindings after 403, got %+v", binding.Resource)
		}
	}
}

func permissionSet(result *analyzers.AnalyzerResult) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for _, binding := range result.Bindings {
		key := binding.Resource.Type + "/" + binding.Resource.Name
		if out[key] == nil {
			out[key] = make(map[string]bool)
		}
		out[key][binding.Permission.Value] = true
	}
	return out
}

func newTFCServer(t *testing.T, orgStatus int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", tfcJSONMediaType)

		switch {
		case r.URL.Path == "/api/v2/account/details":
			_, _ = w.Write([]byte(`{
				"data": {
					"id": "user-abc",
					"type": "users",
					"attributes": {
						"username": "kristen",
						"email": "kristen@example.com",
						"is-service-account": false,
						"is-site-admin": false,
						"permissions": {
							"can-create-organizations": true,
							"can-change-email": false
						}
					},
					"relationships": {
						"authenticated-resource": {
							"data": {"id": "user-abc", "type": "users"}
						}
					}
				}
			}`))
		case r.URL.Path == "/api/v2/organizations":
			if orgStatus != http.StatusOK {
				w.WriteHeader(orgStatus)
				return
			}
			_, _ = w.Write([]byte(`{
				"data": [{
					"id": "org-acme",
					"type": "organizations",
					"attributes": {
						"name": "acme",
						"email": "ops@acme.com",
						"permissions": {
							"can-create-workspace": true,
							"can-read-varsets": true,
							"can-manage-varsets": true,
							"can-destroy": false
						}
					}
				}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/workspaces"):
			_, _ = w.Write([]byte(`{
				"data": [{
					"id": "ws-prod",
					"type": "workspaces",
					"attributes": {
						"name": "prod",
						"execution-mode": "remote",
						"terraform-version": "1.9.0",
						"locked": false,
						"permissions": {
							"can-read-variable": true,
							"can-update-variable": true,
							"can-queue-run": true,
							"can-destroy": false
						}
					}
				}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/varsets"):
			_, _ = w.Write([]byte(`{
				"data": [{
					"id": "varset-1",
					"type": "varsets",
					"attributes": {
						"name": "shared-secrets",
						"description": "shared",
						"global": false,
						"priority": true
					}
				}]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
}
