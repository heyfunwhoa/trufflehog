package doppler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestAnalyzer_MissingKey(t *testing.T) {
	a := Analyzer{Cfg: &config.Config{}}
	_, err := a.Analyze(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer dp.pt.testtoken" {
			t.Errorf("unexpected auth header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v3/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "ci-token",
				"type": "personal",
				"workplace": map[string]string{
					"name": "Acme",
					"slug": "acme",
				},
			})
		case "/v3/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"projects": []map[string]string{{
					"id":   "proj_1",
					"name": "API",
					"slug": "api",
				}},
			})
		case "/v3/configs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"configs": []map[string]string{{
					"name":        "prd",
					"environment": "prd",
					"project":     "api",
				}},
			})
		case "/v3/configs/config/secrets/names":
			w.WriteHeader(http.StatusForbidden)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}, baseURL: server.URL}
	got, err := a.Analyze(context.Background(), map[string]string{"key": "dp.pt.testtoken"})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got.AnalyzerType != analyzers.AnalyzerTypeDoppler {
		t.Fatalf("AnalyzerType = %v", got.AnalyzerType)
	}
	if got.Metadata["workplace"] != "Acme" {
		t.Fatalf("workplace metadata = %v", got.Metadata["workplace"])
	}
	if len(got.Bindings) == 0 {
		t.Fatal("expected bindings")
	}

	permSet := map[string]bool{}
	for _, binding := range got.Bindings {
		permSet[binding.Permission.Value] = true
	}
	for _, want := range []string{"workplace_read", "projects_read", "configs_read"} {
		if !permSet[want] {
			t.Errorf("missing permission %s in %v", want, permSet)
		}
	}

	if len(got.UnboundedResources) < 2 {
		t.Fatalf("expected project and config resources, got %d", len(got.UnboundedResources))
	}
}

func TestAnalyzer_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}, baseURL: server.URL}
	got, err := a.Analyze(context.Background(), map[string]string{"key": "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}
