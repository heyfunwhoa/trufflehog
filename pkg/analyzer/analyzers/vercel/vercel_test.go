package vercel

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
	if _, err := a.Analyze(context.Background(), map[string]string{}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer vercel-token" {
			t.Errorf("unexpected auth header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/user":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]string{
					"id":       "usr_1",
					"username": "jane",
					"name":     "Jane Doe",
					"email":    "jane@example.com",
				},
			})
		case "/v2/teams":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"teams": []map[string]string{{
					"id":   "team_1",
					"name": "Acme",
					"slug": "acme",
				}},
			})
		case "/v9/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"projects": []map[string]string{{
					"id":        "prj_1",
					"name":      "web",
					"framework": "nextjs",
					"accountId": "team_1",
				}},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}, baseURL: server.URL}
	got, err := a.Analyze(context.Background(), map[string]string{"key": "vercel-token"})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got.AnalyzerType != analyzers.AnalyzerTypeVercel {
		t.Fatalf("AnalyzerType = %v", got.AnalyzerType)
	}
	if got.Metadata["username"] != "jane" {
		t.Fatalf("username metadata = %v", got.Metadata["username"])
	}

	permSet := map[string]bool{}
	for _, binding := range got.Bindings {
		permSet[binding.Permission.Value] = true
	}
	for _, want := range []string{"user_read", "teams_read", "projects_read"} {
		if !permSet[want] {
			t.Errorf("missing permission %s in %v", want, permSet)
		}
	}
	if len(got.UnboundedResources) != 2 {
		t.Fatalf("expected team and project resources, got %d", len(got.UnboundedResources))
	}
}

func TestAnalyzer_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}, baseURL: server.URL}
	got, err := a.Analyze(context.Background(), map[string]string{"key": "bad"})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}
