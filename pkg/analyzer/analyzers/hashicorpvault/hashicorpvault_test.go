package hashicorpvault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestAnalyzer_MissingCredentials(t *testing.T) {
	a := Analyzer{Cfg: &config.Config{}}
	if _, err := a.Analyze(context.Background(), map[string]string{"key": "tok"}); err == nil {
		t.Fatal("expected error for missing url")
	}
	if _, err := a.Analyze(context.Background(), map[string]string{"url": "https://vault.example"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "hvs.testtoken" {
			t.Errorf("unexpected vault token header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"display_name": "token-admin",
					"entity_id":    "ent-1",
					"expire_time":  "2026-01-01T00:00:00Z",
					"orphan":       true,
					"policies":     []string{"default", "admin"},
					"renewable":    true,
					"type":         "service",
				},
			})
		case "/v1/sys/mounts":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"secret/": map[string]string{"type": "kv", "description": "kv secrets"},
					"sys/":    map[string]string{"type": "system", "description": "system"},
				},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}}
	got, err := a.Analyze(context.Background(), map[string]string{
		"key": "hvs.testtoken",
		"url": server.URL,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got.AnalyzerType != analyzers.AnalyzerTypeHashiCorpVault {
		t.Fatalf("AnalyzerType = %v", got.AnalyzerType)
	}

	permSet := map[string]bool{}
	for _, binding := range got.Bindings {
		permSet[binding.Permission.Value] = true
	}
	for _, want := range []string{"lookup_self", "list_mounts", "policy:default", "policy:admin"} {
		if !permSet[want] {
			t.Errorf("missing permission %s in %v", want, permSet)
		}
	}
	if len(got.UnboundedResources) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(got.UnboundedResources))
	}
}

func TestAnalyzer_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}}
	got, err := a.Analyze(context.Background(), map[string]string{
		"key": "bad",
		"url": server.URL,
	})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}
