package cloudflare

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

func TestAnalyzer_MissingKey(t *testing.T) {
	a := Analyzer{Cfg: &config.Config{}}
	if _, err := a.Analyze(context.Background(), map[string]string{}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer cfut_test" {
			t.Errorf("unexpected auth header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user/tokens/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]string{"id": "tok-1", "status": "active"},
			})
		case r.URL.Path == "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]string{"id": "u1", "email": "ops@example.com", "username": "ops"},
			})
		case strings.HasPrefix(r.URL.Path, "/accounts"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]string{{"id": "acc-1", "name": "Acme"}},
			})
		case strings.HasPrefix(r.URL.Path, "/zones"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{{
					"id":      "zone-1",
					"name":    "example.com",
					"status":  "active",
					"account": map[string]string{"id": "acc-1", "name": "Acme"},
				}},
			})
		case r.URL.Path == "/user/tokens/tok-1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	a := Analyzer{Cfg: &config.Config{}, baseURL: server.URL}
	got, err := a.Analyze(context.Background(), map[string]string{"key": "cfut_test"})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got.AnalyzerType != analyzers.AnalyzerTypeCloudflare {
		t.Fatalf("AnalyzerType = %v", got.AnalyzerType)
	}

	permSet := map[string]bool{}
	for _, binding := range got.Bindings {
		permSet[binding.Permission.Value] = true
	}
	for _, want := range []string{"token_verify", "user_read", "account_read", "zone_read", "tokens_read"} {
		if !permSet[want] {
			t.Errorf("missing permission %s in %v", want, permSet)
		}
	}
	if len(got.UnboundedResources) != 2 {
		t.Fatalf("expected account and zone resources, got %d", len(got.UnboundedResources))
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
