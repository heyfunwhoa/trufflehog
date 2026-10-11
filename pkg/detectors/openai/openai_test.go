package openai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// The default client must retry transient failures so a single slow or
// failed OpenAI API response does not record an indeterminate verification
// result (CSM-2131).
func TestOpenAI_DefaultClientRetriesTransientErrors(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := defaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected retries to reach a 200 response, got %d", res.StatusCode)
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 attempts (initial + 2 retries), got %d", got)
	}
}

// When the API never recovers, the client must give up after the configured
// retry budget (initial attempt + 2 retries) and surface the failure rather
// than retrying indefinitely.
func TestOpenAI_DefaultClientGivesUpAfterRetryBudget(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := defaultClient.Do(req)
	if res != nil {
		defer func() { _ = res.Body.Close() }()
	}

	if err == nil && res.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected exhausted retries to surface the failure, got status %d with no error", res.StatusCode)
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 attempts (initial + 2 retries), got %d", got)
	}
}

func TestOpenAI_DoesNotMatchAdminKeys(t *testing.T) {
	d := Scanner{}
	adminKey := `OPENAI_ADMIN_KEY = "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"`

	results, err := d.FromData(context.Background(), false, []byte(adminKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("openai detector should not match admin keys, but got %d results", len(results))
	}
}

func TestOpenAI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "user API key",
			input: "openai.api-key: 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",
			want:  []string{"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"},
		},
		{
			name:  "project API key",
			input: `OPENAI_API_KEY = "sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"`,
			want:  []string{"sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"},
		},
		{
			name:  "service account API key",
			input: `OPENAI_API_KEY = "sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"`,
			want:  []string{"sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"},
		},
		{
			name:  "newer user API key",
			input: `"OPENAI_API_KEY = "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"`,
			want:  []string{"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"},
		},
		{
			name:  "newer service account API key",
			input: `OPENAI_API_KEY = "sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"`,
			want:  []string{"sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

const sampleOpenAIKey = "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"

const liveMeBody = `{
	"id": "user-abc123",
	"created": 1700000000,
	"mfa_flag_enabled": true,
	"orgs": {
		"data": [{
			"description": "Acme",
			"personal": false,
			"is_default": true
		}]
	}
}`

func mockClient(t *testing.T, fn roundTripFunc) *http.Client {
	t.Helper()
	return &http.Client{Transport: fn}
}

func TestOpenAI_ReverifyLiveKey(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", req.Method)
		}
		if req.URL.String() != "https://api.openai.com/v1/me" {
			t.Fatalf("unexpected URL %s", req.URL.String())
		}
		if got := req.Header.Get("Authorization"); got != "Bearer "+sampleOpenAIKey {
			t.Fatalf("unexpected Authorization header %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(liveMeBody)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	got, err := s.Reverify(context.Background(), map[string]string{SecretPartKey: sampleOpenAIKey})
	if err != nil {
		t.Fatalf("Reverify returned error: %v", err)
	}
	if !got.Verified {
		t.Fatal("expected key to verify")
	}
	if got.VerificationError() != nil {
		t.Fatalf("unexpected verification error: %v", got.VerificationError())
	}
	if string(got.Raw) != sampleOpenAIKey {
		t.Fatalf("Raw = %q, want %q", got.Raw, sampleOpenAIKey)
	}
	if got.SecretParts[SecretPartKey] != sampleOpenAIKey {
		t.Fatalf("SecretParts[%q] = %q", SecretPartKey, got.SecretParts[SecretPartKey])
	}
	if got.ExtraData["id"] != "user-abc123" {
		t.Fatalf("extra id = %q", got.ExtraData["id"])
	}
	if got.ExtraData["total_orgs"] != "1" {
		t.Fatalf("extra total_orgs = %q", got.ExtraData["total_orgs"])
	}
	if got.ExtraData["mfa_enabled"] != "true" {
		t.Fatalf("extra mfa_enabled = %q", got.ExtraData["mfa_enabled"])
	}
	if got.ExtraData["description"] != "Acme" {
		t.Fatalf("extra description = %q", got.ExtraData["description"])
	}
	if got.ExtraData["is_personal"] != "false" {
		t.Fatalf("extra is_personal = %q", got.ExtraData["is_personal"])
	}
	if got.ExtraData["is_default"] != "true" {
		t.Fatalf("extra is_default = %q", got.ExtraData["is_default"])
	}
}

func TestOpenAI_ReverifyDoesNotRequireOriginalChunk(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(liveMeBody)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	got, err := s.Reverify(context.Background(), map[string]string{SecretPartKey: sampleOpenAIKey})
	if err != nil {
		t.Fatalf("Reverify returned error: %v", err)
	}
	if !got.Verified {
		t.Fatal("expected reverification from SecretParts alone")
	}

	fromData, err := s.FromData(context.Background(), false, []byte(sampleOpenAIKey))
	if err != nil {
		t.Fatalf("FromData returned error: %v", err)
	}
	if len(fromData) != 1 {
		t.Fatalf("expected FromData to still detect the raw key, got %d results", len(fromData))
	}
}

func TestOpenAI_ReverifyInvalidKey(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"invalid_api_key"}}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	got, err := s.Reverify(context.Background(), map[string]string{SecretPartKey: sampleOpenAIKey})
	if err != nil {
		t.Fatalf("Reverify returned error: %v", err)
	}
	if got.Verified {
		t.Fatal("expected determinate unverified result")
	}
	if got.VerificationError() != nil {
		t.Fatalf("401 should be determinate, got verification error: %v", got.VerificationError())
	}
}

func TestOpenAI_ReverifyUnexpectedStatus(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("upstream error")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	got, err := s.Reverify(context.Background(), map[string]string{SecretPartKey: sampleOpenAIKey})
	if err != nil {
		t.Fatalf("Reverify returned error: %v", err)
	}
	if got.Verified {
		t.Fatal("expected unverified result on unexpected status")
	}
	if got.VerificationError() == nil {
		t.Fatal("expected indeterminate verification error for HTTP 500")
	}
}

func TestOpenAI_ReverifyNetworkError(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}

	got, err := s.Reverify(context.Background(), map[string]string{SecretPartKey: sampleOpenAIKey})
	if err != nil {
		t.Fatalf("Reverify returned error: %v", err)
	}
	if got.Verified {
		t.Fatal("expected unverified result on network error")
	}
	if got.VerificationError() == nil {
		t.Fatal("expected indeterminate verification error for network failure")
	}
	if !strings.Contains(got.VerificationError().Error(), "context deadline exceeded") {
		t.Fatalf("unexpected verification error: %v", got.VerificationError())
	}
}

func TestOpenAI_ReverifyRedactsSecretInVerificationError(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("upstream rejected %s", sampleOpenAIKey)
	})}

	got, err := s.Reverify(context.Background(), map[string]string{SecretPartKey: sampleOpenAIKey})
	if err != nil {
		t.Fatalf("Reverify returned error: %v", err)
	}
	if got.VerificationError() == nil {
		t.Fatal("expected verification error")
	}
	if strings.Contains(got.VerificationError().Error(), sampleOpenAIKey) {
		t.Fatalf("verification error leaked secret: %v", got.VerificationError())
	}
}

func TestOpenAI_ReverifyMissingSecretPart(t *testing.T) {
	s := Scanner{}
	tests := []struct {
		name  string
		parts map[string]string
	}{
		{name: "nil map", parts: nil},
		{name: "empty map", parts: map[string]string{}},
		{name: "empty key", parts: map[string]string{SecretPartKey: ""}},
		{name: "whitespace key", parts: map[string]string{SecretPartKey: "   "}},
		{name: "wrong key name", parts: map[string]string{"token": sampleOpenAIKey}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Reverify(context.Background(), tt.parts)
			if err == nil {
				t.Fatal("expected error for missing secret part")
			}
			if !strings.Contains(err.Error(), SecretPartKey) {
				t.Fatalf("error should mention %q, got %v", SecretPartKey, err)
			}
			if got.Verified || len(got.Raw) != 0 {
				t.Fatalf("expected empty result on caller error, got %#v", got)
			}
		})
	}
}

func TestOpenAI_FromDataVerifyUsesSamePathAsReverify(t *testing.T) {
	s := Scanner{client: mockClient(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(liveMeBody)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	results, err := s.FromData(context.Background(), true, []byte("openai.api-key: "+sampleOpenAIKey))
	if err != nil {
		t.Fatalf("FromData returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Verified {
		t.Fatal("expected FromData verify path to mark the key verified")
	}
	if results[0].ExtraData["id"] != "user-abc123" {
		t.Fatalf("expected shared extra data, got %#v", results[0].ExtraData)
	}
}
