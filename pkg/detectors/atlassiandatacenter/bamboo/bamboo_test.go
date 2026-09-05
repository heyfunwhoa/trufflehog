package bamboo

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	testUser     = "zoox-agent-ci"
	testPassword = "wX9mP2qL8nR4vT7bY1cF6hJ3kN5sA0dZ"
	testHost     = "https://bamboo.zooxlabs.com"
)

func TestBamboo_TypeName(t *testing.T) {
	assert.Equal(t, "Bamboo", detector_typepb.DetectorType_Bamboo.String())
}

func TestBambooBaseURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://bamboo.zooxlabs.com/rest/api/latest/agent", "https://bamboo.zooxlabs.com"},
		{"https://bamboo.zooxlabs.com/rest", "https://bamboo.zooxlabs.com"},
		{"https://ci.example.com/bamboo/rest/api/latest/plan", "https://ci.example.com/bamboo"},
		{"http://bamboo.internal:8085", "http://bamboo.internal:8085"},
		{"https://ci.example.com/bamboo/", "https://ci.example.com/bamboo"},
		{"not a url", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, bambooBaseURL(tt.in), tt.in)
	}
}

func TestBamboo_Pattern(t *testing.T) {
	d := Scanner{}
	d.UseFoundEndpoints(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	zooxSnippet := fmt.Sprintf(`
BAMBOO_AGENT_POOL_USERNAME="${BAMBOO_AGENT_POOL_USERNAME:-%s}"
BAMBOO_AGENT_POOL_PASSWORD="${BAMBOO_AGENT_POOL_PASSWORD:-%s}"
BAMBOO_AGENT_POOL_URL="${BAMBOO_AGENT_POOL_URL:-https://bamboo.zooxlabs.com/rest/api/latest/agent}"
`, testUser, testPassword)

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "zoox bash default-value syntax",
			input: zooxSnippet,
			want:  []string{fmt.Sprintf("%s:%s:%s", testUser, testPassword, testHost)},
		},
		{
			name: "plain env vars",
			input: fmt.Sprintf(`
				BAMBOO_USERNAME=%s
				BAMBOO_PASSWORD=%s
				BAMBOO_URL=https://bamboo.internal.corp
			`, testUser, testPassword),
			want: []string{fmt.Sprintf("%s:%s:https://bamboo.internal.corp", testUser, testPassword)},
		},
		{
			name: "context path preserved",
			input: fmt.Sprintf(`
				bamboo_user: %s
				bamboo_password: %s
				bamboo_url: https://ci.example.com/bamboo/rest/api/latest/plan
			`, testUser, testPassword),
			want: []string{fmt.Sprintf("%s:%s:https://ci.example.com/bamboo", testUser, testPassword)},
		},
		{
			name: "username and password without URL",
			input: fmt.Sprintf(`
				bamboo_username = %s
				bamboo_password = %s
			`, testUser, testPassword),
			want: []string{fmt.Sprintf("%s:%s", testUser, testPassword)},
		},
		{
			name: "json object",
			input: fmt.Sprintf(`{
				"BAMBOO_AGENT_POOL_USERNAME": "%s",
				"BAMBOO_AGENT_POOL_PASSWORD": "%s",
				"BAMBOO_AGENT_POOL_URL": "https://bamboo.example.net"
			}`, testUser, testPassword),
			want: []string{fmt.Sprintf("%s:%s:https://bamboo.example.net", testUser, testPassword)},
		},
		{
			name: "not a match - password only",
			input: fmt.Sprintf(`
				BAMBOO_PASSWORD=%s
			`, testPassword),
			want: []string{},
		},
		{
			name: "not a match - placeholder values",
			input: `
				BAMBOO_USERNAME=username
				BAMBOO_PASSWORD=password
				BAMBOO_URL=https://bamboo.example.com
			`,
			want: []string{},
		},
		{
			name: "not a match - no bamboo keyword assignment",
			input: fmt.Sprintf(`
				USERNAME=%s
				PASSWORD=%s
				URL=https://example.com
			`, testUser, testPassword),
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

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

func TestBamboo_FromData(t *testing.T) {
	client := common.SaneHttpClient()
	d := Scanner{client: client}
	d.UseFoundEndpoints(true)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)

	input := fmt.Sprintf(`
BAMBOO_AGENT_POOL_USERNAME="${BAMBOO_AGENT_POOL_USERNAME:-%s}"
BAMBOO_AGENT_POOL_PASSWORD="${BAMBOO_AGENT_POOL_PASSWORD:-%s}"
BAMBOO_AGENT_POOL_URL="${BAMBOO_AGENT_POOL_URL:-https://bamboo.zooxlabs.com/rest/api/latest/agent}"
`, testUser, testPassword)

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(testUser+":"+testPassword))

	tests := []struct {
		name                string
		setup               func()
		data                string
		verify              bool
		wantResults         int
		wantVerified        bool
		wantVerificationErr bool
		wantExtraData       map[string]string
	}{
		{
			name: "found, verified",
			setup: func() {
				gock.New(testHost).
					Get("/rest/api/latest/currentUser").
					MatchParam("os_authType", "basic").
					MatchHeader("Authorization", basic).
					Reply(http.StatusOK).
					JSON(map[string]any{
						"name":     testUser,
						"fullName": "Zoox Agent",
						"email":    "ci@zooxlabs.com",
					})
			},
			data:         input,
			verify:       true,
			wantResults:  1,
			wantVerified: true,
			wantExtraData: map[string]string{
				"endpoint":  testHost,
				"name":      testUser,
				"full_name": "Zoox Agent",
				"email":     "ci@zooxlabs.com",
			},
		},
		{
			name: "found, unverified (401)",
			setup: func() {
				gock.New(testHost).
					Get("/rest/api/latest/currentUser").
					Reply(http.StatusUnauthorized)
			},
			data:         input,
			verify:       true,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name: "found, unverified (403)",
			setup: func() {
				gock.New(testHost).
					Get("/rest/api/latest/currentUser").
					Reply(http.StatusForbidden)
			},
			data:         input,
			verify:       true,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name: "found, 200 without name is not verified",
			setup: func() {
				gock.New(testHost).
					Get("/rest/api/latest/currentUser").
					Reply(http.StatusOK).
					JSON(map[string]any{"ok": true})
			},
			data:         input,
			verify:       true,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name: "found, verification error on unexpected status",
			setup: func() {
				gock.New(testHost).
					Get("/rest/api/latest/currentUser").
					Reply(http.StatusInternalServerError)
			},
			data:                input,
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name: "found, verification error on timeout",
			setup: func() {
				gock.New(testHost).
					Get("/rest/api/latest/currentUser").
					Reply(http.StatusOK).
					Delay(2 * time.Second)
			},
			data:                input,
			verify:              true,
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:         "found, no verify",
			setup:        func() {},
			data:         input,
			verify:       false,
			wantResults:  1,
			wantVerified: false,
		},
		{
			name:        "not found",
			setup:       func() {},
			data:        "bamboo config: nothing here",
			verify:      true,
			wantResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gock.Flush()
			tt.setup()

			ctx := context.Background()
			if tt.wantVerificationErr {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}

			results, err := d.FromData(ctx, tt.verify, []byte(tt.data))
			require.NoError(t, err)
			require.Len(t, results, tt.wantResults)

			for _, result := range results {
				assert.Equal(t, detector_typepb.DetectorType_Bamboo, result.DetectorType)
				assert.NotEmpty(t, result.Raw)
				assert.Equal(t, tt.wantVerified, result.Verified)
				assert.Equal(t, tt.wantVerificationErr, result.VerificationError() != nil)
				if tt.wantExtraData != nil {
					assert.Equal(t, tt.wantExtraData, result.ExtraData)
				}
				assert.Contains(t, result.SecretParts, "username")
				assert.Contains(t, result.SecretParts, "password")
			}
		})
	}
}
