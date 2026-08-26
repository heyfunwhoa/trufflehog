package algoliaadminkey

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	testAppID = "844XQV5SUA"
	testKey   = "BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn"
)

func testInput(appID, key string) string {
	return "[DEBUG] Using algolia Key=" + key + "\n[DEBUG] Using docsearch ID=" + appID
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func routedClient(searchStatus int, searchBody string, monitoringStatus int, monitoringBody string) *http.Client {
	return &http.Client{
		Transport: common.FakeTransport{
			CreateResponse: func(req *http.Request) (*http.Response, error) {
				switch {
				case strings.Contains(req.URL.Host, "algolia.net"):
					return jsonResponse(searchStatus, searchBody), nil
				case req.URL.Host == "status.algolia.com":
					return jsonResponse(monitoringStatus, monitoringBody), nil
				default:
					return jsonResponse(http.StatusNotFound, `{"message":"unexpected host"}`), nil
				}
			},
		},
	}
}

func TestAlgoliaAdminKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using algolia Key=BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn
				[DEBUG] Using docsearch ID=844XQV5SUA
				[INFO] Response received: 200 OK
			`,
			want: []string{"844XQV5SUA:BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appId 0VJ9I1WV78}</id>
  					<secret>{algolia AQAAABAAA 4AYm3wz7nfnX7Bqtw5e5Qo3Z5vfBe0eS}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"0VJ9I1WV78:4AYm3wz7nfnX7Bqtw5e5Qo3Z5vfBe0eS"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[INFO] Sending request to the algolia API
				[DEBUG] Using Key=BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn
				[DEBUG] Using ID=844XQV5SUA
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using algolia Key=BsD-N7ZU7kFiUX5CpN8CUf3nkMaSeZYn
				[DEBUG] Using docsearch ID=844XqV5SUA
				[ERROR] Response received: 401 UnAuthorized
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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

func TestAlgoliaAdminKey_Verify(t *testing.T) {
	input := testInput(testAppID, testKey)

	tests := []struct {
		name         string
		client       *http.Client
		wantVerified bool
		wantExtra    map[string]string
		wantErr      bool
	}{
		{
			name: "admin or custom key with sensitive ACL",
			client: routedClient(
				http.StatusOK, `{"acl":["search","addObject","deleteIndex"],"description":"prod admin"}`,
				http.StatusForbidden, `{}`,
			),
			wantVerified: true,
			wantExtra: map[string]string{
				"acl":         "addObject,deleteIndex,search",
				"description": "prod admin",
			},
		},
		{
			name: "valid search-only key is validity-checked but not marked verified",
			client: routedClient(
				http.StatusOK, `{"acl":["search","listIndexes","settings"]}`,
				http.StatusForbidden, `{}`,
			),
			wantVerified: false,
			wantExtra: map[string]string{
				"acl": "listIndexes,search,settings",
			},
		},
		{
			name: "monitoring key rejected by search API then validated",
			client: routedClient(
				http.StatusForbidden, `{"message":"Invalid Application-ID or API key","status":403}`,
				http.StatusOK, `{"inventory":[]}`,
			),
			wantVerified: true,
			wantExtra:    map[string]string{"type": "monitoring"},
		},
		{
			name: "invalid key on both APIs",
			client: routedClient(
				http.StatusForbidden, `{"message":"Invalid Application-ID or API key","status":403}`,
				http.StatusForbidden, `{"message":"Invalid Application-ID or API key"}`,
			),
			wantVerified: false,
		},
		{
			name:         "unexpected search API status is indeterminate",
			client:       common.ConstantResponseHttpClient(http.StatusInternalServerError, `{}`),
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := Scanner{client: test.client}
			results, err := d.FromData(context.Background(), true, []byte(input))
			require.NoError(t, err)
			require.Len(t, results, 1)

			got := results[0]
			if got.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", got.Verified, test.wantVerified)
			}
			if diff := cmp.Diff(test.wantExtra, got.ExtraData); diff != "" {
				t.Errorf("ExtraData diff (-want +got):\n%s", diff)
			}
			if (got.VerificationError() != nil) != test.wantErr {
				t.Errorf("VerificationError = %v, wantErr %v", got.VerificationError(), test.wantErr)
			}
		})
	}
}
