package riotgames

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestRiotgames_TypeName(t *testing.T) {
	if got := detector_typepb.DetectorType_Riotgames.String(); got != "Riotgames" {
		t.Fatalf("DetectorType_Riotgames.String() = %q, want Riotgames", got)
	}
}

func TestRiotgames_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	key := "RGAPI-b529a03f-3e13-4a9d-a9e2-10ab9ecc8494"
	key2 := "RGAPI-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "env file",
			input: `RIOT_API_KEY="` + key + `"`,
			want:  []string{key},
		},
		{
			name:  "header",
			input: "X-Riot-Token: " + key,
			want:  []string{key},
		},
		{
			name:  "json",
			input: `{"riotApiKey": "` + key + `"}`,
			want:  []string{key},
		},
		{
			name: "multiple keys",
			input: `
RGAPI-b529a03f-3e13-4a9d-a9e2-10ab9ecc8494
RGAPI-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
`,
			want: []string{key, key2},
		},
		{
			name:  "missing prefix",
			input: "rgapi- documentation example: b529a03f-3e13-4a9d-a9e2-10ab9ecc8494",
			want:  []string{},
		},
		{
			name:  "not a uuid",
			input: "RGAPI-not-a-real-key",
			want:  []string{},
		},
		{
			name:  "non-hex characters",
			input: "RGAPI-b529Ax3f-3Y13-4A9d-a9Y2-10Ab9ecc8494",
			want:  []string{},
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

func TestRiotgames_FromData(t *testing.T) {
	token := "RGAPI-b529a03f-3e13-4a9d-a9e2-10ab9ecc8494"
	input := []byte("RIOT_API_KEY=" + token)

	tests := []struct {
		name                string
		s                   Scanner
		verify              bool
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "found, verified",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"id":"NA1"}`)},
			verify:       true,
			wantVerified: true,
		},
		{
			name:         "found, forbidden",
			s:            Scanner{client: common.ConstantResponseHttpClient(403, `{"status":{"status_code":403}}`)},
			verify:       true,
			wantVerified: false,
		},
		{
			name:         "found, unauthorized",
			s:            Scanner{client: common.ConstantResponseHttpClient(401, `{"status":{"status_code":401}}`)},
			verify:       true,
			wantVerified: false,
		},
		{
			name:                "found, rate limited",
			s:                   Scanner{client: common.ConstantResponseHttpClient(429, `{}`)},
			verify:              true,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "found, timeout",
			s:                   Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			verify:              true,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:         "found, not verified because verify=false",
			s:            Scanner{},
			verify:       false,
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(context.Background(), tt.verify, input)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, token, string(got[0].Raw))
			require.Equal(t, tt.wantVerified, got[0].Verified)
			if (got[0].VerificationError() != nil) != tt.wantVerificationErr {
				t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[0].VerificationError())
			}
			require.Equal(t, token, got[0].SecretParts["key"])
		})
	}

	t.Run("not found", func(t *testing.T) {
		got, err := Scanner{}.FromData(context.Background(), true, []byte("no secrets here"))
		require.NoError(t, err)
		require.Empty(t, got)
	})
}
