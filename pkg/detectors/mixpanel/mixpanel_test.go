package mixpanel

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern   = "M0UXRQ2DBF5rEJ1qlJTgJvwGqUJ7D8TQ"
	invalidKeyPattern = "=0UXRQ2DBF5rEJ-qlJTgJvwGqUJ"
	validIdPattern    = "1bTaEGIzJRnBN77woEGPwMiuLS68HN"
	invalidIdPattern  = "=bTaEGIzJRnBN7.woEGPwMiuLS68HN"
	keyword           = "mixpanel"

	serviceAccountUsername = "posthog-migrate.a2b789.mp-service-account"
	serviceAccountSecret   = "fCPFrpZYdzB9nlZ9kqabZcXuxSLKhjld"
	projectSecret          = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	projectToken           = "fa45c697d1c664abb760166578f91f24"
)

func TestMixpanel_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword mixpanel",
			input: fmt.Sprintf("mixpanel secret %s within mixpanel %s", validKeyPattern, validIdPattern),
			want:  []string{validIdPattern + ":" + validKeyPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' '%s'", keyword, validKeyPattern, validIdPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' url = '%s'", keyword, invalidKeyPattern, invalidIdPattern),
			want:  []string{},
		},
		{
			name: "service account username and secret",
			input: fmt.Sprintf(
				"username = %s\nmixpanel password = %s",
				serviceAccountUsername,
				serviceAccountSecret,
			),
			want: []string{serviceAccountUsername + ":" + serviceAccountSecret},
		},
		{
			name: "short service account username without mixpanel keyword",
			input: fmt.Sprintf(
				"username = %s\npassword = %s",
				"ci.a1.mp-service-account",
				serviceAccountSecret,
			),
			want: []string{"ci.a1.mp-service-account:" + serviceAccountSecret},
		},
		{
			name:  "project secret with MIXPANEL_API_SECRET",
			input: fmt.Sprintf("MIXPANEL_API_SECRET=%s", projectSecret),
			want:  []string{projectSecret},
		},
		{
			name:  "project secret with mixpanel secret label",
			input: fmt.Sprintf("mixpanel secret = %s", projectSecret),
			want:  []string{projectSecret},
		},
		{
			name:  "public project token is not reported",
			input: fmt.Sprintf(`mixpanel.init("%s")`, projectToken),
			want:  []string{},
		},
		{
			name:  "MIXPANEL_TOKEN is not reported",
			input: fmt.Sprintf("MIXPANEL_TOKEN=%s", projectToken),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				}
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
