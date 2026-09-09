package wechatappkey

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

func TestWeChatAppKey_TypeName(t *testing.T) {
	if got := detector_typepb.DetectorType_WeChatAppKey.String(); got != "WeChatAppKey" {
		t.Fatalf("DetectorType_WeChatAppKey.String() = %q, want WeChatAppKey", got)
	}
}

func TestWeChatAppKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	appID := "wxd930ea5d5a258f4f"
	secret := "a1b2c3d4e5f678901234567890abcdef"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "env file",
			input: `
WECHAT_APPID=` + appID + `
WECHAT_APPSECRET=` + secret + `
`,
			want: []string{appID + ":" + secret},
		},
		{
			name: "weixin labeled secret",
			input: `
weixin appid ` + appID + `
weixin app_secret ` + secret + `
`,
			want: []string{appID + ":" + secret},
		},
		{
			name: "json",
			input: `{
  "wechat_appid": "` + appID + `",
  "wechat_appsecret": "` + secret + `"
}`,
			want: []string{appID + ":" + secret},
		},
		{
			name: "appid without secret is not reported",
			input: `
wechat appid=` + appID + `
`,
			want: []string{},
		},
		{
			name: "secret without appid is not reported",
			input: `
WECHAT_APPSECRET=` + secret + `
`,
			want: []string{},
		},
		{
			name: "appid too short",
			input: `
wechat appid=wxd930ea5d5a258f
wechat appsecret=` + secret + `
`,
			want: []string{},
		},
		{
			name: "unlabeled 32-hex is not treated as a secret",
			input: `
wechat config uses ` + appID + `
unrelated hash a1b2c3d4e5f678901234567890abcdef
`,
			want: []string{},
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

func TestWeChatAppKey_FromData(t *testing.T) {
	appID := "wxd930ea5d5a258f4f"
	secret := "a1b2c3d4e5f678901234567890abcdef"
	input := []byte("WECHAT_APPID=" + appID + "\nWECHAT_APPSECRET=" + secret)

	tests := []struct {
		name                string
		s                   Scanner
		verify              bool
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "found, verified",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"access_token":"TOKEN","expires_in":7200}`)},
			verify:       true,
			wantVerified: true,
		},
		{
			name:         "found, invalid secret",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"errcode":40001,"errmsg":"invalid credential"}`)},
			verify:       true,
			wantVerified: false,
		},
		{
			name:         "found, invalid appid",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"errcode":40013,"errmsg":"invalid appid"}`)},
			verify:       true,
			wantVerified: false,
		},
		{
			name:         "found, frozen secret treated as live",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"errcode":40243,"errmsg":"appsecret frozen"}`)},
			verify:       true,
			wantVerified: true,
		},
		{
			name:                "found, ip not in whitelist",
			s:                   Scanner{client: common.ConstantResponseHttpClient(200, `{"errcode":40164,"errmsg":"invalid ip"}`)},
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
			name:                "found, unexpected http status",
			s:                   Scanner{client: common.ConstantResponseHttpClient(500, `{}`)},
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
			require.Equal(t, secret, string(got[0].Raw))
			require.Equal(t, appID+":"+secret, string(got[0].RawV2))
			require.Equal(t, tt.wantVerified, got[0].Verified)
			if (got[0].VerificationError() != nil) != tt.wantVerificationErr {
				t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[0].VerificationError())
			}
			require.Equal(t, appID, got[0].SecretParts["app_id"])
			require.Equal(t, secret, got[0].SecretParts["app_secret"])
		})
	}

	t.Run("not found", func(t *testing.T) {
		got, err := Scanner{}.FromData(context.Background(), true, []byte("no secrets here"))
		require.NoError(t, err)
		require.Empty(t, got)
	})
}
