package laravelappkey

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validAppKey   = "base64:" + base64.StdEncoding.EncodeToString(bytes32('v'))
	invalidAppKey = "base64:" + base64.StdEncoding.EncodeToString(bytes32('x'))
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestLaravelAppKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid .env assignment",
			input: `
APP_NAME=Laravel
APP_ENV=production
APP_KEY=` + validAppKey + `
APP_DEBUG=false
APP_URL=https://app.example.com
`,
			want: []string{validAppKey + ":https://app.example.com"},
		},
		{
			name:  "quoted .env values",
			input: `APP_KEY="` + validAppKey + `"` + "\n" + `APP_URL="https://quoted.example.com/"`,
			want:  []string{validAppKey + ":https://quoted.example.com"},
		},
		{
			name:  "key without APP_URL still reported",
			input: "export APP_KEY=" + validAppKey,
			want:  []string{validAppKey},
		},
		{
			name: "php env default",
			input: `
				'key' => env('APP_KEY', '` + validAppKey + `'),
				'url' => env('APP_URL', 'https://php.example.com'),
			`,
			want: []string{validAppKey + ":https://php.example.com"},
		},
		{
			name:  "localhost APP_URL is ignored for pairing",
			input: "APP_KEY=" + validAppKey + "\nAPP_URL=http://localhost:8000",
			want:  []string{validAppKey},
		},
		{
			name:  "invalid - missing base64 prefix",
			input: "APP_KEY=SomeRandomStringThatIsThirtyTwoCh",
			want:  []string{},
		},
		{
			name:  "invalid - truncated key",
			input: "APP_KEY=base64:short==",
			want:  []string{},
		},
		{
			name:  "invalid - no APP_KEY keyword",
			input: validAppKey,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.want) > 0 {
				matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
				if len(matchedDetectors) == 0 {
					t.Errorf("keywords %v not matched by input", d.Keywords())
					return
				}
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
				if r.SecretParts["key"] == "" {
					t.Errorf("missing SecretParts key")
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

func cookieClient(cookieName, cookieValue string, status int) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			header := make(http.Header)
			if cookieName != "" {
				header.Add("Set-Cookie", (&http.Cookie{Name: cookieName, Value: cookieValue, Path: "/"}).String())
			}
			return &http.Response{
				StatusCode: status,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}
}

func TestLaravelAppKey_VerifyMatchSuccess(t *testing.T) {
	cookie, err := encryptLaravelCBC(validAppKey, []byte("csrf-token"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	scanner := Scanner{client: cookieClient("XSRF-TOKEN", cookie, http.StatusOK)}
	input := "APP_KEY=" + validAppKey + "\nAPP_URL=https://app.example.com"
	results, err := scanner.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Verified {
		t.Fatalf("expected verified APP_KEY, verification error=%v", results[0].VerificationError())
	}
	if results[0].ExtraData["cookie"] != "XSRF-TOKEN" {
		t.Fatalf("expected cookie=XSRF-TOKEN, got %q", results[0].ExtraData["cookie"])
	}
	if results[0].SecretParts["key"] != validAppKey {
		t.Fatalf("expected SecretParts key to be preserved")
	}
}

func TestLaravelAppKey_VerifyMatchWrongKey(t *testing.T) {
	cookie, err := encryptLaravelCBC(validAppKey, []byte("csrf-token"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	scanner := Scanner{client: cookieClient("laravel_session", cookie, http.StatusOK)}
	input := "APP_KEY=" + invalidAppKey + "\nAPP_URL=https://app.example.com"
	results, err := scanner.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Fatal("wrong APP_KEY should not verify")
	}
	if results[0].VerificationError() != nil {
		t.Fatalf("MAC failure should be determinate, got %v", results[0].VerificationError())
	}
}

func TestLaravelAppKey_VerifyMatchNoCookies(t *testing.T) {
	scanner := Scanner{client: common.ConstantResponseHttpClient(http.StatusOK, "no cookies")}
	input := "APP_KEY=" + validAppKey + "\nAPP_URL=https://app.example.com"
	results, err := scanner.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Fatal("response without Laravel cookies should not verify")
	}
	if results[0].VerificationError() == nil {
		t.Fatal("missing cookies should be an indeterminate verification error")
	}
}

func TestLaravelAppKey_VerifyMatchTimeout(t *testing.T) {
	scanner := Scanner{
		client: &http.Client{
			Timeout: time.Nanosecond,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, context.DeadlineExceeded
			}),
		},
	}
	input := "APP_KEY=" + validAppKey + "\nAPP_URL=https://app.example.com"
	results, err := scanner.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Fatal("timeout should not verify")
	}
	if results[0].VerificationError() == nil {
		t.Fatal("timeout should set a verification error")
	}
}

func TestLaravelAppKey_VerifyMatchUnexpectedStatusWithoutCookies(t *testing.T) {
	scanner := Scanner{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("error")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}
	input := "APP_KEY=" + validAppKey + "\nAPP_URL=https://app.example.com"
	results, err := scanner.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Fatal("500 without cookies should not verify")
	}
	if results[0].VerificationError() == nil {
		t.Fatal("500 without cookies should be indeterminate")
	}
}
