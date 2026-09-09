package mercadopago

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

func TestMercadoPago_TypeName(t *testing.T) {
	if got := detector_typepb.DetectorType_MercadoPago.String(); got != "MercadoPago" {
		t.Fatalf("DetectorType_MercadoPago.String() = %q, want MercadoPago", got)
	}
}

func TestMercadoPago_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	prodToken := "APP_USR-558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291"
	regionToken := "APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__AR_BA__-987654321"
	testToken := "TEST-558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "production access token",
			input: "MERCADOPAGO_ACCESS_TOKEN=" + prodToken,
			want:  []string{prodToken},
		},
		{
			name:  "production access token with region suffix",
			input: "Authorization: Bearer " + regionToken,
			want:  []string{regionToken},
		},
		{
			name:  "sandbox TEST token with mercadopago keyword",
			input: "mercadopago:\n  access_token: " + testToken,
			want:  []string{testToken},
		},
		{
			name:  "yaml config",
			input: "mercadopago:\n  access_token: \"" + prodToken + "\"\n",
			want:  []string{prodToken},
		},
		{
			name:  "multiple tokens",
			input: "APP_USR-558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291\nAPP_USR-4934588586838432-030918-25abcdef0123456789abcdef01234567-241983636",
			want: []string{
				"APP_USR-558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291",
				"APP_USR-4934588586838432-030918-25abcdef0123456789abcdef01234567-241983636",
			},
		},
		{
			name:  "public key uuid is not an access token",
			input: "mercadopago public_key=APP_USR-d0a26210-4b4a-4c3d-9e1f-479f0400869e",
			want:  []string{},
		},
		{
			name:  "hash too short",
			input: "APP_USR-558881221565652-080712-7cfa0eb2-803211291",
			want:  []string{},
		},
		{
			name:  "missing trailing id",
			input: "APP_USR-558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e",
			want:  []string{},
		},
		{
			name:  "user id too short",
			input: "APP_USR-12345678-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291",
			want:  []string{},
		},
		{
			name:  "no prefix",
			input: "mercadopago token 558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291",
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

func TestMercadoPago_FromData(t *testing.T) {
	token := "APP_USR-558881221565652-080712-7cfa0eb248a1acbf6e073617a80e7d7e-803211291"
	input := []byte("mercadopago access_token=" + token)

	tests := []struct {
		name                string
		s                   Scanner
		verify              bool
		wantVerified        bool
		wantVerificationErr bool
		wantCount           int
	}{
		{
			name:         "found, verified",
			s:            Scanner{client: common.ConstantResponseHttpClient(200, `{"id":803211291,"site_id":"MLB"}`)},
			verify:       true,
			wantVerified: true,
			wantCount:    1,
		},
		{
			name:         "found, unverified",
			s:            Scanner{client: common.ConstantResponseHttpClient(401, `{"message":"invalid_token"}`)},
			verify:       true,
			wantVerified: false,
			wantCount:    1,
		},
		{
			name:                "found, timeout",
			s:                   Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			verify:              true,
			wantVerified:        false,
			wantVerificationErr: true,
			wantCount:           1,
		},
		{
			name:                "found, unexpected api surface",
			s:                   Scanner{client: common.ConstantResponseHttpClient(500, `{}`)},
			verify:              true,
			wantVerified:        false,
			wantVerificationErr: true,
			wantCount:           1,
		},
		{
			name:         "found, not verified because verify=false",
			s:            Scanner{},
			verify:       false,
			wantVerified: false,
			wantCount:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(context.Background(), tt.verify, input)
			require.NoError(t, err)
			require.Len(t, got, tt.wantCount)
			for _, r := range got {
				require.NotEmpty(t, r.Raw)
				require.Equal(t, tt.wantVerified, r.Verified)
				if (r.VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, r.VerificationError())
				}
				require.Equal(t, "key", firstKey(r.SecretParts))
			}
		})
	}

	t.Run("not found", func(t *testing.T) {
		got, err := Scanner{}.FromData(context.Background(), true, []byte("no secrets here"))
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func firstKey(parts map[string]string) string {
	for k := range parts {
		return k
	}
	return ""
}
