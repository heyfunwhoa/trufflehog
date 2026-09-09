package mercadopago

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Production: APP_USR-{application_id}-{MMDDYY}-{32hex}-{user_id}
	// Sandbox:    TEST-{application_id}-{MMDDYY}-{32hex}-{user_id}
	// Some live tokens append a region marker: __XX_XX__-{merchant_id}
	// Public keys (APP_USR-{uuid}) are intentionally not matched.
	keyPat = regexp.MustCompile(`\b((?:APP_USR|TEST)-\d{10,16}-\d{6}-[a-f0-9]{32}(?:__[A-Z]{2}_[A-Z]{2}__)?-\d+)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"app_usr-", "mercadopago"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_MercadoPago,
			Raw:          []byte(token),
			Redacted:     redactToken(token),
			SecretParts:  map[string]string{"key": token},
			ExtraData:    map[string]string{"token_type": tokenType(token)},
		}

		if verify {
			isVerified, extraData, verificationErr := verifyMatch(ctx, s.getClient(), token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, token)
			for k, v := range extraData {
				s1.ExtraData[k] = v
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func tokenType(token string) string {
	if strings.HasPrefix(token, "TEST-") {
		return "test_access_token"
	}
	return "access_token"
}

func redactToken(token string) string {
	if len(token) <= 16 {
		return token[:min(len(token), 8)] + "..."
	}
	return token[:12] + "..."
}

type mercadoPagoUser struct {
	ID     json.Number `json:"id"`
	SiteID string      `json:"site_id"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mercadopago.com/users/me", http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		extra := map[string]string{}
		var user mercadoPagoUser
		if err := json.NewDecoder(res.Body).Decode(&user); err == nil {
			if user.ID.String() != "" {
				extra["user_id"] = user.ID.String()
			}
			if user.SiteID != "" {
				extra["site_id"] = user.SiteID
			}
		}
		return true, extra, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MercadoPago
}

func (s Scanner) Description() string {
	return "MercadoPago is a Latin American payment platform. Access tokens can process payments, refunds, and access customer and merchant data."
}
