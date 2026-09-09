package bitwarden

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Organization keys: organization.<uuid>. Personal keys: user.<uuid>.
	clientIdPat = regexp.MustCompile(`\b((?:organization|user)\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)
	// Client secret is an opaque alphanumeric string with no fixed prefix, typically 30 chars.
	// PrefixRegex requires a nearby "secret" keyword (e.g. client_secret, BW_CLIENTSECRET).
	clientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + `\b([a-zA-Z0-9]{30})\b`)

	// Cloud-hosted identity endpoints. Self-hosted instances use
	// https://your.domain.com/identity/connect/token and are not covered yet.
	identityEndpoints = []string{
		"https://identity.bitwarden.com/connect/token",
		"https://identity.bitwarden.eu/connect/token",
	}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitwarden", "bw_client", "organization."}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Bitwarden secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueClientIDs := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientIDs[strings.TrimSpace(match[1])] = struct{}{}
	}

	uniqueSecrets := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[strings.TrimSpace(match[1])] = struct{}{}
	}

	if len(uniqueClientIDs) == 0 || len(uniqueSecrets) == 0 {
		return results, nil
	}

	for clientID := range uniqueClientIDs {
		for clientSecret := range uniqueSecrets {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Bitwarden,
				Redacted:     clientID,
				Raw:          []byte(clientSecret),
				RawV2:        []byte(fmt.Sprintf("%s:%s", clientID, clientSecret)),
				SecretParts: map[string]string{
					"client_id":     clientID,
					"client_secret": clientSecret,
				},
			}

			if verify {
				isVerified, extraData, verificationErr := verifyMatch(ctx, s.getClient(), clientID, clientSecret)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, clientID, clientSecret)
			}

			results = append(results, s1)

			if s1.Verified {
				delete(uniqueSecrets, clientSecret)
				break
			}
		}
	}

	return results, nil
}

func scopeForClientID(clientID string) string {
	if strings.HasPrefix(strings.ToLower(clientID), "organization.") {
		return "api.organization"
	}
	return "api"
}

func verifyMatch(ctx context.Context, client *http.Client, clientID, clientSecret string) (bool, map[string]string, error) {
	scope := scopeForClientID(clientID)
	var lastErr error
	for _, endpoint := range identityEndpoints {
		verified, err := verifyAtEndpoint(ctx, client, endpoint, clientID, clientSecret, scope)
		if verified {
			return true, map[string]string{"endpoint": endpoint}, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return false, nil, lastErr
}

func verifyAtEndpoint(ctx context.Context, client *http.Client, endpoint, clientID, clientSecret, scope string) (bool, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", scope)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		body := string(bodyBytes)
		if strings.Contains(body, "access_token") {
			return true, nil
		}
		return false, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		if strings.Contains(string(bodyBytes), "invalid_client") {
			return false, nil
		}
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Bitwarden
}

func (s Scanner) Description() string {
	return "Bitwarden organization and personal API keys are OAuth2 client credentials used to access the Bitwarden Public API or CLI. These credentials can be used to manage organizations, members, collections, and vault data."
}
