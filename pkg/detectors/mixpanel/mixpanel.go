package mixpanel

import (
	"context"
	"fmt"
	"io"
	"net/http"

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

const (
	tokenTypeServiceAccount = "service_account"
	tokenTypeProjectSecret  = "project_secret"

	serviceAccountVerifyURL = "https://mixpanel.com/api/app/me"
	projectSecretVerifyURL  = "https://mixpanel.com/api/2.0/engage"
)

var (
	defaultClient = common.SaneHttpClient()

	// Service account usernames are assigned by Mixpanel as {name}.{org}.mp-service-account.
	// See https://docs.mixpanel.com/reference/service-accounts
	serviceAccountUserPat = regexp.MustCompile(`\b([a-zA-Z0-9_-]+\.[a-zA-Z0-9]+\.mp-service-account)\b`)

	// 32-char service account secrets / project secrets labeled with mixpanel.
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mixpanel", "mp-service-account"}) + `\b([a-zA-Z0-9]{32})\b`)

	// Legacy service-account pairing used a 30-40 char id plus a 32-char secret, both near "mixpanel".
	legacyIDPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mixpanel"}) + `\b([a-zA-Z0-9.-]{30,40})\b`)

	// Project secrets (API secrets) are 32-char credentials. Mixpanel project tokens use the same
	// length but are public identifiers, so require a secret/password label in addition to "mixpanel".
	// See https://docs.mixpanel.com/reference/project-secret
	projectSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mixpanel"}) + `(?i)(?:api[_-]?secret|project[_-]?secret|secret|password)(?:.|[\n\r]){0,20}?\b([a-zA-Z0-9]{32})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mixpanel", "mp-service-account"}
}

// FromData will find and optionally verify Mixpanel secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	usernames := uniqueMatches(serviceAccountUserPat, dataStr)
	secrets := uniqueMatches(secretPat, dataStr)
	legacyIDs := uniqueMatches(legacyIDPat, dataStr)
	projectSecrets := uniqueMatches(projectSecretPat, dataStr)

	// Usernames and 32-char secrets can overlap with the legacy 30-40 char id pattern.
	for username := range usernames {
		delete(secrets, username)
		delete(legacyIDs, username)
		delete(projectSecrets, username)
	}
	for secret := range secrets {
		delete(legacyIDs, secret)
	}

	client := s.getClient()
	usedSecrets := make(map[string]struct{})

	if len(usernames) > 0 {
		for username := range usernames {
			for secret := range secrets {
				result := s.makeServiceAccountResult(ctx, client, verify, username, secret)
				results = append(results, result)
				usedSecrets[secret] = struct{}{}
				if result.Verified {
					break
				}
			}
		}
	} else {
		for id := range legacyIDs {
			for secret := range secrets {
				if id == secret {
					continue
				}
				result := s.makeServiceAccountResult(ctx, client, verify, id, secret)
				results = append(results, result)
				usedSecrets[secret] = struct{}{}
				if result.Verified {
					break
				}
			}
		}
	}

	for secret := range projectSecrets {
		if _, used := usedSecrets[secret]; used {
			continue
		}
		results = append(results, s.makeProjectSecretResult(ctx, client, verify, secret))
	}

	return results, nil
}

func uniqueMatches(pat *regexp.Regexp, data string) map[string]struct{} {
	matches := make(map[string]struct{})
	for _, match := range pat.FindAllStringSubmatch(data, -1) {
		matches[match[1]] = struct{}{}
	}
	return matches
}

func (s Scanner) makeServiceAccountResult(ctx context.Context, client *http.Client, verify bool, username, secret string) detectors.Result {
	result := detectors.Result{
		DetectorType: detector_typepb.DetectorType_Mixpanel,
		Raw:          []byte(secret),
		RawV2:        []byte(username + ":" + secret),
		ExtraData:    map[string]string{"token_type": tokenTypeServiceAccount},
		SecretParts: map[string]string{
			"username": username,
			"secret":   secret,
		},
	}

	if !verify {
		return result
	}

	verified, verificationErr := verifyServiceAccount(ctx, client, username, secret)
	result.Verified = verified
	result.SetVerificationError(verificationErr, secret)
	return result
}

func (s Scanner) makeProjectSecretResult(ctx context.Context, client *http.Client, verify bool, secret string) detectors.Result {
	result := detectors.Result{
		DetectorType: detector_typepb.DetectorType_Mixpanel,
		Raw:          []byte(secret),
		ExtraData:    map[string]string{"token_type": tokenTypeProjectSecret},
		SecretParts:  map[string]string{"key": secret},
	}

	if !verify {
		return result
	}

	verified, verificationErr := verifyProjectSecret(ctx, client, secret)
	result.Verified = verified
	result.SetVerificationError(verificationErr, secret)
	return result
}

func verifyServiceAccount(ctx context.Context, client *http.Client, username, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serviceAccountVerifyURL, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(username, secret)
	return checkMixpanelAuth(client, req)
}

func verifyProjectSecret(ctx context.Context, client *http.Client, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, projectSecretVerifyURL, nil)
	if err != nil {
		return false, err
	}
	// Project secret auth uses the secret as the basic-auth username with an empty password.
	// See https://docs.mixpanel.com/reference/project-secret
	req.SetBasicAuth(secret, "")
	return checkMixpanelAuth(client, req)
}

func checkMixpanelAuth(client *http.Client, req *http.Request) (bool, error) {
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
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Mixpanel
}

func (s Scanner) Description() string {
	return "Mixpanel is an analytics service that tracks user interactions with web and mobile applications. Mixpanel service account credentials and project secrets can be used to query, export, and modify project data."
}
