package algoliaadminkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"algolia", "docsearch", "appId"}) + `\b([A-Z0-9]{10})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"algolia", "docsearch", "apiKey"}) + `\b([a-zA-Z0-9]{32})\b`)

	invalidHosts = simple.NewCache[struct{}]()

	errNoHost = errors.New("no such host")
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
	return []string{"algolia", "docsearch"}
}

// FromData will find and optionally verify AlgoliaAdminKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("algoliaadminkey")
	dataStr := string(data)

	// Deduplicate matches.
	idMatches := make(map[string]struct{})
	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		id := match[1]
		if detectors.StringShannonEntropy(id) > 2 {
			idMatches[id] = struct{}{}
		}
	}
	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := match[1]
		if detectors.StringShannonEntropy(key) > 3 {
			keyMatches[key] = struct{}{}
		}
	}

	client := s.getClient()

	// Test matches.
	for key := range keyMatches {
		for id := range idMatches {
			if invalidHosts.Exists(id) {
				logger.V(3).Info("Skipping application id: no such host", "host", id)
				delete(idMatches, id)
				continue
			}

			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_AlgoliaAdminKey,
				Raw:          []byte(key),
				SecretParts: map[string]string{
					"id":  id,
					"key": key,
				},
				RawV2: []byte(id + ":" + key),
			}

			if verify {
				isVerified, extraData, verificationErr := verifyMatch(ctx, client, id, key)
				r.Verified = isVerified
				r.ExtraData = extraData
				if verificationErr != nil {
					if errors.Is(verificationErr, errNoHost) {
						invalidHosts.Set(id, struct{}{})
						continue
					}

					r.SetVerificationError(verificationErr, key)
				}
			}

			results = append(results, r)
			if r.Verified {
				break
			}
		}
	}
	return results, nil
}

// https://www.algolia.com/doc/guides/security/api-keys/#access-control-list-acl
var nonSensitivePermissions = map[string]struct{}{
	"listIndexes": {},
	"search":      {},
	"settings":    {},
}

func verifyMatch(ctx context.Context, client *http.Client, appId, apiKey string) (bool, map[string]string, error) {
	verified, extraData, err := verifySearchAPIKey(ctx, client, appId, apiKey)
	if err != nil {
		return false, nil, err
	}
	if verified || extraData != nil {
		return verified, extraData, nil
	}

	// Search API rejected the key. It may still be a Monitoring API key,
	// which authenticates against status.algolia.com instead.
	return verifyMonitoringAPIKey(ctx, client, appId, apiKey)
}

func verifySearchAPIKey(ctx context.Context, client *http.Client, appId, apiKey string) (bool, map[string]string, error) {
	// https://www.algolia.com/doc/rest-api/search/#tag/Api-Keys/operation/getApiKey
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "https://"+appId+".algolia.net/1/keys/"+apiKey, http.NoBody)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("X-Algolia-Application-Id", appId)
	req.Header.Set("X-Algolia-API-Key", apiKey)

	res, err := client.Do(req)
	if err != nil {
		// lookup xyz.algolia.net: no such host
		if strings.Contains(err.Error(), "no such host") {
			return false, nil, errNoHost
		}

		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var keyRes keyResponse
		if err := json.NewDecoder(res.Body).Decode(&keyRes); err != nil {
			return false, nil, err
		}

		slices.Sort(keyRes.ACL)
		extraData := map[string]string{
			"acl": strings.Join(keyRes.ACL, ","),
		}
		if keyRes.Description != "" && keyRes.Description != "<redacted>" {
			extraData["description"] = keyRes.Description
		}

		// Search-only keys are designed to be public. Record that the key is
		// valid so verification is determinate, but do not mark it verified.
		if !hasSensitivePermissions(keyRes.ACL) {
			return false, extraData, nil
		}

		return true, extraData, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Invalidated Search API key, or a key that belongs to another Algolia API.
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func hasSensitivePermissions(acl []string) bool {
	for _, perm := range acl {
		if _, ok := nonSensitivePermissions[perm]; !ok {
			return true
		}
	}
	return false
}

func verifyMonitoringAPIKey(ctx context.Context, client *http.Client, appId, apiKey string) (bool, map[string]string, error) {
	// Authenticated inventory requires a Monitoring API key. Invalid keys return 403.
	// https://www.algolia.com/doc/rest-api/monitoring/get-servers
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "https://status.algolia.com/1/inventory/servers", http.NoBody)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("X-Algolia-Application-Id", appId)
	req.Header.Set("X-Algolia-API-Key", apiKey)

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
		return true, map[string]string{"type": "monitoring"}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// https://www.algolia.com/doc/rest-api/search/#tag/Api-Keys/operation/getApiKey
type keyResponse struct {
	ACL         []string `json:"acl"`
	Description string   `json:"description"`
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_AlgoliaAdminKey
}

func (s Scanner) Description() string {
	return "Algolia is a search-as-a-service platform. Algolia API keys (admin, custom, and monitoring) authenticate requests to manage indices, query data, and access account APIs."
}
