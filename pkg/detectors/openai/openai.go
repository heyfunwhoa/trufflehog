package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	client *http.Client
}

// SecretPartKey is the SecretParts map key this detector stores and that
// Reverify requires.
const SecretPartKey = "key"

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Reverifier = (*Scanner)(nil)

var (
	// The OpenAI API can be slow to respond under load, so use a longer
	// per-attempt timeout than the default 5s and retry transient failures
	// (timeouts, connection errors, 429/5xx) so a single slow response does
	// not record an indeterminate verification result.
	defaultClient = common.RetryableHTTPClient(
		common.WithTimeout(10*time.Second),
		common.WithMaxRetries(2),
	)

	// The magic string T3BlbkFJ is the base64-encoded string: OpenAI
	// Matches: legacy keys (sk-{alnum}T3BlbkFJ...), project keys (sk-proj-...),
	//          service account keys (sk-svcacct-... or sk-service-...)
	// Does NOT match: admin keys (sk-admin-...)
	keyPat = regexp.MustCompile(`\b(sk-(?:(?:proj|svcacct|service)-[A-Za-z0-9_-]+|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"T3BlbkFJ"}
}

// FromData will find and optionally verify OpenAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := resultForToken(token)
		if verify {
			s.verifyResult(ctx, &s1, token)
		}
		results = append(results, s1)
	}

	return
}

// Reverify checks whether a previously discovered OpenAI key is still live
// using the credential stored in SecretParts. It does not re-run detection.
func (s Scanner) Reverify(ctx context.Context, secretParts map[string]string) (detectors.Result, error) {
	token := ""
	if secretParts != nil {
		token = strings.TrimSpace(secretParts[SecretPartKey])
	}
	if token == "" {
		return detectors.Result{}, fmt.Errorf("missing required secret part %q", SecretPartKey)
	}

	s1 := resultForToken(token)
	s.verifyResult(ctx, &s1, token)
	return s1, nil
}

func resultForToken(token string) detectors.Result {
	return detectors.Result{
		DetectorType: detector_typepb.DetectorType_OpenAI,
		Redacted:     redactToken(token),
		Raw:          []byte(token),
		SecretParts:  map[string]string{SecretPartKey: token},
	}
}

func redactToken(token string) string {
	if len(token) < 4 {
		return "sk-..."
	}
	end := min(len(token)-1, 47)
	return token[:3] + "..." + token[end:]
}

func (s Scanner) httpClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) verifyResult(ctx context.Context, result *detectors.Result, token string) {
	verified, extraData, verificationErr := verifyToken(ctx, s.httpClient(), token)
	result.Verified = verified
	result.ExtraData = extraData
	result.SetVerificationError(verificationErr, token)
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/me", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case 200:
		var resData response
		if err = json.NewDecoder(res.Body).Decode(&resData); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"id":          resData.ID,
			"total_orgs":  fmt.Sprintf("%d", len(resData.Orgs.Data)),
			"mfa_enabled": strconv.FormatBool(resData.MfaFlagEnabled),
			"created_at":  time.Unix(int64(resData.Created), 0).Format(time.RFC3339),
		}

		if len(resData.Orgs.Data) > 0 {
			extraData["description"] = resData.Orgs.Data[0].Description
			extraData["is_personal"] = strconv.FormatBool(resData.Orgs.Data[0].Personal)
			extraData["is_default"] = strconv.FormatBool(resData.Orgs.Data[0].IsDefault)
		}
		return true, extraData, nil
	case 401:
		// Invalid
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_OpenAI
}

func (s Scanner) Description() string {
	return "OpenAI provides various AI models and services. The API keys can be used to access and interact with these models and services."
}

type response struct {
	Object                   string `json:"object"`
	ID                       string `json:"id"`
	Email                    any    `json:"email"`
	Name                     any    `json:"name"`
	Picture                  any    `json:"picture"`
	Created                  int    `json:"created"`
	PhoneNumber              any    `json:"phone_number"`
	MfaFlagEnabled           bool   `json:"mfa_flag_enabled"`
	Orgs                     orgs   `json:"orgs"`
	HasProjectsArchive       bool   `json:"has_projects_archive"`
	HasPaygProjectSpendLimit bool   `json:"has_payg_project_spend_limit"`
	Amr                      []any  `json:"amr"`
}
type settings struct {
	ThreadsUIVisibility      string `json:"threads_ui_visibility"`
	UsageDashboardVisibility string `json:"usage_dashboard_visibility"`
}
type projects struct {
	Object string `json:"object"`
	Data   []any  `json:"data"`
}
type data struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Created     int      `json:"created"`
	Title       string   `json:"title"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Personal    bool     `json:"personal"`
	Settings    settings `json:"settings"`
	ParentOrgID any      `json:"parent_org_id"`
	IsDefault   bool     `json:"is_default"`
	Role        string   `json:"role"`
	Projects    projects `json:"projects"`
}
type orgs struct {
	Object string `json:"object"`
	Data   []data `json:"data"`
}
