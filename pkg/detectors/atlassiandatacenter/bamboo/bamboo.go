package bamboo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

var (
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.EndpointCustomizer          = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)
)

func (Scanner) CloudEndpoint() string { return "" }

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	keywords = []string{"bamboo"}

	// Captures the assigned value, including bash `${VAR:-default}` form.
	// CSM-1981 (Zoox) used that syntax; generic secret matchers treat the
	// whole `${VAR:-secret}` wrapper as the value and never see the default.
	assignmentValue = `(?:["']?(?:\$\{[^}]*:-)?)?([^"'\s}$]+)`

	// Optional quotes between the key and `=`/':' cover JSON (`"BAMBOO_USERNAME": "alice"`).
	keySep = `["']?\s*[=:]\s*`

	// BAMBOO_AGENT_POOL_USERNAME=... / bamboo.user: ... / bamboo_uid=...
	usernamePat = regexp.MustCompile(`(?i)\bbamboo(?:[._-][a-z0-9]+)*[._-](?:user(?:name)?|uid)` + keySep + assignmentValue)
	passwordPat = regexp.MustCompile(`(?i)\bbamboo(?:[._-][a-z0-9]+)*[._-](?:password|passwd|pass|pwd|secret)` + keySep + assignmentValue)
	envURLPat   = regexp.MustCompile(`(?i)\bbamboo(?:[._-][a-z0-9]+)*[._-](?:url|uri|host|endpoint|server)` + keySep + `(?:["']?(?:\$\{[^}]*:-)?)?(https?://[^\s"'}$]+)`)

	// Keyword-prefixed assignments where "bamboo" is nearby but the key is generic.
	nearbyUserPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bamboo"}) + `(?i)(?:user(?:name)?|uid)` + keySep + assignmentValue)
	nearbyPassPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bamboo"}) + `(?i)(?:password|passwd|pwd|secret)` + keySep + assignmentValue)

	// Capture an optional single path segment so context-path installs
	// (`https://host/bamboo/rest/...`) keep `/bamboo` after normalization.
	keywordURLPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bamboo"}) + `(https?://[a-zA-Z0-9][a-zA-Z0-9.\-]*(?::\d{1,5})?(?:/[a-zA-Z0-9._\-]+)?)`)
	hostURLPat    = regexp.MustCompile(`(?i)(https?://[a-zA-Z0-9][a-zA-Z0-9.\-]*bamboo[a-zA-Z0-9.\-]*(?::\d{1,5})?(?:/[a-zA-Z0-9._\-]+)?)`)

	placeholderValues = map[string]struct{}{
		"username": {}, "user": {}, "password": {}, "passwd": {}, "pass": {},
		"secret": {}, "null": {}, "undefined": {}, "none": {}, "example": {},
		"changeme": {}, "placeholder": {}, "todo": {}, "xxx": {},
	}
)

func (s Scanner) Keywords() []string {
	return keywords
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Bamboo
}

func (s Scanner) Description() string {
	return "Atlassian Bamboo is a self-hosted CI/CD server. Username and password pairs authenticate to the Bamboo REST API (including remote-agent pool credentials such as BAMBOO_AGENT_POOL_*)."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	usernames := collectAssignments(usernamePat, dataStr)
	collectInto(usernames, nearbyUserPat, dataStr)
	passwords := collectAssignments(passwordPat, dataStr)
	collectInto(passwords, nearbyPassPat, dataStr)

	filterPlaceholders(usernames)
	filterPlaceholders(passwords)
	for p := range passwords {
		if len(p) < 8 {
			delete(passwords, p)
		}
	}

	if len(usernames) == 0 || len(passwords) == 0 {
		return nil, nil
	}

	endpoints := s.urls(dataStr)

	for username := range usernames {
		for password := range passwords {
			if username == password {
				continue
			}
			if len(endpoints) == 0 {
				results = append(results, detectors.Result{
					DetectorType: detector_typepb.DetectorType_Bamboo,
					Raw:          []byte(password),
					RawV2:        []byte(username + ":" + password),
					Redacted:     username,
					SecretParts: map[string]string{
						"username": username,
						"password": password,
					},
					ExtraData: map[string]string{
						"message": "No Bamboo URL was found or configured. To verify this credential, set the Bamboo instance base URL as a custom endpoint.",
					},
				})
				continue
			}

			for _, endpoint := range endpoints {
				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_Bamboo,
					Raw:          []byte(password),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", username, password, endpoint)),
					Redacted:     username + ":" + endpoint,
					SecretParts: map[string]string{
						"username": username,
						"password": password,
						"url":      endpoint,
					},
				}

				if verify {
					isVerified, extraData, verificationErr := verifyMatch(ctx, s.getClient(), endpoint, username, password)
					s1.Verified = isVerified
					s1.ExtraData = extraData
					s1.SetVerificationError(verificationErr, password)
					if s1.Verified {
						results = append(results, s1)
						break
					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) urls(data string) []string {
	raw := make(map[string]struct{})
	for _, pat := range []*regexp.Regexp{envURLPat, keywordURLPat, hostURLPat} {
		for _, m := range pat.FindAllStringSubmatch(data, -1) {
			if len(m) > 1 && m[1] != "" {
				raw[m[1]] = struct{}{}
			}
		}
	}

	found := make([]string, 0, len(raw))
	for u := range raw {
		found = append(found, u)
	}

	normalized := make(map[string]struct{})
	for _, u := range s.Endpoints(found...) {
		if base := bambooBaseURL(u); base != "" {
			normalized[base] = struct{}{}
		}
	}

	out := make([]string, 0, len(normalized))
	for u := range normalized {
		out = append(out, u)
	}
	return out
}

func collectAssignments(pat *regexp.Regexp, data string) map[string]struct{} {
	out := make(map[string]struct{})
	collectInto(out, pat, data)
	return out
}

func collectInto(dst map[string]struct{}, pat *regexp.Regexp, data string) {
	for _, m := range pat.FindAllStringSubmatch(data, -1) {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(m[1])
		v = strings.Trim(v, `"'`)
		if v == "" {
			continue
		}
		dst[v] = struct{}{}
	}
}

func filterPlaceholders(values map[string]struct{}) {
	for v := range values {
		if _, ok := placeholderValues[strings.ToLower(v)]; ok {
			delete(values, v)
			continue
		}
		if strings.Contains(v, "://") {
			delete(values, v)
		}
	}
}

// bambooBaseURL reduces a found URL to the Bamboo instance origin, keeping a
// context path such as /bamboo when the REST API is not mounted at the root.
func bambooBaseURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	path := u.Path
	lower := strings.ToLower(path)
	if i := strings.Index(lower, "/rest/"); i >= 0 {
		path = path[:i]
	} else if i := strings.Index(lower, "/rest"); i >= 0 && (i+len("/rest") == len(path)) {
		path = path[:i]
	}
	u.Path = strings.TrimRight(path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

// verifyMatch checks username/password against GET /rest/api/latest/currentUser.
// Docs: https://developer.atlassian.com/server/bamboo/using-the-bamboo-rest-apis/
func verifyMatch(ctx context.Context, client *http.Client, baseURL, username, password string) (bool, map[string]string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/rest/api/latest/currentUser?os_authType=basic"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			// 200 with a non-JSON body is not a Bamboo currentUser response.
			return false, nil, nil
		}
		name, _ := body["name"].(string)
		if name == "" {
			return false, nil, nil
		}
		extra := map[string]string{"endpoint": baseURL, "name": name}
		if fullName, ok := body["fullName"].(string); ok && fullName != "" {
			extra["full_name"] = fullName
		}
		if email, ok := body["email"].(string); ok && email != "" {
			extra["email"] = email
		}
		return true, extra, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil
	case http.StatusTooManyRequests:
		return false, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	default:
		if resp.StatusCode >= 500 {
			return false, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		// Anything else (404, 302 login page, ...) is not a Bamboo auth response.
		return false, nil, nil
	}
}
