package laravelappkey

import (
	"context"
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
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Laravel `php artisan key:generate` writes APP_KEY=base64:<16 or 32 raw bytes>.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"APP_KEY"}) + `\b(base64:[A-Za-z0-9+/]{22,43}={0,2})`)
	urlPat = regexp.MustCompile(detectors.PrefixRegex([]string{"APP_URL"}) + `(https?://[^\s"'<>]+)`)
)

func (s Scanner) Keywords() []string {
	return []string{"app_key"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_LaravelAppKey
}

func (s Scanner) Description() string {
	return "Laravel APP_KEY is the application encryption key used by Laravel's Encrypter to protect cookies, sessions, and other encrypted values. A valid key can decrypt live session and XSRF cookies from the app."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := strings.TrimSpace(match[1])
		if _, err := parseAppKey(key); err != nil {
			continue
		}
		uniqueKeys[key] = struct{}{}
	}

	uniqueURLs := make(map[string]struct{})
	for _, match := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		if appURL, ok := usableAppURL(strings.TrimRight(match[1], ".,);")); ok {
			uniqueURLs[appURL] = struct{}{}
		}
	}

	for key := range uniqueKeys {
		if len(uniqueURLs) == 0 {
			results = append(results, s.newResult(key, ""))
			continue
		}

		for appURL := range uniqueURLs {
			result := s.newResult(key, appURL)
			if verify {
				verified, extra, verificationErr := verifyAppKey(ctx, s.getClient(), key, appURL)
				result.Verified = verified
				result.SetVerificationError(verificationErr, key)
				if extra != nil {
					result.ExtraData = extra
				}
			}
			results = append(results, result)
			if result.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) newResult(key, appURL string) detectors.Result {
	parts := map[string]string{"key": key}
	var rawV2 []byte
	if appURL != "" {
		parts["url"] = appURL
		rawV2 = []byte(key + ":" + appURL)
	}
	return detectors.Result{
		DetectorType: s.Type(),
		Raw:          []byte(key),
		RawV2:        rawV2,
		Redacted:     redactKey(key),
		SecretParts:  parts,
	}
}

func redactKey(key string) string {
	if len(key) < 16 {
		return "base64:***"
	}
	return key[:10] + "..." + key[len(key)-4:]
}

func usableAppURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimRight(raw, "/")
	if raw == "" || strings.Contains(raw, "$") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return "", false
	}
	if strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return "", false
	}
	return parsed.String(), true
}

func verifyAppKey(ctx context.Context, client *http.Client, appKey, appURL string) (bool, map[string]string, error) {
	cookies, status, err := fetchCookies(ctx, client, appURL)
	if err != nil {
		return false, nil, err
	}

	var laravelCookies []cookieCandidate
	for _, c := range cookies {
		if isLaravelEncryptedCookie(c.Value) {
			laravelCookies = append(laravelCookies, c)
		}
	}

	if len(laravelCookies) == 0 {
		return false, nil, fmt.Errorf("no Laravel encrypted cookies in HTTP %d response from APP_URL", status)
	}

	for _, c := range laravelCookies {
		if decryptLaravelCookie(appKey, c.Value) {
			return true, map[string]string{
				"app_url": appURL,
				"cookie":  c.Name,
			}, nil
		}
	}

	// Cookies were present and MAC/decrypt failed: the key does not match this app.
	return false, map[string]string{"app_url": appURL}, nil
}

type cookieCandidate struct {
	Name  string
	Value string
}

func fetchCookies(ctx context.Context, client *http.Client, appURL string) ([]cookieCandidate, int, error) {
	current := appURL
	var cookies []cookieCandidate
	var lastStatus int

	for hop := 0; hop < 5; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, http.NoBody)
		if err != nil {
			return cookies, lastStatus, err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			return cookies, lastStatus, err
		}
		lastStatus = resp.StatusCode
		for _, c := range resp.Cookies() {
			cookies = append(cookies, cookieCandidate{Name: c.Name, Value: c.Value})
		}
		location := resp.Header.Get("Location")
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 || location == "" {
			break
		}
		next, err := resp.Request.URL.Parse(location)
		if err != nil {
			break
		}
		current = next.String()
	}

	return cookies, lastStatus, nil
}
