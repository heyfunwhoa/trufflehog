package wechatappkey

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

const verifyURL = "https://api.weixin.qq.com/cgi-bin/token"

var (
	defaultClient = common.SaneHttpClient()

	// Official Account / Mini Program AppIDs are wx followed by 16 hex characters.
	appIDPat = regexp.MustCompile(`\b(wx[0-9a-fA-F]{16})\b`)
	// AppSecret is a 32-character hex string. Require a nearby WeChat-related label
	// because 32-hex values are otherwise extremely common.
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"wechat", "weixin", "wx_secret", "wx_app_secret", "appsecret", "app_secret",
	}) + `\b([0-9a-fA-F]{32})\b`)
	secretAssignPat = regexp.MustCompile(`(?i)(?:wechat|weixin|wx)[._-]?(?:app)?[._-]?secret["']?\s*[=:]\s*["']?([0-9a-fA-F]{32})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"wechat", "weixin", "wx_app", "wx_secret"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueAppIDs := make(map[string]struct{})
	for _, match := range appIDPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAppIDs[match[1]] = struct{}{}
	}

	uniqueSecrets := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		if detectors.KeyIsRandom(match[1]) {
			uniqueSecrets[match[1]] = struct{}{}
		}
	}
	for _, match := range secretAssignPat.FindAllStringSubmatch(dataStr, -1) {
		if detectors.KeyIsRandom(match[1]) {
			uniqueSecrets[match[1]] = struct{}{}
		}
	}

	for appID := range uniqueAppIDs {
		for secret := range uniqueSecrets {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_WeChatAppKey,
				Raw:          []byte(secret),
				RawV2:        []byte(appID + ":" + secret),
				Redacted:     appID,
				SecretParts: map[string]string{
					"app_id":     appID,
					"app_secret": secret,
				},
			}

			if verify {
				isVerified, extraData, verificationErr := verifyMatch(ctx, s.getClient(), appID, secret)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, secret)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

type wechatTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

func verifyMatch(ctx context.Context, client *http.Client, appID, secret string) (bool, map[string]string, error) {
	u, err := url.Parse(verifyURL)
	if err != nil {
		return false, nil, err
	}
	q := u.Query()
	q.Set("grant_type", "client_credential")
	q.Set("appid", appID)
	q.Set("secret", secret)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return false, nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	var body wechatTokenResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return false, nil, fmt.Errorf("failed to decode WeChat token response: %w", err)
	}

	if body.AccessToken != "" && body.ErrCode == 0 {
		return true, nil, nil
	}

	switch body.ErrCode {
	case 40001, 40013, 40125, 41004:
		// Invalid appid, secret, or missing secret — determinate failure.
		return false, nil, nil
	case 40243:
		// AppSecret is frozen. The credential is real but currently unusable.
		return true, map[string]string{"status": "frozen"}, nil
	case 40164:
		// Caller IP is not on the WeChat API whitelist. The secret may still be valid.
		return false, nil, fmt.Errorf("WeChat API IP not in whitelist: %s", body.ErrMsg)
	default:
		return false, nil, fmt.Errorf("unexpected WeChat API error %d: %s", body.ErrCode, body.ErrMsg)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_WeChatAppKey
}

func (s Scanner) Description() string {
	return "WeChat Official Account and Mini Program AppID/AppSecret pairs can mint access tokens used to send messages, access user data, and call other WeChat backend APIs."
}
