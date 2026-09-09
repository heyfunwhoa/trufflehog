package riotgames

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
}

var _ detectors.Detector = (*Scanner)(nil)

const verifyURL = "https://na1.api.riotgames.com/lol/status/v4/platform-data"

var (
	defaultClient = common.SaneHttpClient()

	// Development and production Riot API keys are RGAPI- followed by a UUID.
	keyPat = regexp.MustCompile(`\b(RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"rgapi-"}
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
			DetectorType: detector_typepb.DetectorType_Riotgames,
			Raw:          []byte(token),
			Redacted:     redactToken(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, s.getClient(), token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func redactToken(token string) string {
	if len(token) <= 11 {
		return token
	}
	return token[:11] + "..."
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Riot-Token", token)
	req.Header.Set("Accept", "application/json")

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
	return detector_typepb.DetectorType_Riotgames
}

func (s Scanner) Description() string {
	return "Riot Games API keys authenticate requests to League of Legends, VALORANT, and other Riot game data APIs."
}
