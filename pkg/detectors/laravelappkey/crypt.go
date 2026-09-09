package laravelappkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// laravelPayload is the JSON object Laravel's Encrypter stores inside a
// base64-encoded cookie (Illuminate\Encryption\Encrypter).
type laravelPayload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
	Tag   string `json:"tag"`
}

func parseAppKey(appKey string) ([]byte, error) {
	appKey = strings.TrimSpace(appKey)
	encoded := strings.TrimPrefix(appKey, "base64:")
	if encoded == appKey {
		return nil, errors.New("missing base64: prefix")
	}
	key, err := decodeB64(encoded)
	if err != nil {
		return nil, err
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("APP_KEY must decode to 16 or 32 bytes")
	}
	return key, nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(s)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func isLaravelEncryptedCookie(value string) bool {
	payload, ok := parseLaravelPayload(value)
	return ok && payload.IV != "" && payload.Value != ""
}

func parseLaravelPayload(value string) (laravelPayload, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return laravelPayload{}, false
	}
	if unescaped, err := unescapeCookieValue(value); err == nil {
		value = unescaped
	}
	raw, err := decodeB64(value)
	if err != nil {
		return laravelPayload{}, false
	}
	var payload laravelPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return laravelPayload{}, false
	}
	return payload, payload.IV != "" && payload.Value != ""
}

func unescapeCookieValue(value string) (string, error) {
	// net/http usually already unescapes Cookie.Value; handle leftover % encodings.
	replacer := strings.NewReplacer("%3D", "=", "%3d", "=", "%2B", "+", "%2b", "+", "%2F", "/", "%2f", "/")
	return replacer.Replace(value), nil
}

// decryptLaravelCookie reports whether cookieValue was produced by Laravel's
// Encrypter using appKey.
//
// Matches Illuminate\Encryption\Encrypter (Laravel 11/12):
//   - AES-CBC: HMAC-SHA256(iv_b64 + value_b64, key) then AES-CBC + PKCS#7
//   - AES-GCM: empty MAC; authenticate via the 16-byte GCM tag
//   - APP_KEY "base64:" prefix is stripped and decoded (EncryptionServiceProvider::parseKey)
func decryptLaravelCookie(appKey, cookieValue string) bool {
	key, err := parseAppKey(appKey)
	if err != nil {
		return false
	}
	payload, ok := parseLaravelPayload(cookieValue)
	if !ok {
		return false
	}

	if payload.MAC != "" && !validMAC(key, payload) {
		return false
	}

	iv, err := decodeB64(payload.IV)
	if err != nil {
		return false
	}
	ciphertext, err := decodeB64(payload.Value)
	if err != nil {
		return false
	}

	if payload.Tag != "" {
		tag, err := decodeB64(payload.Tag)
		if err != nil {
			return false
		}
		_, err = decryptGCM(key, iv, ciphertext, tag)
		return err == nil
	}

	_, err = decryptCBC(key, iv, ciphertext)
	return err == nil
}

func validMAC(key []byte, payload laravelPayload) bool {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload.IV + payload.Value))
	expected := hex.EncodeToString(mac.Sum(nil))
	got, err := hex.DecodeString(payload.MAC)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid CBC payload")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New("invalid IV length")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return pkcs7Unpad(plain)
}

func decryptGCM(key, iv, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, iv, append(ciphertext, tag...), nil)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty plaintext")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-pad], nil
}
