package laravelappkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestParseAppKey(t *testing.T) {
	raw := bytes32('k')
	encoded := "base64:" + base64.StdEncoding.EncodeToString(raw)

	got, err := parseAppKey(encoded)
	if err != nil {
		t.Fatalf("parseAppKey: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("decoded key mismatch")
	}

	if _, err := parseAppKey("not-a-key"); err == nil {
		t.Fatal("expected error for key without base64: prefix")
	}
	if _, err := parseAppKey("base64:short"); err == nil {
		t.Fatal("expected error for undersized key")
	}
}

func TestDecryptLaravelCookieCBC(t *testing.T) {
	appKey := "base64:" + base64.StdEncoding.EncodeToString(bytes32('a'))
	cookie, err := encryptLaravelCBC(appKey, []byte("s:40:\"csrf-token-value-for-tests-abcdef\";"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !decryptLaravelCookie(appKey, cookie) {
		t.Fatal("expected CBC cookie to decrypt with matching APP_KEY")
	}

	otherKey := "base64:" + base64.StdEncoding.EncodeToString(bytes32('b'))
	if decryptLaravelCookie(otherKey, cookie) {
		t.Fatal("expected CBC cookie to fail with the wrong APP_KEY")
	}
}

func TestDecryptPHPLaravelEncrypterPayloads(t *testing.T) {
	// Fixtures produced by PHP 8.3 openssl_* using the same steps as
	// Illuminate\Encryption\Encrypter::encrypt / decrypt (AES-256-CBC default,
	// AES-256-GCM AEAD, AES-128-CBC). Key material is 32 (or 16) 0x61/0x63 bytes.
	const appKey256 = "base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	const appKey128 = "base64:Y2NjY2NjY2NjY2NjY2NjYw=="

	tests := []struct {
		name   string
		appKey string
		cookie string
	}{
		{
			name:   "php aes-256-cbc",
			appKey: appKey256,
			cookie: "eyJpdiI6ImVJKzFuN1FYK2JPd0Y4d3dxZzFtT3c9PSIsInZhbHVlIjoiYWtxU21lVklSTHN1MmdQd2h3c0U4LzZ5QkF0ZW1wVGF5cEhUN0xUOUNOWT0iLCJtYWMiOiJhNDgyZGExNzQ5Y2I4ODdmNzc3NWQ1M2JiN2YxYjdiZDY2ZGFhNjQyNzRjZDM5OGY1ZGY4ZWI1YTRjY2Q4NzFmIiwidGFnIjoiIn0=",
		},
		{
			name:   "php aes-256-gcm empty mac",
			appKey: appKey256,
			cookie: "eyJpdiI6IjcxK2d1bjVveXNCK2s0M1UiLCJ2YWx1ZSI6IjhYRnFwUkZmL1RrZ0ZNbkM1WnNSU2htM3NNblJBRzFlTkQxa3Z3PT0iLCJtYWMiOiIiLCJ0YWciOiJQNDgwM0lpNVFZRnZ2RnhlNmQxLzVnPT0ifQ==",
		},
		{
			name:   "php aes-128-cbc",
			appKey: appKey128,
			cookie: "eyJpdiI6IjdjNEZITVd0THg4NGI2aU5ldkRXaEE9PSIsInZhbHVlIjoiSkZQS2NxSEFaRVNlS0J3VmpLc0tudz09IiwibWFjIjoiMjIwMmI3OTIyMDRkMjIzM2I5ZjQyM2YzNDJhYTUwZWM2YmJkN2JmY2VkYWUyZjEzYWRiMzY3YzdjNjc4MWRhYiIsInRhZyI6IiJ9",
		},
		{
			name:   "openssl-cli aes-256-cbc deterministic iv",
			appKey: appKey256,
			cookie: "eyJpdiI6IlltSmlZbUppWW1KaVltSmlZbUppWWc9PSIsInZhbHVlIjoiL0N3Tzl2MGNaV0h1MGNFSDlVV0V1OWF6WExPcHRBdkdHTFVMRWNlY1dvQT0iLCJtYWMiOiI0NjI3ZDkxY2I5YTBjZWZlOTAyNDExNjllM2M1NDA4M2EyNTcyYjE3Zjg4MDBmNWU2NjA5MTRjYWM0MjZmMjQzIiwidGFnIjoiIn0=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !decryptLaravelCookie(tt.appKey, tt.cookie) {
				t.Fatalf("expected PHP/OpenSSL Laravel payload to verify")
			}
			wrong := "base64:" + base64.StdEncoding.EncodeToString(bytes32('z'))
			if decryptLaravelCookie(wrong, tt.cookie) {
				t.Fatal("expected wrong APP_KEY to fail")
			}
		})
	}
}

func TestDecryptLaravelCookieGCM(t *testing.T) {
	appKey := "base64:" + base64.StdEncoding.EncodeToString(bytes32('g'))
	cookie, err := encryptLaravelGCM(appKey, []byte("xsrf-token"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !decryptLaravelCookie(appKey, cookie) {
		t.Fatal("expected GCM cookie to decrypt with matching APP_KEY")
	}

	otherKey := "base64:" + base64.StdEncoding.EncodeToString(bytes32('h'))
	if decryptLaravelCookie(otherKey, cookie) {
		t.Fatal("expected GCM cookie to fail with the wrong APP_KEY")
	}
}

func TestIsLaravelEncryptedCookie(t *testing.T) {
	appKey := "base64:" + base64.StdEncoding.EncodeToString(bytes32('c'))
	cookie, err := encryptLaravelCBC(appKey, []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !isLaravelEncryptedCookie(cookie) {
		t.Fatal("expected encrypted payload to be detected")
	}
	if isLaravelEncryptedCookie("not-a-cookie") {
		t.Fatal("expected junk value to be rejected")
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func encryptLaravelCBC(appKey string, plaintext []byte) (string, error) {
	key, err := parseAppKey(appKey)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivB64 := base64.StdEncoding.EncodeToString(iv)
	valueB64 := base64.StdEncoding.EncodeToString(ciphertext)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(ivB64 + valueB64))

	payload, err := json.Marshal(laravelPayload{
		IV:    ivB64,
		Value: valueB64,
		MAC:   hex.EncodeToString(mac.Sum(nil)),
		Tag:   "",
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func encryptLaravelGCM(appKey string, plaintext []byte) (string, error) {
	key, err := parseAppKey(appKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := aesgcm.Seal(nil, iv, plaintext, nil)
	tagStart := len(sealed) - aesgcm.Overhead()
	ciphertext, tag := sealed[:tagStart], sealed[tagStart:]

	ivB64 := base64.StdEncoding.EncodeToString(iv)
	valueB64 := base64.StdEncoding.EncodeToString(ciphertext)
	tagB64 := base64.StdEncoding.EncodeToString(tag)

	payload, err := json.Marshal(laravelPayload{
		IV:    ivB64,
		Value: valueB64,
		// Laravel AEAD ciphers leave mac empty and rely on the GCM tag.
		MAC: "",
		Tag: tagB64,
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}
