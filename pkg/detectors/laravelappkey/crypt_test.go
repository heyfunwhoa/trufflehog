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
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(ivB64 + valueB64))

	payload, err := json.Marshal(laravelPayload{
		IV:    ivB64,
		Value: valueB64,
		MAC:   hex.EncodeToString(mac.Sum(nil)),
		Tag:   tagB64,
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
