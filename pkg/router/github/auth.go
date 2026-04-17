package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
)

func Sha256HMAC(key string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(payload)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func SecureEqual(x, y string) bool {
	if subtle.ConstantTimeCompare([]byte(x), []byte(y)) == 1 {
		return true
	}
	return false
}

func IsValidGithubSignature(secret string, message []byte) bool {

	type GithubMessage struct {
		Signature string
		Payload   []byte
	}

	var m GithubMessage

	err := json.Unmarshal(message, &m)
	if err != nil {
		log.Printf("Failed to unmarshal message in IsValidGithubSignature: %v",
			err)
		return false
	}

	expected := m.Signature
	got := fmt.Sprintf("sha256=%v", Sha256HMAC(secret, m.Payload))

	log.Printf("Expected = %v got = %v", expected, got)

	return SecureEqual(got, expected)
}
