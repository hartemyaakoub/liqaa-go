package liqaa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// WebhookVerifier verifies HMAC-SHA256 signed webhook deliveries from LIQAA.
//
// Header format: X-LIQAA-Signature: t=<unix_ts>,v1=<hex_hmac>
// HMAC is computed over fmt.Sprintf("%d.%s", timestamp, rawBody).
type WebhookVerifier struct {
	secret             []byte
	replayWindowSecs   int64
}

// NewWebhookVerifier constructs a verifier with a 5-minute replay window.
func NewWebhookVerifier(signingSecret string) *WebhookVerifier {
	return &WebhookVerifier{secret: []byte(signingSecret), replayWindowSecs: 300}
}

// WithReplayWindow overrides the default 5-minute replay window.
func (v *WebhookVerifier) WithReplayWindow(seconds int64) *WebhookVerifier {
	v.replayWindowSecs = seconds
	return v
}

// Verify returns true iff the signature is valid AND the timestamp is fresh.
func (v *WebhookVerifier) Verify(rawBody []byte, signatureHeader string) bool {
	timestamp, received, ok := parseSignatureHeader(signatureHeader)
	if !ok {
		return false
	}
	if abs64(time.Now().Unix()-timestamp) > v.replayWindowSecs {
		return false
	}
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	mac.Write(rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(received))
}

func parseSignatureHeader(h string) (timestamp int64, sig string, ok bool) {
	if h == "" {
		return 0, "", false
	}
	parts := map[string]string{}
	for _, segment := range strings.Split(h, ",") {
		segment = strings.TrimSpace(segment)
		k, v, found := strings.Cut(segment, "=")
		if !found {
			continue
		}
		parts[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	t, err := strconv.ParseInt(parts["t"], 10, 64)
	if err != nil {
		return 0, "", false
	}
	v1 := parts["v1"]
	if v1 == "" {
		return 0, "", false
	}
	return t, v1, true
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
