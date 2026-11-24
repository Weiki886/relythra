package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestDeploymentSignatureAcceptsCurrentSignedBody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"external_deployment_id":"deploy-42"}`)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := SignDeploymentRequest([]byte("deployment-secret"), timestamp, body)
	if err := VerifyDeploymentSignature([]byte("deployment-secret"), timestamp, signature, body, now); err != nil {
		t.Fatalf("verify valid signature: %v", err)
	}
}

func TestDeploymentSignatureRejectsTamperingAndStaleTimestamps(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"external_deployment_id":"deploy-42"}`)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := SignDeploymentRequest([]byte("deployment-secret"), timestamp, body)

	tests := []struct {
		name      string
		secret    []byte
		timestamp string
		signature string
		body      []byte
	}{
		{name: "wrong key", secret: []byte("other-secret"), timestamp: timestamp, signature: signature, body: body},
		{name: "modified body", secret: []byte("deployment-secret"), timestamp: timestamp, signature: signature, body: []byte(`{"external_deployment_id":"deploy-43"}`)},
		{name: "malformed timestamp", secret: []byte("deployment-secret"), timestamp: "tomorrow", signature: signature, body: body},
		{name: "malformed signature", secret: []byte("deployment-secret"), timestamp: timestamp, signature: "sha256=not-hex", body: body},
		{name: "empty key", timestamp: timestamp, signature: signature, body: body},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			if err := VerifyDeploymentSignature(testCase.secret, testCase.timestamp, testCase.signature, testCase.body, now); !errors.Is(err, ErrInvalidDeploymentSignature) {
				t.Fatalf("VerifyDeploymentSignature error = %v, want ErrInvalidDeploymentSignature", err)
			}
		})
	}

	oldTimestamp := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	oldSignature := SignDeploymentRequest([]byte("deployment-secret"), oldTimestamp, body)
	if err := VerifyDeploymentSignature([]byte("deployment-secret"), oldTimestamp, oldSignature, body, now); !errors.Is(err, ErrInvalidDeploymentSignature) {
		t.Fatalf("stale signature error = %v, want ErrInvalidDeploymentSignature", err)
	}
}

func TestDeploymentSignatureRejectsFutureTimestampBeyondSkew(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	body := []byte(`{}`)
	timestamp := strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10)
	signature := SignDeploymentRequest([]byte("deployment-secret"), timestamp, body)
	if err := VerifyDeploymentSignature([]byte("deployment-secret"), timestamp, signature, body, now); !errors.Is(err, ErrInvalidDeploymentSignature) {
		t.Fatalf("future signature error = %v, want ErrInvalidDeploymentSignature", err)
	}
}

func TestGrafanaNativeWebhookSignatureAndReplayKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"alerts":[]}`)
	mac := hmac.New(sha256.New, []byte("grafana-secret"))
	_, _ = fmt.Fprintf(mac, "%s:", timestamp)
	_, _ = mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))
	if err := VerifyGrafanaWebhookSignature([]byte("grafana-secret"), timestamp, signature, body, now); err != nil {
		t.Fatalf("verify Grafana native signature: %v", err)
	}
	nativeKey, err := GrafanaWebhookReplayKey(signature)
	if err != nil {
		t.Fatal(err)
	}
	legacyKey, err := GrafanaWebhookReplayKey("sha256=" + signature)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(nativeKey, legacyKey) {
		t.Fatal("native and prefixed signature replay keys differ")
	}
	if err := VerifyGrafanaWebhookSignature([]byte("grafana-secret"), timestamp, signature, []byte(`{}`), now); !errors.Is(err, ErrInvalidDeploymentSignature) {
		t.Fatalf("tampered body error = %v", err)
	}
	if err := VerifyGrafanaWebhookSignature([]byte("grafana-secret"), strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10), signature, body, now); !errors.Is(err, ErrInvalidDeploymentSignature) {
		t.Fatalf("stale timestamp error = %v", err)
	}
}

func TestGrafanaWebhookSignatureRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"alerts":[]}`)
	key := []byte("grafana-test-key")
	tests := []struct {
		name      string
		key       []byte
		timestamp string
		signature string
	}{
		{name: "missing timestamp", key: key},
		{name: "malformed timestamp", key: key, timestamp: "tomorrow"},
		{name: "expired", key: key, timestamp: strconv.FormatInt(now.Add(-301*time.Second).Unix(), 10)},
		{name: "future", key: key, timestamp: strconv.FormatInt(now.Add(301*time.Second).Unix(), 10)},
		{name: "empty key", timestamp: strconv.FormatInt(now.Unix(), 10)},
		{name: "malformed signature", key: key, timestamp: strconv.FormatInt(now.Unix(), 10), signature: "invalid"},
		{name: "short signature", key: key, timestamp: strconv.FormatInt(now.Unix(), 10), signature: "abcd"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signature := test.signature
			if signature == "" {
				signature = signGrafanaNativeRequest(key, test.timestamp, body)
			}
			if err := VerifyGrafanaWebhookSignature(test.key, test.timestamp, signature, body, now); !errors.Is(err, ErrInvalidDeploymentSignature) {
				t.Fatalf("invalid signature accepted: %v", err)
			}
		})
	}
	for _, delta := range []time.Duration{-5 * time.Minute, 5 * time.Minute} {
		timestamp := strconv.FormatInt(now.Add(delta).Unix(), 10)
		signature := signGrafanaNativeRequest(key, timestamp, body)
		if err := VerifyGrafanaWebhookSignature(key, timestamp, signature, body, now); err != nil {
			t.Fatalf("skew boundary rejected: %v", err)
		}
		if err := VerifyGrafanaWebhookSignature([]byte("wrong-key"), timestamp, signature, body, now); err == nil {
			t.Fatal("wrong key accepted")
		}
	}
}
