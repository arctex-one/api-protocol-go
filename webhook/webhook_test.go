package webhook

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestHMACWireVector(t *testing.T) {
	body := []byte(`{"amount":"100.00"}`)
	key := []byte("synthetic-key")
	stamp := "2026-01-01T00:00:00Z"
	want := "6be9ae6e9e6ab1172aa9bdb8c5bca9cd5ab732df78596e0b7aaacc0861396d6f"
	if got := HMACSignature(body, key, stamp); got != want {
		t.Fatalf("signature differs from the independent vector: %s", got)
	}
	headers := make(http.Header)
	headers.Set("X-Callback-Algorithm", AlgorithmHMAC)
	headers.Set("X-Callback-Timestamp", stamp)
	headers.Set("X-Callback-Signature", want)
	now, _ := time.Parse(time.RFC3339, stamp)
	if err := VerifyHMAC(body, headers, key, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	altered := []byte(`{ "amount": "100.00" }`)
	if !errors.Is(VerifyHMAC(altered, headers, key, now, time.Minute), ErrInvalidCallback) {
		t.Fatal("verification accepted re-encoded raw bytes")
	}
	headers.Add("X-Callback-Signature", want)
	if !errors.Is(VerifyHMAC(body, headers, key, now, time.Minute), ErrInvalidCallback) {
		t.Fatal("verification accepted duplicate headers")
	}
}

func TestEd25519PreservesWireBytesAndKeyIdentity(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	kid := CallbackKeyID(publicKey)
	stamp := "2026-01-01T00:00:00Z"
	now, _ := time.Parse(time.RFC3339, stamp)
	body := []byte("{\n  \"event_id\": \"example\"\n}")
	protected, input, err := Ed25519SigningInput(body, kid, stamp)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := `{"alg":"EdDSA","kid":"` + kid + `","b64":false,"crit":["b64"],"ts":"2026-01-01T00:00:00Z"}`
	wantProtected := base64.RawURLEncoding.EncodeToString([]byte(wantHeader))
	if protected != wantProtected || !bytes.Equal(input, append([]byte(wantProtected+"."), body...)) {
		t.Fatal("producer signing bytes changed")
	}

	headers := make(http.Header)
	headers.Set("X-Callback-Algorithm", AlgorithmEd25519)
	headers.Set("X-Callback-Timestamp", stamp)
	headers.Set("X-Callback-Key-Id", kid)
	headers.Set("X-Callback-JWS", DetachedEd25519(protected, ed25519.Sign(privateKey, input)))
	delivery, err := ParseEd25519(headers, now)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.KeyID() != kid {
		t.Fatal("key ID changed")
	}
	if err := delivery.Verify(body, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Verify(body, nil); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal("verification accepted a missing key")
	}
	if _, err := ParseEd25519(headers, now.Add(Ed25519VerificationWindow+time.Nanosecond)); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal("verification accepted an expired signature")
	}
	headers.Set("X-Callback-Key-Id", CallbackKeyID(make(ed25519.PublicKey, ed25519.PublicKeySize)))
	if _, err := ParseEd25519(headers, now); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal("verification accepted a mismatched key ID")
	}
}
