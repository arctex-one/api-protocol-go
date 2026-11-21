package webhook

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	// AlgorithmEd25519 is the callback header value for detached Ed25519.
	AlgorithmEd25519 = "jws+eddsa-ed25519"

	// Ed25519VerificationWindow is the maximum age of an Ed25519 delivery.
	Ed25519VerificationWindow = 5 * time.Minute
)

type protectedHeader struct {
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid,omitempty"`
	B64       bool     `json:"b64"`
	Critical  []string `json:"crit"`
	Timestamp string   `json:"ts"`
}

// Ed25519SigningInput builds the protected header and bytes sent to the signer.
func Ed25519SigningInput(body []byte, keyID, timestamp string) (protected string, input []byte, err error) {
	header, err := json.Marshal(protectedHeader{
		Algorithm: "EdDSA",
		KeyID:     keyID,
		Critical:  []string{"b64"},
		Timestamp: timestamp,
	})
	if err != nil {
		return "", nil, err
	}
	protected = base64.RawURLEncoding.EncodeToString(header)
	return protected, signingInput(protected, body), nil
}

// DetachedEd25519 encodes the protected header and raw signature for transport.
func DetachedEd25519(protected string, signature []byte) string {
	return protected + ".." + base64.RawURLEncoding.EncodeToString(signature)
}

func signingInput(protected string, body []byte) []byte {
	return append([]byte(protected+"."), body...)
}

// Ed25519Delivery contains parsed callback headers before trusted key lookup.
type Ed25519Delivery struct {
	keyID     string
	protected string
	signature []byte
}

// KeyID identifies the trusted public key required to verify this delivery.
func (delivery Ed25519Delivery) KeyID() string {
	return delivery.keyID
}

// Verify checks the raw callback body against the resolved public key.
func (delivery Ed25519Delivery) Verify(body []byte, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || CallbackKeyID(key) != delivery.keyID ||
		!ed25519.Verify(key, signingInput(delivery.protected, body), delivery.signature) {
		return ErrInvalidCallback
	}
	return nil
}

// ParseEd25519 validates the detached JWS and timestamp before any key lookup.
func ParseEd25519(headers http.Header, now time.Time) (Ed25519Delivery, error) {
	if now.IsZero() || callbackHeader(headers, "X-Callback-Algorithm") != AlgorithmEd25519 {
		return Ed25519Delivery{}, ErrInvalidCallback
	}
	compact := callbackHeader(headers, "X-Callback-JWS")
	protected, detached, ok := strings.Cut(compact, ".")
	payload, encodedSignature, separated := strings.Cut(detached, ".")
	if !ok || !separated || payload != "" || len(protected) > 1024 || len(encodedSignature) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return Ed25519Delivery{}, ErrInvalidCallback
	}
	encoding := base64.RawURLEncoding.Strict()
	raw, err := encoding.DecodeString(protected)
	if err != nil {
		return Ed25519Delivery{}, ErrInvalidCallback
	}
	alg, kid, timestamp, err := callbackProtectedFields(raw)
	if err != nil || alg != "EdDSA" || !ValidCallbackKeyID(kid) ||
		kid != callbackHeader(headers, "X-Callback-Key-Id") || timestamp != callbackHeader(headers, "X-Callback-Timestamp") {
		return Ed25519Delivery{}, ErrInvalidCallback
	}
	signedAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || signedAt.Before(now.Add(-Ed25519VerificationWindow)) || signedAt.After(now) {
		return Ed25519Delivery{}, ErrInvalidCallback
	}
	signature, err := encoding.DecodeString(encodedSignature)
	if err != nil {
		return Ed25519Delivery{}, ErrInvalidCallback
	}
	return Ed25519Delivery{keyID: kid, protected: protected, signature: signature}, nil
}

// ValidCallbackKeyID restricts the untrusted key selector before lookup.
func ValidCallbackKeyID(kid string) bool {
	if len(kid) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	_, err := base64.RawURLEncoding.Strict().DecodeString(kid)
	return err == nil
}

// CallbackKeyID returns the RFC 7638 thumbprint of an Ed25519 public JWK.
func CallbackKeyID(key ed25519.PublicKey) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	x := base64.RawURLEncoding.EncodeToString(key)
	digest := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// Reject duplicate and unknown protected fields before resolving a key. This
// profile accepts only the protected parameters emitted by the Arctex signer.
func callbackProtectedFields(raw []byte) (alg, kid, timestamp string, err error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", "", "", ErrInvalidCallback
	}
	fields := make(map[string]json.RawMessage, 5)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", "", "", ErrInvalidCallback
		}
		name, ok := token.(string)
		if !ok || fields[name] != nil {
			return "", "", "", ErrInvalidCallback
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", "", "", ErrInvalidCallback
		}
		fields[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return "", "", "", ErrInvalidCallback
	}
	var crit []string
	if len(fields) != 5 || string(fields["b64"]) != "false" ||
		json.Unmarshal(fields["crit"], &crit) != nil || len(crit) != 1 || crit[0] != "b64" ||
		json.Unmarshal(fields["alg"], &alg) != nil || json.Unmarshal(fields["kid"], &kid) != nil ||
		json.Unmarshal(fields["ts"], &timestamp) != nil {
		return "", "", "", ErrInvalidCallback
	}
	return alg, kid, timestamp, nil
}
