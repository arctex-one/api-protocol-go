package request

import (
	"bytes"
	"testing"
)

func TestCanonicalizePreservesReplayIdentity(t *testing.T) {
	document := []byte(`{"components":{"schemas":{"Example":{"type":"object","additionalProperties":false,"required":["amount"],"properties":{"amount":{"type":"string","pattern":"^(?=.*[1-9])[0-9]+(\\.[0-9]+)?$"},"memo":{"type":"string"}}}}}}`)
	canonicalize := func(body string) []byte {
		t.Helper()
		canonical, err := Canonicalize(document, "Example", []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	original := canonicalize(`{"amount":"100.00","memo":"example"}`)
	if !bytes.Equal(original, canonicalize(` { "memo":"example", "amount" : "100.00" } `)) {
		t.Fatal("member order or whitespace changed replay identity")
	}
	if bytes.Equal(original, canonicalize(`{"amount":"100","memo":"example"}`)) ||
		bytes.Equal(original, canonicalize(`{"amount":"100.00"}`)) {
		t.Fatal("decimal scale or field presence was lost")
	}
	for _, invalid := range []string{
		`{"amount":"1","amount":"1"}`,
		`{"amount":"1","memo":null}`,
		`{"amount":"1","unknown":true}`,
		`{"amount":"1"} {}`,
		`{"amount":"0.00"}`,
	} {
		if _, err := Canonicalize(document, "Example", []byte(invalid)); err == nil {
			t.Errorf("accepted invalid request %s", invalid)
		}
	}
}
