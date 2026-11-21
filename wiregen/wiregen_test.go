package wiregen

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateDeterministicModelsAndMethods(t *testing.T) {
	document := []byte(`{
  "components": {
    "schemas": {
      "Quote": {
        "type": "object",
        "required": ["quote_ref"],
        "properties": {
          "quote_ref": {"type": "string"},
          "amount": {"type": "string"}
        }
      }
    }
  },
  "paths": {
    "/v1/quotes/{quote_ref}": {
      "get": {
        "operationId": "get_quote",
        "responses": {
          "200": {
            "content": {
              "application/json": {"schema": {"$ref": "#/components/schemas/Quote"}}
            }
          }
        }
      }
    }
  }
}`)
	options := Options{
		EmbedContract: true,
		ClientSource:  "\ntype Client struct {}\n",
	}
	original, err := Generate(document, options)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Generate(document, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, repeated) {
		t.Fatal("consecutive builds generated different source")
	}
	source := string(original)
	for _, required := range []string{
		"const Contract =",
		"json:\"amount,omitempty\"",
		"AdditionalFields",
		"GetQuote(ctx context.Context, QuoteRef string, query url.Values) (*Quote, error)",
		"url.PathEscape(QuoteRef)",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("generated source is missing %q", required)
		}
	}
	options.EmbedContract = false
	sdk, err := Generate(document, options)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sdk, []byte("const Contract =")) {
		t.Fatal("the SDK generator embedded the schema")
	}
}
