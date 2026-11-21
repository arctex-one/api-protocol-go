// Package request validates and canonicalizes Arctex JSON request bodies.
package request

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Canonicalize validates raw against a trusted Arctex OpenAPI document and rejects
// duplicate members recursively before canonicalization.
// JSON member order/whitespace are immaterial; decimal strings and presence are
// deliberately preserved. Frozen resolved terms are stored separately.
func Canonicalize(document []byte, schemaName string, raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("UTF-8 JSON is required")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := jsonValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("one JSON object required")
	}
	var contract struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err = json.Unmarshal(document, &contract); err != nil {
		return nil, err
	}
	if err = validateValue(v, contract.Components.Schemas[schemaName], contract.Components.Schemas); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("request nesting exceeds the supported shape")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		out := map[string]any{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, errors.New("object key required")
			}
			if _, dup := out[key]; dup {
				return nil, errors.New("duplicate JSON property")
			}
			v, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		_, err = d.Token()
		return out, err
	case '[':
		out := []any{}
		for d.More() {
			v, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		_, err = d.Token()
		return out, err
	}
	return nil, errors.New("invalid JSON delimiter")
}
func validateValue(value any, raw json.RawMessage, schemas map[string]json.RawMessage) error {
	var s struct {
		Ref        string                     `json:"$ref"`
		Type       string                     `json:"type"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Additional *bool                      `json:"additionalProperties"`
		Enum       []string                   `json:"enum"`
		Pattern    string                     `json:"pattern"`
		MinLength  int                        `json:"minLength"`
		MaxLength  int                        `json:"maxLength"`
		Minimum    *int64                     `json:"minimum"`
		Maximum    *int64                     `json:"maximum"`
	}
	if len(raw) == 0 {
		return errors.New("unknown request schema")
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if s.Ref != "" {
		return validateValue(value, schemas[strings.TrimPrefix(s.Ref, "#/components/schemas/")], schemas)
	}
	if value == nil {
		return errors.New("null is not accepted")
	}
	switch s.Type {
	case "object":
		m, ok := value.(map[string]any)
		if !ok {
			return errors.New("object required")
		}
		for _, key := range s.Required {
			if _, ok = m[key]; !ok {
				return fmt.Errorf("%s is required", key)
			}
		}
		for key, v := range m {
			child, ok := s.Properties[key]
			if !ok {
				if s.Additional != nil && !*s.Additional {
					return fmt.Errorf("unknown property %s", key)
				}
				continue
			}
			if err := validateValue(v, child, schemas); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return errors.New("boolean required")
		}
	case "integer":
		v, ok := value.(json.Number)
		if !ok {
			return errors.New("integer required")
		}
		n, err := v.Int64()
		if err != nil {
			return errors.New("integer required")
		}
		if s.Minimum != nil && n < *s.Minimum || s.Maximum != nil && n > *s.Maximum {
			return errors.New("integer is out of bounds")
		}
	case "string":
		v, ok := value.(string)
		if !ok {
			return errors.New("string required")
		}
		if len([]rune(v)) < s.MinLength || (s.MaxLength > 0 && len([]rune(v)) > s.MaxLength) {
			return errors.New("invalid string length")
		}
		if s.Pattern != "" {
			pattern := s.Pattern
			positive := strings.HasPrefix(pattern, "^(?=.*[1-9])")
			pattern = strings.Replace(pattern, "(?=.*[1-9])", "", 1)
			valid, err := regexp.MatchString(pattern, v)
			if positive && !strings.ContainsAny(v, "123456789") {
				valid = false
			}
			if err != nil || !valid {
				return errors.New("invalid string format")
			}
		}
		if len(s.Enum) > 0 {
			for _, allowed := range s.Enum {
				if v == allowed {
					return nil
				}
			}
			return errors.New("unsupported value")
		}
	default:
		return fmt.Errorf("unsupported request schema %s", s.Type)
	}
	return nil
}
