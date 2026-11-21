// Package wiregen generates the Go wire API for an Arctex OpenAPI document.
package wiregen

import (
	"encoding/json"
	"fmt"
	"go/format"
	"sort"
	"strings"
)

// Options supplies the caller's HTTP client implementation and its imports.
type Options struct {
	ClientImports []string
	ClientSource  string
	EmbedContract bool
}

type schema struct {
	Ref        string            `json:"$ref"`
	Type       string            `json:"type"`
	Properties map[string]schema `json:"properties"`
	Required   []string          `json:"required"`
	Items      *schema           `json:"items"`
	OneOf      []schema          `json:"oneOf"`
	AllOf      []schema          `json:"allOf"`
}
type operation struct {
	ID          string `json:"operationId"`
	RequestBody struct {
		Content map[string]struct {
			Schema schema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
	Responses map[string]struct {
		Content map[string]struct {
			Schema schema `json:"schema"`
		} `json:"content"`
	} `json:"responses"`
}

func name(s string) string {
	var b strings.Builder
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' }) {
		if p != "" {
			b.WriteString(strings.ToUpper(p[:1]) + p[1:])
		}
	}
	return b.String()
}
func kind(s schema) string {
	if s.Ref != "" {
		return strings.TrimPrefix(s.Ref, "#/components/schemas/")
	}
	for _, part := range s.AllOf {
		if part.Ref != "" {
			return kind(part)
		}
	}
	switch s.Type {
	case "string":
		return "string"
	case "integer":
		return "int64"
	case "boolean":
		return "bool"
	case "array":
		return "[]" + kind(*s.Items)
	case "object":
		return "map[string]json.RawMessage"
	}
	return "json.RawMessage"
}
func keys[T any](m map[string]T) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}

// Generate emits deterministic models and typed client methods from an Arctex
// schema. The supplied client source defines Client and its HTTP call method.
func Generate(document []byte, options Options) ([]byte, error) {
	var spec struct {
		Components struct {
			Schemas map[string]schema `json:"schemas"`
		} `json:"components"`
		Paths map[string]map[string]operation `json:"paths"`
	}
	if err := json.Unmarshal(document, &spec); err != nil {
		return nil, fmt.Errorf("decode Arctex OpenAPI: %w", err)
	}

	var b strings.Builder
	b.WriteString("// Code generated from the maintained OpenAPI contract; DO NOT EDIT.\npackage generated\nimport(")
	imports := []string{"context", "encoding/json", "net/http", "net/url", "strings"}
	for _, path := range append(imports, options.ClientImports...) {
		fmt.Fprintf(&b, "%q;", path)
	}
	b.WriteString(")\n")
	if options.EmbedContract {
		fmt.Fprintf(&b, "const Contract = %q\n", document)
	}
	writeModels(&b, spec.Components.Schemas)
	b.WriteString(options.ClientSource)
	writeOperations(&b, spec.Paths)
	return format.Source([]byte(b.String()))
}

func writeModels(b *strings.Builder, schemas map[string]schema) {
	for _, n := range keys(schemas) {
		s := schemas[n]
		if len(s.Properties) == 0 {
			fmt.Fprintf(b, "type %s = %s\n", n, kind(s))
			continue
		}
		req := map[string]bool{}
		for _, x := range s.Required {
			req[x] = true
		}
		fmt.Fprintf(b, "type %s struct {\n", n)
		for _, p := range keys(s.Properties) {
			typ := kind(s.Properties[p])
			if !req[p] {
				typ = "*" + typ
			}
			tag := p
			if !req[p] {
				tag += ",omitempty"
			}
			fmt.Fprintf(b, "%s %s `json:%q`\n", name(p), typ, tag)
		}
		b.WriteString("AdditionalFields map[string]json.RawMessage `json:\"-\"`\n}\n")
		fmt.Fprintf(b, "func(v *%s)UnmarshalJSON(raw []byte)error{type plain %s;var p plain;if err:=json.Unmarshal(raw,&p);err!=nil{return err};var extra map[string]json.RawMessage;if err:=json.Unmarshal(raw,&extra);err!=nil{return err};", n, n)
		for _, p := range keys(s.Properties) {
			fmt.Fprintf(b, "delete(extra,%q);", p)
		}
		fmt.Fprintf(b, "p.AdditionalFields=extra;*v=%s(p);return nil}\n", n)
		fmt.Fprintf(b, "func(v %s)MarshalJSON()([]byte,error){type plain %s;raw,err:=json.Marshal(plain(v));if err!=nil{return nil,err};var out map[string]json.RawMessage;if err=json.Unmarshal(raw,&out);err!=nil{return nil,err};for k,value:=range v.AdditionalFields{switch k{", n, n)
		for _, p := range keys(s.Properties) {
			fmt.Fprintf(b, "case %q:continue;", p)
		}
		b.WriteString("};if _,exists:=out[k];!exists{out[k]=value}};return json.Marshal(out)}\n")
	}
}

func writeOperations(b *strings.Builder, paths map[string]map[string]operation) {
	for _, path := range keys(paths) {
		for _, method := range keys(paths[path]) {
			op := paths[path][method]
			if op.ID == "" {
				continue
			}
			out := "json.RawMessage"
			for _, code := range []string{"200", "201", "202"} {
				if content, ok := op.Responses[code]; ok {
					out = kind(content.Content["application/json"].Schema)
					break
				}
			}
			input := ""
			if method == "post" {
				input = kind(op.RequestBody.Content["application/json"].Schema)
			}
			params := []string{}
			for _, part := range strings.Split(path, "/") {
				if strings.HasPrefix(part, "{") {
					params = append(params, strings.Trim(part, "{}"))
				}
			}
			fmt.Fprintf(b, "func(c *Client)%s(ctx context.Context,", name(op.ID))
			for _, p := range params {
				fmt.Fprintf(b, "%s string,", name(p))
			}
			b.WriteString("query url.Values,")
			if input != "" {
				fmt.Fprintf(b, "key string,body %s,", input)
			}
			fmt.Fprintf(b, ")(*%s,error){path:=%q;", out, path)
			for _, p := range params {
				fmt.Fprintf(b, "path=strings.ReplaceAll(path,%q,url.PathEscape(%s));", "{"+p+"}", name(p))
			}
			body := "nil"
			if input != "" {
				body = "body"
			}
			key := `""`
			if input != "" {
				key = "key"
			}
			fmt.Fprintf(b, "out:=new(%s);err:=c.call(ctx,%q,path,query,%s,%s,out);return out,err}\n", out, strings.ToUpper(method), key, body)
		}
	}
}
