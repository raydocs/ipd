package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// validateUniqueJSON checks decoded member names before a map can discard them.
// It is opt-in for adapters whose normalized identity requires unambiguous JSON.
func validateUniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSONValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func uniqueJSONValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON depth exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate JSON member")
			}
			seen[name] = true
			if err := uniqueJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil {
			return err
		}
		if token != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for d.More() {
			if err := uniqueJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil {
			return err
		}
		if token != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	return nil
}
