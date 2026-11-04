package featuregraphprojection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// DecodeStrict decodes one JSON value while rejecting duplicate object keys at
// every depth, trailing data, and fields not represented by a destination
// struct. Numbers are retained as json.Number while validating the input.
func DecodeStrict(data []byte, out any) error {
	if out == nil {
		return fmt.Errorf("strict JSON destination is nil")
	}
	if err := validateStrictJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode strict JSON: %w", err)
	}
	return requireJSONEOF(decoder)
}

// CanonicalJSON validates strict JSON and emits its compact encoding with
// lexicographically sorted object keys. json.Number avoids float64 coercion.
func CanonicalJSON(data []byte) ([]byte, error) {
	if err := validateStrictJSON(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode strict JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize strict JSON: %w", err)
	}
	return result, nil
}

func validateStrictJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return fmt.Errorf("invalid strict JSON: %w", err)
	}
	return requireJSONEOF(decoder)
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid strict JSON: trailing value")
		}
		return fmt.Errorf("invalid strict JSON: trailing data: %w", err)
	}
	return nil
}
