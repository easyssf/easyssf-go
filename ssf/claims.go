package ssf

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// Claims is a JSON object as decoded by encoding/json: the claims of a SET, an event payload, a
// subject identifier. Numbers are float64 or json.Number, nested objects are Claims-shaped
// map[string]any values, and Object converts them.
type Claims = map[string]any

// StringMember returns the member with the given name if it is a non-empty string, "" otherwise.
func StringMember(object Claims, name string) string {
	if object == nil {
		return ""
	}
	if s, ok := object[name].(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	return ""
}

// Object returns the value as a JSON object, nil if it is not one.
func Object(value any) Claims {
	if object, ok := value.(map[string]any); ok {
		return object
	}
	return nil
}

// ObjectMember returns the member with the given name if it is a JSON object, nil otherwise.
func ObjectMember(object Claims, name string) Claims {
	if object == nil {
		return nil
	}
	return Object(object[name])
}

// Int64 reads a JSON number as an integer; ok is false if the value is not a finite number.
func Int64(value any) (n int64, ok bool) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return int64(f), true
		}
		return 0, false
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

// Strings reads a JSON array of strings; other values give nil, non-string elements are skipped.
func Strings(value any) []string {
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	strings := make([]string, 0, len(array))
	for _, element := range array {
		if s, ok := element.(string); ok {
			strings = append(strings, s)
		}
	}
	return strings
}

// Audiences reads an aud claim as a list: a string as a list of one, an array of its strings, nil
// for anything else.
func Audiences(aud any) []string {
	switch v := aud.(type) {
	case string:
		return []string{v}
	case []any:
		return Strings(v)
	}
	return nil
}

// EventTimestamp reads an event_timestamp claim of an event payload. CAEP 1.0 (section 2) and
// RISC 1.0 (section 2.7) define it as a JSON number of seconds since the epoch; a value that is
// clearly milliseconds is read as such, as some transmitters send milliseconds. ok is false if
// the value is not a number.
func EventTimestamp(value any) (t time.Time, ok bool) {
	number, ok := Int64(value)
	if !ok {
		return time.Time{}, false
	}
	// CAEP defines seconds since epoch, some transmitters send milliseconds
	if number > 100_000_000_000 {
		return time.Unix(number/1000, 0).UTC(), true
	}
	return time.Unix(number, 0).UTC(), true
}

// ParseClaims decodes a JSON object. Numbers are kept as json.Number so that large iat values
// survive; the accessors of this package read both.
func ParseClaims(data []byte) (Claims, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var claims Claims
	if err := decoder.Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
