package exposure

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// The canonical form the report hash is computed over: UTF-8, object keys
// sorted, no insignificant whitespace, null for an absent value and [] for an
// empty list. Strings escape only what JSON requires; HTML characters and
// non-ASCII text are written as is.

// encodeValue returns the canonical JSON of v. Nil slices become [] unless
// the field is tagged nullable, so an empty list is never written as null.
func encodeValue(v any) ([]byte, error) {
	tree, err := valueTree(v)
	if err != nil {
		return nil, err
	}
	return appendCanonical(nil, tree)
}

func valueTree(v any) (any, error) {
	if testHookEncodePanic != nil && testHookEncodePanic() {
		panic("canonical encoder test panic")
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, nil
	}
	copied := reflect.New(rv.Type()).Elem()
	copied.Set(rv)
	if err := fillNilSlices(copied, 0); err != nil {
		return nil, err
	}

	raw, err := json.Marshal(copied.Interface())
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return tree, nil
}

// fillNilSlices walks v and replaces nil slices with empty ones. It copies
// pointer, slice and map storage before walking it; v must be addressable.
func fillNilSlices(v reflect.Value, depth int) error {
	if depth > 256 {
		return errors.New("canonical value exceeds nesting limit")
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			fresh := reflect.New(v.Type().Elem())
			fresh.Elem().Set(v.Elem())
			v.Set(fresh)
			if err := fillNilSlices(v.Elem(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			f := t.Field(i)
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			fv := v.Field(i)
			if fv.Kind() == reflect.Slice && fv.IsNil() {
				if f.Tag.Get("nullable") == "true" {
					continue
				}
				fv.Set(reflect.MakeSlice(fv.Type(), 0, 0))
				continue
			}
			if err := fillNilSlices(fv, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if !v.IsNil() {
			fresh := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
			reflect.Copy(fresh, v)
			v.Set(fresh)
		}
		for i := range v.Len() {
			if err := fillNilSlices(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		// Map values are not addressable, and the report's maps may be read
		// by a worker that outlived its budget: fill a fresh map in the copy
		// and never write to the original.
		if v.IsNil() || !mayHoldSlice(v.Type().Elem(), map[reflect.Type]bool{}) || !v.CanSet() {
			return nil
		}
		fresh := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			val := reflect.New(iter.Value().Type()).Elem()
			val.Set(iter.Value())
			if err := fillNilSlices(val, depth+1); err != nil {
				return err
			}
			fresh.SetMapIndex(iter.Key(), val)
		}
		v.Set(fresh)
	}
	return nil
}

// mayHoldSlice reports whether a value of type t can contain a slice.
func mayHoldSlice(t reflect.Type, seen map[reflect.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Slice:
		return true
	case reflect.Pointer, reflect.Map:
		return mayHoldSlice(t.Elem(), seen)
	case reflect.Struct:
		for i := range t.NumField() {
			if mayHoldSlice(t.Field(i).Type, seen) {
				return true
			}
		}
	}
	return false
}

func appendCanonical(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case json.Number:
		return append(dst, x.String()...), nil
	case string:
		return appendJSONString(dst, x), nil
	case []any:
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendCanonical(dst, e); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, k)
			dst = append(dst, ':')
			var err error
			if dst, err = appendCanonical(dst, x[k]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	}
	return nil, fmt.Errorf("unsupported canonical value %T", v)
}

const hexDigits = "0123456789abcdef"

func appendJSONString(dst []byte, s string) []byte {
	s = strings.ToValidUTF8(s, "�")
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(s[i:])
			dst = utf8.AppendRune(dst, r)
			i += size
			continue
		}
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
		i++
	}
	return append(dst, '"')
}

// hashInput is the canonical JSON of the report with observed_at and hash
// removed from tree: the exact bytes the report hash covers.
func hashInput(tree map[string]any) ([]byte, error) {
	delete(tree, "observed_at")
	delete(tree, "hash")
	return appendCanonical(nil, tree)
}

func canonicalTree(r *exposureReport) (map[string]any, error) {
	tree, err := valueTree(*r)
	if err != nil {
		return nil, err
	}
	return tree.(map[string]any), nil
}

// seal sets r.Hash from the hash input and returns the canonical body.
func seal(r *exposureReport) ([]byte, error) {
	tree, err := canonicalTree(r)
	if err != nil {
		return nil, err
	}
	observed := tree["observed_at"]
	input, err := hashInput(tree)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(input)
	r.Hash = "sha256:" + hex.EncodeToString(sum[:])
	tree["hash"] = r.Hash
	tree["observed_at"] = observed
	return appendCanonical(nil, tree)
}
