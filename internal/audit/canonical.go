// RFC 8785 JSON Canonicalization Scheme (JCS) encoder, hand-rolled to
// avoid taking on a third-party dependency for a one-call surface.
// Used by chain.go to produce the bytes hashed into row_hash.
//
// Subset implemented (covers what audit Event records produce):
//   - Object keys sorted by UTF-16 code-unit ordering (RFC 8785 §3.2.3).
//   - No insignificant whitespace.
//   - Strings: NFC unicode normalisation + RFC 8785 string escaping.
//   - Numbers: ECMAScript Number formatting (RFC 8785 §3.2.4 / IEEE 754
//     double precision). Integers stay integer, floats use Go's
//     strconv.FormatFloat with 'g' + -1 precision (shortest round-trip).
//     Exponential notation for the integer subdomain is collapsed.
//   - Booleans, null, arrays handled per JSON.
//   - UTF-8 byte output.
//
// Not implemented: JSON numbers outside double precision (BigInt), since
// audit Event values never carry them; if a future field needs one, add
// handling here with a test.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"

	"golang.org/x/text/unicode/norm"
)

// Canonicalize returns the RFC 8785 JCS encoding of v.
//
// Accepted shapes are the JSON-native Go types: nil, bool, string,
// json.Number, all numeric types, []any, map[string]any, plus structs
// (encoded via their JSON marshalling, then re-canonicalised). Anything
// outside that returns an error rather than silently coercing — callers
// in this package only ever pass map[string]any built from typed
// columns, so the strict surface catches accidental misuse.
func Canonicalize(v any) ([]byte, error) {
	// Round-trip through encoding/json to flatten structs / pointers /
	// any custom MarshalJSON into a uniform map/slice tree, then
	// canonicalise that tree. encoding/json's number handling becomes
	// json.Number which we re-format below.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("canonicalize: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeCanonicalString(buf, x)
	case json.Number:
		return writeCanonicalNumber(buf, string(x))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortKeysUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", v)
	}
}

// sortKeysUTF16 orders strings by their UTF-16 code-unit sequence per
// RFC 8785 §3.2.3. Go's natural string < compares UTF-8 bytes, which
// ranks supplementary-plane code points BELOW BMP code points whose
// UTF-16 surrogate pair encoding starts with a high surrogate (0xD800+).
// JCS requires the UTF-16 view; we materialise it explicitly.
func sortKeysUTF16(keys []string) {
	encoded := make([][]uint16, len(keys))
	for i, k := range keys {
		encoded[i] = utf16.Encode([]rune(norm.NFC.String(k)))
	}
	idx := make([]int, len(keys))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		ka, kb := encoded[idx[a]], encoded[idx[b]]
		for n := 0; n < len(ka) && n < len(kb); n++ {
			if ka[n] != kb[n] {
				return ka[n] < kb[n]
			}
		}
		return len(ka) < len(kb)
	})
	tmp := make([]string, len(keys))
	for i, j := range idx {
		tmp[i] = keys[j]
	}
	copy(keys, tmp)
}

// writeCanonicalString emits an RFC 8785 string: NFC-normalise the
// runes, then escape per RFC 8259 §7 with the JCS-mandated short forms
// (\b, \t, \n, \f, \r, \", \\) and \uXXXX for everything else under
// 0x20. Characters >= 0x20 pass through as UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) error {
	s = norm.NFC.String(s)
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeCanonicalNumber emits a JSON number per RFC 8785 §3.2.4, which
// references the ECMAScript ToString(Number) algorithm. We accept a
// json.Number string (already validated as a JSON number by the
// decoder) and:
//   - keep integer literals as integer (no trailing `.0`),
//   - reformat floats via strconv.FormatFloat 'g' / -1 — that matches
//     ECMAScript "shortest round-trip" exactly for values in the
//     IEEE 754 double range,
//   - reject NaN / +Inf / -Inf (RFC 8785 forbids them in JCS).
func writeCanonicalNumber(buf *bytes.Buffer, s string) error {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatUint(u, 10))
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("canonicalize: parse number %q: %w", s, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonicalize: NaN/Inf not representable in JCS")
	}
	// Whole-valued floats emit as integers so 1.0 -> "1", matching the
	// ECMAScript ToString contract. Bound the cast to int64's range;
	// outside that, FormatFloat 'g' -1 produces the canonical exponential
	// form that ECMAScript Number.prototype.toString agrees with.
	const int64MaxAsFloat = 9.223372036854775e18
	if f == math.Trunc(f) && f >= -int64MaxAsFloat && f <= int64MaxAsFloat {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}
